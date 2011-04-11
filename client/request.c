/*

  Copyright (c) 2011 Samuel Lidén Borell <samuel@slbdata.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#include "request.h"

#include <stdbool.h>
#include <stdlib.h>
#include <glib.h>
#include <openssl/asn1t.h>

// Hack to mark things as context specific
static int context_specific_i2d(ASN1_VALUE **val, unsigned char **out,
                                const ASN1_ITEM *it) {
    unsigned char *binary = NULL;
    int length = ASN1_item_i2d(*val, (out ? &binary : NULL), it);
    
    if (out) {
        // Make context specific
        binary[0] = V_ASN1_CONTEXT_SPECIFIC |
                    V_ASN1_CONSTRUCTED;
        
        // Copy result to output buffer
        if (!binary) return -1;
        
        memcpy(*out, binary, length);
        *out += length;
    }
        
    return length;
}

#define IMPLEMENT_CONT_SPEC_HACK(name) \
    static int name##_ex_i2d(ASN1_VALUE **val, unsigned char **out, \
                                  const ASN1_ITEM *it, int tag, int aclass) { \
        return context_specific_i2d(val, out, ASN1_ITEM_rptr(name)); \
    } \
    \
    const ASN1_EXTERN_FUNCS name##_ff = { \
        NULL, NULL, NULL, NULL, NULL, name##_ex_i2d, \
    }; \
    \
    IMPLEMENT_EXTERN_ASN1(name##_cont, V_ASN1_SEQUENCE, name##_ff)


// Request body part
typedef struct {
    ASN1_INTEGER *bodyPartID;
    X509_REQ *csr;
} REQ_BODY_PART;

ASN1_SEQUENCE(REQ_BODY_PART) = {
    ASN1_SIMPLE(REQ_BODY_PART, bodyPartID, ASN1_INTEGER),
    ASN1_SIMPLE(REQ_BODY_PART, csr, X509_REQ)
} ASN1_SEQUENCE_END(REQ_BODY_PART)

IMPLEMENT_ASN1_FUNCTIONS(REQ_BODY_PART)
IMPLEMENT_CONT_SPEC_HACK(REQ_BODY_PART)

// OtherMsg body part
typedef struct {
    ASN1_INTEGER *bodyPartID;
    ASN1_OBJECT *otherMsgType;
    ASN1_IA5STRING *otherMsgValue;
} OTHERMSG_BODY_PART;

ASN1_SEQUENCE(OTHERMSG_BODY_PART) = {
    ASN1_SIMPLE(OTHERMSG_BODY_PART, bodyPartID, ASN1_INTEGER),
    ASN1_SIMPLE(OTHERMSG_BODY_PART, otherMsgType, ASN1_OBJECT),
    ASN1_SIMPLE(OTHERMSG_BODY_PART, otherMsgValue, ASN1_IA5STRING)
} ASN1_SEQUENCE_END(OTHERMSG_BODY_PART)

IMPLEMENT_ASN1_FUNCTIONS(OTHERMSG_BODY_PART)
IMPLEMENT_CONT_SPEC_HACK(OTHERMSG_BODY_PART)

// PKIData
typedef struct {
    STACK *controlSequence;
    STACK *reqSequence;
    STACK *cmsSequence;
    STACK *otherMsgSequence;
} PKIDATA;

ASN1_SEQUENCE(PKIDATA) = {
    ASN1_SEQUENCE_OF(PKIDATA, controlSequence, ASN1_NULL),
    ASN1_SEQUENCE_OF(PKIDATA, reqSequence, REQ_BODY_PART_cont),
    ASN1_SEQUENCE_OF(PKIDATA, cmsSequence, ASN1_NULL),
    ASN1_SEQUENCE_OF(PKIDATA, otherMsgSequence, OTHERMSG_BODY_PART),
} ASN1_SEQUENCE_END(PKIDATA)

IMPLEMENT_ASN1_FUNCTIONS(PKIDATA)


static ASN1_INTEGER *intToAsn1(int i) {
    ASN1_INTEGER *a = ASN1_INTEGER_new();
    ASN1_INTEGER_set(a, i);
    return a;
}

static ASN1_IA5STRING *strToIA5(const char *s) {
    ASN1_IA5STRING *a = ASN1_IA5STRING_new();
    ASN1_STRING_set((ASN1_STRING*)a, s, strlen(s));
    return a;
}

static REQ_BODY_PART *wrapBodyPartReq(X509_REQ *req, int bodyPartId) {
    REQ_BODY_PART *part = REQ_BODY_PART_new();
    if (part) {
        part->bodyPartID = intToAsn1(bodyPartId);
        part->csr = req;
    }
    return part;
}

static OTHERMSG_BODY_PART *makeOtherMsg(const char *oneTimePassword,
                                        int bodyPartId) {
    OTHERMSG_BODY_PART *part = OTHERMSG_BODY_PART_new();
    if (part) {
        part->bodyPartID = intToAsn1(bodyPartId);
        // 1.2.752.36 is iD2 Technologies AB
        part->otherMsgType = OBJ_txt2obj("1.2.752.36.4.1.1", 1);
        part->otherMsgValue = strToIA5(oneTimePassword);
        if (!part->otherMsgType) abort();
    }
    return part;
}

/**
 * Encapsulates a number of PKCS10 requests in a DER-encoded
 * PKCS7/CMC container.
 *
 * @param reqs        A STACK of X509_REQ. It's free'd by this function.
 * @param der         DER-encoded result
 * @param derLength   Length of DER in bytes
 */
void request_wrap(STACK *reqs, char **der, size_t *derLength) {
    PKIDATA *pkidata = PKIDATA_new();
    ASN1_TYPE *pkitype = NULL;
    PKCS7 *pkiP7 = NULL;
    PKCS7 *signdata = NULL;
    
    if (!pkidata) goto end;
    
    // Add PKCS10 requests
    // FIXME something is wrong with the requests
    fprintf(stderr, "add reqs\n");
    STACK *reqParts = pkidata->reqSequence;
    int num = sk_num(reqs);
    for (int i = 0; i < num; i++) {
        X509_REQ *req = (X509_REQ*)sk_value(reqs, i);
        
        fprintf(stderr, "push wrapBodyReq\n");
        REQ_BODY_PART *reqPart = wrapBodyPartReq(req, 0x01000002+i);
        
        if (!reqPart ||
            !sk_push(reqParts, (char*)reqPart)) goto end;
    }
    
    // Add "CMC request"
    // TODO use the value from the OneTimePassword parameter
    OTHERMSG_BODY_PART *otherMsgPart = makeOtherMsg("Not Applicable", 0x01000001);
    
    if (!otherMsgPart ||
        !sk_push(pkidata->otherMsgSequence, (char*)otherMsgPart)) goto end;
    
    // Wrap in CMC PKIData structure
    pkitype = ASN1_TYPE_new();
    if (!pkitype) goto end;
    pkitype->type = V_ASN1_SEQUENCE;
    fprintf(stderr, "wrap in CMC PKIDATA\n");
    if (!ASN1_pack_string(pkidata, (i2d_of_void*)i2d_PKIDATA,
                            &pkitype->value.sequence)) goto end;
    
    PKIDATA_free(pkidata);
    pkidata = NULL;
    
    pkiP7 = PKCS7_new();
    if (!pkiP7 ||
        !PKCS7_set0_type_other(pkiP7, NID_id_cct_PKIData, pkitype)) goto end;
    
    // Wrap in PKCS7 SignedData structure
    signdata = PKCS7_new();
    if (!signdata ||
        !PKCS7_set_type(signdata, NID_pkcs7_signed) ||
        !PKCS7_set_content(signdata, pkiP7)) goto end;
    
    // Encode data
    fprintf(stderr, "enc der\n");
    *der = NULL;
    *derLength = i2d_PKCS7(signdata, (unsigned char**)der);
    
  end:
    fprintf(stderr, "free\n");
    if (signdata) PKCS7_free(signdata);
    else if (pkiP7) PKCS7_free(pkiP7);
    else if (pkitype) ASN1_TYPE_free(pkitype);
    if (pkidata) PKIDATA_free(pkidata);
    fprintf(stderr, "done\n");
}

typedef struct {
    const char *name;
    const int nid;
} DNAttrInfo;

#define NUM_DN_ATTRS 7

/**
 * Returns an object identifier NID for a field name. This function uses
 * the names used in old versions of OpenSSL, BankID and probably other
 * software. These are different from RFC 2256.
 */
static bool get_non_rfc2256(const char *field, int *nid, int *position) {
    static const DNAttrInfo attrdefs[NUM_DN_ATTRS] = {
        // TODO add all names that are supported by BankID
        { "S", NID_surname, },
        { "G", NID_givenName, },
        { "SN", NID_serialNumber, },
        { "OID.2.5.4.41", NID_name, },
        { "CN", NID_commonName, },
        { "C", NID_countryName, },
        { "O", NID_organizationName, },
    };
    
    for (size_t i = 0; i < NUM_DN_ATTRS; i++) {
        if (!g_ascii_strcasecmp(field, attrdefs[i].name)) {
            *nid = attrdefs[i].nid;
            *position = i;
            return true;
        }
    }
    return false;
}

/**
 * Determines which type a string should have in ASN1 (ASCII or UTF8).
 *
 * By default, OpenSSL seems to encode our UTF-8 strings as a T61STRING,
 * which is not what BankID does (and is also wrong).
 */
static int determine_string_type(const char *s, int length) {
    return (g_utf8_strlen(s, length) == length) ?
        V_ASN1_PRINTABLESTRING : V_ASN1_UTF8STRING;
}

/**
 * Parses a subject name in RFC 2253 format, for example:
 *  CN=John Doe,SN=197711223334
 *
 * If fullDN is false, then only the name (OID 2.5.4.41) is included.
 */
X509_NAME *dn_from_string(const char *s, bool fullDN) {
    X509_NAME *subject = X509_NAME_new();
    
    // First all attributes are parsed and are stored here, then they are
    // put in the correct order in the final subject name.
    X509_NAME_ENTRY *entries[NUM_DN_ATTRS];
    memset(entries, 0, sizeof(entries));
    
    while (*s != '\0') {
        // Parse attribute
        size_t nameLength = strcspn(s, ",+=");
        if (s[nameLength] != '=') goto error;
        
        const char *value = &s[nameLength+1];
        // TODO handle escaped data
        size_t valueLength = strcspn(value, "+,");
        if (value[valueLength] == '+') goto error; // Not supported
        
        // Parse attribute name
        char *field = g_strndup(s, nameLength);
        fprintf(stderr, "field=>%s< value=>%.*s<\n", field, valueLength, value);
        int nid, position;
        bool ok = get_non_rfc2256(field, &nid, &position);
        g_free(field);
        if (!ok) goto error; // Unsupported attribute
        
        if (fullDN || nid == NID_name) {
            // Add attribute
            if (entries[position]) {
                X509_NAME_ENTRY_free(entries[position]);
            } else {
                entries[position] = X509_NAME_ENTRY_create_by_NID(NULL, nid,
                    determine_string_type(value, valueLength),
                    (unsigned char*)value, valueLength);
            }
        }
        
        // Go to next attribute
        s += nameLength+1+valueLength;
        if (*s == ',') s++;
    }
    
    // Add the attributes to the subject name in the correct order
    for (size_t i = 0; i < NUM_DN_ATTRS; i++) {
        if (entries[i] != NULL) {
            X509_NAME_add_entry(subject, entries[i], -1, 0);
            X509_NAME_ENTRY_free(entries[i]);
        }
    }
    
    return subject;
    
  error:
    X509_NAME_free(subject);
    return NULL;
}


