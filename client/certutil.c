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

#include <stdbool.h>
#include <stdlib.h>
#include <glib.h>
#include <openssl/asn1t.h>

#include "../common/defines.h"
#include "misc.h"
#include "platform.h"
#include "certutil.h"

typedef struct {
    const char *name;
    const int nid;
} DNAttrInfo;

#define NUM_DN_ATTRS 15

/**
 * Returns an object identifier NID for a field name. This function uses
 * the names used in old versions of OpenSSL, BankID and probably other
 * software. These are different from RFC 2256.
 */
static bool get_non_rfc2256(const char *field, int *nid, int *position) {
    static const DNAttrInfo attrdefs[NUM_DN_ATTRS] = {
        // These are supported in Nexus Personal 4.10.4.3 and 4.16.1 on Win32
        { "C", NID_countryName, },
        { "CN", NID_commonName, },
        { "D", NID_description, },
        { "EM", NID_pkcs9_emailAddress, },
        { "G", NID_givenName, },
        { "L", NID_localityName, },
        { "N", NID_name, },
        { "O", NID_organizationName, },
        { "OU", NID_organizationalUnitName, },
        { "S", NID_surname, },
        { "SN", NID_serialNumber, },
        { "ST", NID_stateOrProvinceName, },
        { "STREET", NID_streetAddress, },
        { "T", NID_title, },
        { "OID.2.5.4.41", NID_name, }, // TODO support arbitrary OIDs
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
X509_NAME *certutil_parse_dn(const char *s, bool fullDN) {
    X509_NAME *subject = X509_NAME_new();
    STACK_OF(X509_NAME_ENTRY) *entries = sk_X509_NAME_ENTRY_new_null();
    
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
        int nid, position;
        bool ok = get_non_rfc2256(field, &nid, &position);
        g_free(field);
        if (!ok) goto error; // Unsupported attribute
        
        if (fullDN || nid == NID_name) {
            // Add attribute
            X509_NAME_ENTRY *entry = X509_NAME_ENTRY_create_by_NID(NULL, nid,
                determine_string_type(value, valueLength),
                (unsigned char*)value, valueLength);
            if (!entry) goto error;
            sk_X509_NAME_ENTRY_push(entries, entry);
        }
        
        // Go to next attribute
        s += nameLength+1+valueLength;
        if (*s == ',') s++;
    }
    
    // Add the attributes to the subject name in reverse order
    int num = sk_X509_NAME_ENTRY_num(entries);
    for (int i = num; i >= 0; i--) {
        X509_NAME_ENTRY *entry = sk_X509_NAME_ENTRY_value(entries, i);
        X509_NAME_add_entry(subject, entry, -1, 0);
        X509_NAME_ENTRY_free(entry);
    }
    sk_X509_NAME_ENTRY_free(entries);
    
    return subject;
    
  error:
    fprintf(stderr, BINNAME ": failed to parse subject name: %s\n", s);
    X509_NAME_free(subject);
    sk_X509_NAME_ENTRY_pop_free(entries, X509_NAME_ENTRY_free);
    return NULL;
}


/**
 * Returns the BASE64-encoded DER representation of a certificate.
 */
char *certutil_derEncode(X509 *cert) {
    unsigned char *der = NULL;
    char *base64 = NULL;
    int len;
    
    len = i2d_X509(cert, &der);
    if (!der) return NULL;
    base64 = base64_encode((const char*)der, len);
    free(der);
    return base64;
}

const int opensslKeyUsages[] = {
    X509v3_KU_KEY_CERT_SIGN,     // KeyUsage_Issuing
    X509v3_KU_NON_REPUDIATION,   // KeyUsage_Signing
    X509v3_KU_DIGITAL_SIGNATURE, // KeyUsage_Authentication
};

/**
 * Returns true if a certificate supports the given key usage (such as
 * authentication or signing).
 */
bool certutil_hasKeyUsage(X509 *cert, KeyUsage keyUsage) {
    ASN1_BIT_STRING *usage;
    bool supported = false;

    usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (usage) {
        const int opensslKeyUsage = opensslKeyUsages[keyUsage];
        supported = (usage->length > 0) &&
                    ((usage->data[0] & opensslKeyUsage) == opensslKeyUsage);
        ASN1_BIT_STRING_free(usage);
    }
    return supported;
}

/**
 * Gets a property of an X509_NAME, such as a subject name (NID_commonName),
 */
char *certutil_getNamePropertyByNID(X509_NAME *name, int nid) {
    char *text;
    int length;
    
    length = X509_NAME_get_text_by_NID(name, nid, NULL, 0);
    if (length < 0) return NULL;
    
    text = malloc(length+1);
    text[0] = '\0'; // if the function would fail
    X509_NAME_get_text_by_NID(name, nid, text, length+1);
    return text;
}

bool certutil_matchSubjectFilter(const char *subjectFilter, X509_NAME *name) {
    if (!subjectFilter) return true;
    
    // TODO use OBJ_txt2nid and support arbitrary OIDs?
    if ((strncmp(subjectFilter, "2.5.4.5=", 8) != 0) ||
        (strchr(subjectFilter, ',') != NULL)) {
        // OID 2.5.4.5 (Serial number) is the only supported/allowed filter
        return true; // Nothing to filter with
    }
    
    const char *wantedSerial = subjectFilter + 8;
    
    char *actualSerial = certutil_getNamePropertyByNID(name, NID_serialNumber);
    
    bool ok = !strcmp(actualSerial, wantedSerial);
    free(actualSerial);
    return ok;
}

bool certutil_compareX509Names(const X509_NAME *a, const X509_NAME *b,
                               bool orderMightDiffer) {
#if 0   // this might work in OpenSSL 1.0.0
    return X509_NAME_cmp(a, b);
#else
    if (!orderMightDiffer) return X509_NAME_cmp(a, b);
    
    int num = sk_X509_NAME_ENTRY_num(a->entries);
    if (sk_X509_NAME_ENTRY_num(b->entries) != num) return false;
    
    for (int i = 0; i < num; i++) {
        bool match = false;
        for (int j = i; j < num; j++) {
            X509_NAME_ENTRY *ae = sk_X509_NAME_ENTRY_value(a->entries, i);
            X509_NAME_ENTRY *be = sk_X509_NAME_ENTRY_value(b->entries, j);
            
            if (!OBJ_cmp(ae->object, be->object) &&
                !ASN1_STRING_cmp(ae->value, be->value)) {
                match = true;
                break;
            }
        }
        if (!match) return false;
    }
    return true;
#endif
}

X509 *certutil_findCert(const STACK_OF(X509) *certList,
                        const X509_NAME *name,
                        const KeyUsage keyUsage,
                        bool orderMightDiffer) {
    int num = sk_X509_num(certList);
    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(certList, i);
        if (!certutil_compareX509Names(X509_get_subject_name(cert), name, orderMightDiffer) &&
            certutil_hasKeyUsage(cert, keyUsage)) {
            return cert;
        }
    }
    return NULL;
}


PKCS7 *certutil_parseP7SignedData(const char *p7data, size_t length) {
    // Parse data
    BIO *bio = BIO_new_mem_buf((void *)p7data, length);
    if (!bio) return NULL;
    PKCS7 *p7 = d2i_PKCS7_bio(bio, NULL);
    BIO_free(bio);
    
    // Check that it's valid and contains certificates
    if (!p7 || !PKCS7_type_is_signed(p7) || !p7->d.sign || !p7->d.sign->cert ||
        sk_X509_num(p7->d.sign->cert) == 0) {
        PKCS7_free(p7);
        return NULL;
    }
    
    return p7;
}

/**
 * Makes a filename for a certificate.
 */
char *certutil_makeFilename(X509_NAME *xname) {
    if (!xname) return NULL;
    
    char *nameAttr = certutil_getNamePropertyByNID(xname, NID_name);
    if (!nameAttr) return NULL;
    
    char *filename = platform_getFilenameForKey(nameAttr);
    free(nameAttr);
    
    return filename;
}

/**
 * Gets an attribute of the type PRINTABLESTRING from a PKCS12 bag.
 */
char *certutil_getBagAttr(PKCS12_SAFEBAG *bag, ASN1_OBJECT *oid) {
    // Find the attribute
    ASN1_TYPE *at = NULL;
    
    if (!bag->attrib) return NULL;
    
    int numattr = sk_X509_ATTRIBUTE_num(bag->attrib);
    for (int i = 0; i < numattr; i++) {
        X509_ATTRIBUTE *xattr = sk_X509_ATTRIBUTE_value(bag->attrib, i);
        if (xattr->object && !OBJ_cmp(xattr->object, oid)) {
            // Match
            at = sk_ASN1_TYPE_value(xattr->value.set, 0);
            break;
        }
    }
    
    if (!at || at->type != V_ASN1_PRINTABLESTRING) return NULL;
    
    // Copy the value to a string
    int len = at->value.printablestring->length;
    char *str = malloc(len+1);
    if (str) memcpy(str, at->value.printablestring->data, len);
    str[len] = '\0';
    return str;
}


