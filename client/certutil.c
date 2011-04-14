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

#include "certutil.h"

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
X509_NAME *certutil_parse_dn(const char *s, bool fullDN) {
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



