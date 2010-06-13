/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
  Copyright (c) 2010 Marcus Carlson <marcus@mejlamej.nu>
 
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

#define _BSD_SOURCE 1

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>

#include "../common/defines.h"
#include "misc.h"
#include "platform.h"
#include "keyfile.h"

void keyfile_init() {
    OpenSSL_add_all_algorithms();
}

void keyfile_shutdown() {
    EVP_cleanup();
}

static PKCS12 *pkcs12_open(const char *p12Data, const int p12Length) {
    BIO *bio;
    PKCS12 *p12;
    
    bio = BIO_new_mem_buf((void *)p12Data, p12Length);
    if (!bio) return NULL;
    p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);
    
    return p12;
}

static void pkcs12_close(PKCS12 *p12) {
    PKCS12_free(p12);
}

static char *subject(X509_NAME *name) {
    unsigned char *data;
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) return NULL;
    X509_NAME_print_ex(out, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    
    int length = BIO_get_mem_data(out, &data);
    char *result = malloc(length+1);
    result[length] = '\0';
    memcpy(result, data, length);
    
    BIO_free(out); // This free's "data" too
    return result;
}

static EVP_PKEY *getPrivateKey(PKCS12 *p12, X509 *x509, const char* pass, int passlen) {
    // Extract all PKCS7 safes
    STACK_OF(PKCS7) *pkcs7s = PKCS12_unpack_authsafes(p12);
    if (!pkcs7s) return NULL;
    
    // For each PKCS7 safe
    int nump = sk_PKCS7_num(pkcs7s);
    for (int p = 0; p < nump; p++) {
        PKCS7 *p7 = sk_PKCS7_value(pkcs7s, p);
        if (!p7) continue;
        STACK_OF(PKCS12_SAFEBAG) *safebags = PKCS12_unpack_p7data(p7);
        if (!safebags) continue;
        
        // For each PKCS12 safebag
        int numb = sk_PKCS12_SAFEBAG_num(safebags);
        for (int i = 0; i < numb; i++) {
            PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(safebags, i);
            if (!bag) continue;
            
            switch (M_PKCS12_bag_type(bag)) {
                case NID_pkcs8ShroudedKeyBag:;
                    // Encrypted key
                    PKCS8_PRIV_KEY_INFO *p8 = PKCS12_decrypt_skey(bag, pass, passlen);
                    
                    if (p8) {
                        EVP_PKEY *pk = EVP_PKCS82PKEY(p8);
                        PKCS8_PRIV_KEY_INFO_free(p8);
                        if (!pk) break; // out of switch
                        
                        if (X509_check_private_key(x509, pk) > 0) {
                            sk_PKCS12_SAFEBAG_pop_free(safebags, PKCS12_SAFEBAG_free);
                            sk_PKCS7_pop_free(pkcs7s, PKCS7_free);
                            return pk;
                        }
                        EVP_PKEY_free(pk);
                    }
                    break;
            }
        }
        
        sk_PKCS12_SAFEBAG_pop_free(safebags, PKCS12_SAFEBAG_free);
    }
    
    sk_PKCS7_pop_free(pkcs7s, PKCS7_free);
    return NULL;
}

/**
 * Returns a list of all x509 certificates in a PKCS12 object.
 */
static STACK_OF(X509) *pkcs12_listCerts(PKCS12 *p12) {
    STACK_OF(X509) *x509s = sk_X509_new_null();
    if (!x509s) return NULL;
    
    // Extract all PKCS7 safes
    STACK_OF(PKCS7) *pkcs7s = PKCS12_unpack_authsafes(p12);
    if (!pkcs7s) {
        sk_X509_free(x509s);
        return NULL;
    }
    
    // For each PKCS7 safe
    int nump = sk_PKCS7_num(pkcs7s);
    for (int p = 0; p < nump; p++) {
        PKCS7 *p7 = sk_PKCS7_value(pkcs7s, p);
        if (!p7) continue;
        STACK_OF(PKCS12_SAFEBAG) *safebags = PKCS12_unpack_p7data(p7);
        if (!safebags) continue;
        
        // For each PKCS12 safebag
        int numb = sk_PKCS12_SAFEBAG_num(safebags);
        for (int i = 0; i < numb; i++) {
            PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(safebags, i);
            if (!bag) continue;
            
            if (M_PKCS12_bag_type(bag) == NID_certBag) {
                // Extract x509 cert
                X509 *x509 = PKCS12_certbag2x509(bag);
                if (x509 != NULL) {
                    sk_X509_push(x509s, x509);
                }
            }
        }
        
        sk_PKCS12_SAFEBAG_pop_free(safebags, PKCS12_SAFEBAG_free);
    }
    
    sk_PKCS7_pop_free(pkcs7s, PKCS7_free);
    return x509s;
}

/**
 * Returns the BASE64-encoded DER representation of a certificate.
 */
static char *der_encode(X509 *cert) {
    unsigned char *der = NULL;
    char *base64 = NULL;
    int len;
    
    len = i2d_X509(cert, &der);
    if (!der) return NULL;
    base64 = base64_encode((const char*)der, len);
    free(der);
    return base64;
}

/**
 * Returns true if a certificate supports the given key usage (such as
 * authentication or signing).
 */
static bool has_keyusage(X509 *cert, int keyUsage) {
    ASN1_BIT_STRING *usage;
    bool supported = false;

    usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (usage) {
        supported = (usage->length > 0) && (usage->data[0] & keyUsage);
        ASN1_BIT_STRING_free(usage);
    }
    return supported;
}

/**
 * Lists the subjects in the given P12 file.
 */
bool keyfile_listPeople(const char *p12Data, const int p12Length,
                        KeyfileSubject ***people, int *count) {
    *count = 0;
    PKCS12 *p12 = pkcs12_open(p12Data, p12Length);
    if (!p12) return false;
    
    STACK_OF(X509) *certList = pkcs12_listCerts(p12);
    pkcs12_close(p12);
    if (!certList) return false;
    
    int certCount = sk_X509_num(certList);
    for (int i = 0; i < certCount; i++) {
        X509 *x = sk_X509_value(certList, i);
        if (has_keyusage(x, CERTUSE_AUTHENTICATION)) {
            (*count)++;
        }
    }
    
    *people = malloc(*count * sizeof(void*));
    if (!*people) {
        sk_X509_pop_free(certList, X509_free);
        return false;
    }
    
    KeyfileSubject **person = *people;
    for (int i = 0; i < certCount; i++) {
        X509 *x = sk_X509_value(certList, i);
        // TODO: egentligen en fuling - det här borde skickas med beroende på om det är signering eller auth!
        if (has_keyusage(x, CERTUSE_AUTHENTICATION)) {
            char *p = subject(X509_get_subject_name(x));
            *person = p;
            person++;
        }
    }
    
    sk_X509_pop_free(certList, X509_free);
    return true;
}

void keyfile_freeSubject(KeyfileSubject *person) {
    free(person);
}

KeyfileSubject *keyfile_duplicateSubject(const KeyfileSubject *person) {
    return strdup(person);
}

bool keyfile_compareSubjects(const KeyfileSubject *a, const KeyfileSubject *b) {
    return (strcmp(a, b) == 0);
}

char *keyfile_getDisplayName(const KeyfileSubject *person) {

    //TODO: int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf,int len);


    // FIXME: Hack
    const char *name = strstr(person, "name = ");
    if (!name) return strdup(person);
    
    name += 7;
    //return strndup(name, strcspn(name, ","));
    int length = strcspn(name, ",");
    char *displayName = malloc(length+1);
    memcpy(displayName, name, length);
    displayName[length] = '\0';
    return displayName;
}

bool keyfile_matchSubjectFilter(const KeyfileSubject *person,
                                const char *subjectFilter) {
    // FIXME: Hack
    if (!subjectFilter) return true;
    
    if ((strncmp(subjectFilter, "2.5.4.5=", 8) != 0) ||
        (strchr(subjectFilter, ',') != NULL)) {
        // OID 2.5.4.5 (Serial number) is the only supported/allowed filter
        return true; // Nothing to filter with
    }
    
    const char *wantedSerial = subjectFilter + 8;
    
    const char *serialOIDTag = strstr(person, "serialNumber = ");
    if (!serialOIDTag) {
        // Shouldn't happen
        return true;
    }
    
    const char *actualSerial = serialOIDTag + 15;
    size_t actualLength = strcspn(actualSerial, ",");
    
    return ((strlen(wantedSerial) == actualLength) &&
            (strncmp(wantedSerial, actualSerial, actualLength) == 0));
}

static X509 *findCert(const STACK_OF(X509) *certList,
                      const KeyfileSubject *person,
                      const unsigned int certMask) {
    int num = sk_X509_num(certList);
    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(certList, i);
        char *dn = subject(X509_get_subject_name(cert));
        if (!strcmp(dn, person)) {
            if (has_keyusage(cert, certMask)) {
                return cert;
            }
        }
    }
    return NULL;
}

/**
 * Returns a list of DER-BASE64 encoded certificates, from the subject
 * to the root CA. This is actually wrong, since the root CA that's
 * returned could be untrusted. However, at least my P12 has only one
 * possible chain and the validation is done server-side, so this shouldn't
 * be a problem.
 */
bool keyfile_getBase64Chain(const char *p12Data, const int p12Length,
                            const KeyfileSubject *person,
                            const unsigned int certMask,
                            char ***certs, int *count) {
    
    PKCS12 *p12;
    p12 = pkcs12_open(p12Data, p12Length);
    if (!p12) return false;

    STACK_OF(X509) *certList = pkcs12_listCerts(p12);
    pkcs12_close(p12);
    if (!certList) return false;
    
    X509 *cert = findCert(certList, person, certMask);
    if (!cert) {
        sk_X509_pop_free(certList, X509_free);
        return false;
    }
    
    *count = 1;
    *certs = malloc(sizeof(char*));
    (*certs)[0] = der_encode(cert);
    
    X509_NAME *issuer = X509_get_issuer_name(cert);
    while (issuer != NULL) {
        char* issuerName = subject(issuer);
        
        cert = findCert(certList, issuerName, CERTUSE_ISSUER);
        free(issuerName);
        if (!cert) break;
        
        issuer = X509_get_issuer_name(cert);
        (*count)++;
        *certs = realloc(*certs, *count * sizeof(char*));
        (*certs)[*count-1] = der_encode(cert);
    }
    
    sk_X509_pop_free(certList, X509_free);
    return true;
}

bool keyfile_sign(const char *p12Data, const int p12Length,
                  const KeyfileSubject *person,
                  const unsigned int certMask,
                  const char *password,
                  const char *message, const int messagelen,
                  char **signature, int *siglen) {
    
    assert(p12Data != NULL);
    assert(person != NULL);
    assert(message != NULL);
    assert(password != NULL);
    assert(signature != NULL);
    assert(siglen != NULL);
    
    bool success = false;
    PKCS12 *p12 = pkcs12_open(p12Data, p12Length);
    if (!p12) return false;
    
    STACK_OF(X509) *certList = pkcs12_listCerts(p12);
    if (!certList) {
        pkcs12_close(p12);
        return false;
    }
    
    int num = sk_X509_num(certList);
    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(certList, i);
        char *dn = subject(X509_get_subject_name(cert));
        bool equal = !strcmp(dn, person);
        free(dn);
        
        if (equal && has_keyusage(cert, certMask)) {
            EVP_MD_CTX sig_ctx;
            EVP_PKEY *key = getPrivateKey(p12, cert, password, strlen(password));
            if (!key) break;
            
            // Sign with the default crypto with SHA1
            unsigned int sig_len = EVP_PKEY_size(key);
            *siglen = sig_len;
            *signature = malloc(sig_len);
            
            EVP_MD_CTX_init(&sig_ctx);
            success = (EVP_SignInit(&sig_ctx, EVP_sha1()) &&
                       EVP_SignUpdate(&sig_ctx, message, messagelen) &&
                       EVP_SignFinal(&sig_ctx, (unsigned char*)*signature,
                                     &sig_len, key));
            EVP_MD_CTX_cleanup(&sig_ctx);
            
            if (!success) {
                free(*signature);
            }
            *siglen = sig_len;
            EVP_PKEY_free(key);
            break;
        }
    }
    
    sk_X509_pop_free(certList, X509_free);
    pkcs12_close(p12);
    return success;
}

