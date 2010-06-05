/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
 
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

typedef struct {
    enum {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;

void keyfile_init() {
    OpenSSL_add_all_algorithms();

    platform_seedRandom();
}

void keyfile_shutdown() {
}

static PKCS12 *pkcs12_open(const char *p12Data, const int p12Length) {
    BIO *bio;
    bio = BIO_new_mem_buf((void *)p12Data, p12Length);
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(bio, NULL);
    //TODO: cleanup bio
    return p12;
}

static void pkcs12_close(PKCS12 *p12) {
}

static char *subject (X509_NAME *name) {
    BIO *out;
    unsigned char *issuer, *result;
    int n;
    out = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(out, name, 0,XN_FLAG_ONELINE);
    n = BIO_get_mem_data(out, &issuer);
    result = (char *) malloc (n+1);
    result[n]='\0';
    memcpy(result,issuer,n);

    BIO_free(out);
    out = NULL;
    return result;
}

static EVP_PKEY * get_key (PKCS12 *p12, X509 *x509, const char* pass, int passlen) {
    //för varje PKCS7:a
    STACK_OF(PKCS7) *pkcs7s;
    pkcs7s = PKCS12_unpack_authsafes(p12);
    
    PKCS7 * p7 = NULL;
    int nump = sk_PKCS7_num(pkcs7s);
    int p;

    for (p = 0; p < nump; p++) {
        p7 = sk_PKCS7_value (pkcs7s, p);
        STACK_OF(PKCS12_SAFEBAG) *safebags;
        safebags = PKCS12_unpack_p7data(p7);
        //gå igenom alla pkcs12_safebags
        PKCS12_SAFEBAG *bag = NULL;
        int numb = sk_PKCS12_SAFEBAG_num (safebags);
        int i;
        for (i = 0; i < numb; i++) {
            bag = sk_PKCS12_SAFEBAG_value (safebags, i);
            EVP_PKEY *pk;
            PKCS8_PRIV_KEY_INFO * p8;

            switch (M_PKCS12_bag_type(bag)) {
                /*case NID_keyBag:
                    if (!lkey || !pkey) return 1;
                    if (!(*pkey = EVP_PKCS82PKEY(bag->value.keybag))) return 0;
                    *keymatch |= MATCH_KEY;
                break;*/

                case NID_pkcs8ShroudedKeyBag:
                    p8 = PKCS12_decrypt_skey(bag, pass, passlen);

                    if (p8) {
                        pk = EVP_PKCS82PKEY(p8);

                        if (X509_check_private_key (x509, pk)) {
                            return pk;
                        }
                    }
                break;
            }
        }
    }

    return NULL;
}


static STACK_OF(X509) *pkcs12_listCerts(PKCS12 *p12) {
    STACK_OF(X509) * x509s;
    x509s = sk_X509_new_null ();

    //för varje PKCS7:a
    STACK_OF(PKCS7) *pkcs7s;
    pkcs7s = PKCS12_unpack_authsafes(p12);
    
    PKCS7 * p7 = NULL;
    int nump = sk_PKCS7_num(pkcs7s);
    int p;
    //Lägg alla cert i en stack
    for (p = 0; p < nump; p++) {
        p7 = sk_PKCS7_value (pkcs7s, p);
        STACK_OF(PKCS12_SAFEBAG) *safebags;
        safebags = PKCS12_unpack_p7data(p7);

        //gå igenom alla pkcs12_safebags
        PKCS12_SAFEBAG *bag = NULL;
        int numb = sk_PKCS12_SAFEBAG_num (safebags);
        int i;
        for (i = 0; i < numb; i++) {
            bag = sk_PKCS12_SAFEBAG_value (safebags, i);
            //ta ut X509
            X509 * x509;
            x509 = PKCS12_certbag2x509(bag);
            if (x509 != NULL) {
                sk_X509_push (x509s, x509);
            }
        }

    }

    return x509s;
}

static char *der_encode(X509 *cert) {
    char *base64 = NULL;
    unsigned char *buf;
    int len;
    buf = NULL;
    len = i2d_X509(cert, &buf);
    base64 = base64_encode((const char*)buf, len);
    free(buf);
    return base64;
}

static bool has_keyusage (X509 *cert, int kusage) {
        ASN1_BIT_STRING *usage;
    
        usage=X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
        if (usage) {
            return ((usage->length > 0) && (usage->data[0] & kusage));
        }
    return false;
}

/**
 * Lists the subjects in the given P12 file.
 */
bool keyfile_listPeople(const char *p12Data, const int p12Length,
                        KeyfileSubject ***people, int *count) {
    *count = 0;
    PKCS12 * p12;
    p12 = pkcs12_open(p12Data, p12Length);
    if (!p12)
        return false;

    STACK_OF(X509) *certList = pkcs12_listCerts(p12);
    if (!certList) return false;

    int num = sk_X509_num (certList);
    for (int i = 0; i < num; i++) {
        X509 * x;
        x = sk_X509_value(certList, i);
        char *dn;
        dn = subject (X509_get_subject_name (x));
        if (has_keyusage (x, CERTUSE_AUTHENTICATION)) {
            (*count)++;
        }
    }
    
    *people = malloc(*count * sizeof(void*));
    KeyfileSubject **person = *people;
    for (int i = 0; i < num; i++) {
        X509 *x;
        x = sk_X509_value(certList, i);
        //TODO: egentligen en fuling - det här borde skickas med beroende på om det är signering eller auth!
        if (has_keyusage (x, CERTUSE_AUTHENTICATION)) {
            char *p;
            p = strdup(subject(X509_get_subject_name (x)));
            *person = p;
            person++;
        }
    }
    
    //TODO: CERT_DestroyCertList(certList);
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
    
    const char *serialOIDTag = strstr(person, "serialNumber=");
    if (!serialOIDTag) {
        // Shouldn't happen
        return true;
    }
    
    const char *actualSerial = serialOIDTag + 13;
    size_t actualLength = strcspn(actualSerial, ",");
    
    return ((strlen(wantedSerial) == actualLength) &&
            (strncmp(wantedSerial, actualSerial, actualLength) == 0));
}

static X509 *findCert(const STACK_OF(X509) *certList,
                                 const KeyfileSubject *person,
                                 const unsigned int certMask) {
    int num = sk_X509_num (certList);
    for (int i = 0; i < num; i++) {
        char * dn;
        X509 *cert;
        cert = sk_X509_value (certList, i);
        dn = subject (X509_get_subject_name (cert));
        if (!strcmp (dn, person)) {
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
    if (!p12)
        return false;

    STACK_OF(X509) *certList = pkcs12_listCerts(p12);
    if (!certList) return false;
    
    X509 *cert = findCert(certList, person, certMask);
    if (!cert) {
        //CERT_DestroyCertList(certList);
        return false;
    }
    
    *count = 1;
    *certs = malloc(sizeof(char*));
    (*certs)[0] = der_encode(cert);

    X509_NAME *issuer = X509_get_issuer_name (cert);
    while (issuer != NULL) {
        char* issuerName;
        issuerName = subject (issuer);
        
        cert = findCert(certList, issuerName, CERTUSE_ISSUER);
        if (!cert) break;
        issuer = X509_get_issuer_name (cert);
        (*count)++;
        *certs = realloc(*certs, *count * sizeof(char*));
        (*certs)[*count-1] = der_encode(cert);
    }
    //CERT_DestroyCertList(certList);
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
    PKCS12 *p12;

    p12 = pkcs12_open (p12Data, p12Length);
    if (!p12)
        return false;
    STACK_OF(X509) *certList = pkcs12_listCerts(p12);
    
    int num = sk_X509_num (certList);
    for (int i = 0; i < num; i++) {
        char * dn;
        X509 *cert;
        cert = sk_X509_value (certList, i);
        dn = subject (X509_get_subject_name (cert));
        //TODO: free dn
        if (!strcmp(dn, person) && has_keyusage (cert, certMask)) {
            EVP_MD_CTX sig_ctx;
            unsigned char sig_buf[4096]; //TODO: size of sha

            EVP_PKEY *pk;
            pk = get_key (p12, cert, password, strlen(password));
            if (!pk) {
                //Wrong password
                return false;
            }

            EVP_SignInit(&sig_ctx, EVP_sha1());
            EVP_SignUpdate(&sig_ctx, message, messagelen);
            unsigned int sig_len = sizeof(sig_buf);
            int sig_err;
            sig_err = EVP_SignFinal(&sig_ctx, sig_buf,
                                    &sig_len, pk);
            *signature = malloc(sig_len);
            memcpy(*signature, sig_buf, sig_len);
            *siglen = sig_len;
            
            return true;
        }
    }
    
    return false;
}

