/*

  Copyright (c) 2009-2011 Samuel Lidén Borell <samuel@slbdata.se>
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

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <stdio.h>

typedef struct _PKCS12Token PKCS12Token;
#define TokenType PKCS12Token

#include "../common/defines.h"
#include "misc.h"
#include "request.h"
#include "backend_private.h"

typedef struct {
    int refCount;
    PKCS12 *data;
} SharedPKCS12;

struct _PKCS12Token {
    Token base;
    
    SharedPKCS12 *sharedP12;
    int p12Index;
    const X509_NAME *subjectName;
};

static const int opensslKeyUsages[] = {
    X509v3_KU_KEY_CERT_SIGN,     // KeyUsage_Issuing
    X509v3_KU_NON_REPUDIATION,   // KeyUsage_Signing
    X509v3_KU_DIGITAL_SIGNATURE, // KeyUsage_Authentication
};

static bool _backend_init(Backend *backend) {
    OpenSSL_add_all_algorithms();
    //listTokens(backend);
    return true;
}

static void _backend_free(Backend *backend) {
    EVP_cleanup();
}

/**
 * Parses a P12 file and returns a parsed representation of the file, with
 * a reference count so it can be shared by multiple tokens.
 */
static SharedPKCS12 *pkcs12_parse(const char *p12Data, const int p12Length) {
    BIO *bio;
    PKCS12 *data;
    
    // Parse P12 data
    bio = BIO_new_mem_buf((void *)p12Data, p12Length);
    if (!bio) return NULL;
    data = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);
    if (!data) return NULL;
    
    // Create a reference counted object
    SharedPKCS12 *sharedP12 = malloc(sizeof(SharedPKCS12));
    if (!sharedP12) {
        PKCS12_free(data);
        return NULL;
    }
    sharedP12->refCount = 1;
    sharedP12->data = data;
    
    return sharedP12;
}

/**
 * Releases a shared PKCS12 object. If nobody else is using the object then
 * it's freed.
 */
static void pkcs12_release(SharedPKCS12 *sharedP12) {
    if (--sharedP12->refCount == 0) {
        // We're the last reference holder to release the P12
        PKCS12_free(sharedP12->data);
        free(sharedP12);
    }
}

static EVP_PKEY *getPrivateKey(PKCS12 *p12, X509 *x509, const char* pass) {
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
                    PKCS8_PRIV_KEY_INFO *p8 = PKCS12_decrypt_skey(bag, pass, strlen(pass));
                    
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
static bool has_keyusage(X509 *cert, KeyUsage keyUsage) {
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
static char *getNamePropertyByNID(X509_NAME *name, int nid) {
    char *text;
    int length;
    
    length = X509_NAME_get_text_by_NID(name, nid, NULL, 0);
    if (length < 0) return NULL;
    
    text = malloc(length+1);
    text[0] = '\0'; // if the function would fail
    X509_NAME_get_text_by_NID(name, nid, text, length+1);
    return text;
}

static bool matchSubjectFilter(const Backend *backend, X509_NAME *name) {
    const char *subjectFilter = backend->notifier->subjectFilter;
    if (!subjectFilter) return true;
    
    // TODO use OBJ_txt2nid and support arbitrary OIDs?
    if ((strncmp(subjectFilter, "2.5.4.5=", 8) != 0) ||
        (strchr(subjectFilter, ',') != NULL)) {
        // OID 2.5.4.5 (Serial number) is the only supported/allowed filter
        return true; // Nothing to filter with
    }
    
    const char *wantedSerial = subjectFilter + 8;
    
    char *actualSerial = getNamePropertyByNID(name, NID_serialNumber);
    
    bool ok = !strcmp(actualSerial, wantedSerial);
    free(actualSerial);
    return ok;
}

/**
 * Creates a PKCS12 Token structure.
 */
static PKCS12Token *createToken(const Backend *backend, SharedPKCS12 *sharedP12,
                                X509_NAME *id, void *tag) {
    PKCS12Token *token = calloc(1, sizeof(PKCS12Token));
    if (!token) return NULL;
    token->base.backend = backend;
    token->base.status = TokenStatus_NeedPassword;
    token->base.displayName = getNamePropertyByNID(id, NID_commonName);
    token->base.tag = tag;
    token->sharedP12 = sharedP12;
    token->subjectName = id;
    sharedP12->refCount++;
    return token;
}

static void _backend_freeToken(PKCS12Token *token) {
    pkcs12_release(token->sharedP12);
    free(token);
}

/**
 * Adds all subjects in a PKCS12 files and notifies the frontend of them.
 */
static TokenError _backend_addFile(Backend *backend,
                                   const char *data, size_t length,
                                   void *tag) {
    SharedPKCS12 *p12 = pkcs12_parse(data, length);
    if (!p12) return TokenError_BadFile;
    
    STACK_OF(X509) *certList = pkcs12_listCerts(p12->data);
    if (!certList) return TokenError_Unknown;
    
    int certCount = sk_X509_num(certList);
    for (int i = 0; i < certCount; i++) {
        X509 *x = sk_X509_value(certList, i);
        
        if (!has_keyusage(x, backend->notifier->keyUsage)) goto dontAddCert;
        
        X509_NAME *id = X509_get_subject_name(x);
        if (!matchSubjectFilter(backend, id)) goto dontAddCert;
        
        PKCS12Token *token = createToken(backend, p12, id, tag);
        if (token) {
            backend->notifier->notifyFunction((Token*)token, TokenChange_Added);
            continue;
        }
        
      dontAddCert:
        X509_free(x);
    }
    
    pkcs12_release(p12);
    return TokenError_Success;
}

static X509 *findCert(const STACK_OF(X509) *certList,
                      const X509_NAME *name,
                      const KeyUsage keyUsage) {
    int num = sk_X509_num(certList);
    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(certList, i);
        if (!X509_NAME_cmp(X509_get_subject_name(cert), name) &&
            has_keyusage(cert, keyUsage)) {
            return cert;
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
static TokenError _backend_getBase64Chain(const PKCS12Token *token,
                                          char ***certs, size_t *count) {
    
    STACK_OF(X509) *certList = pkcs12_listCerts(token->sharedP12->data);
    if (!certList) return TokenError_Unknown;
    
    X509 *cert = findCert(certList, token->subjectName,
                          token->base.backend->notifier->keyUsage);
    if (!cert) {
        sk_X509_pop_free(certList, X509_free);
        return TokenError_Unknown;
    }
    
    *count = 1;
    *certs = malloc(sizeof(char*));
    (*certs)[0] = der_encode(cert);
    
    X509_NAME *issuer = X509_get_issuer_name(cert);
    while (issuer != NULL) {
        cert = findCert(certList, issuer, KeyUsage_Issuing);
        if (!cert) break;
        
        issuer = X509_get_issuer_name(cert);
        (*count)++;
        *certs = realloc(*certs, *count * sizeof(char*));
        (*certs)[*count-1] = der_encode(cert);
    }
    
    sk_X509_pop_free(certList, X509_free);
    return TokenError_Success;
}

static TokenError _backend_sign(PKCS12Token *token,
                                const char *message, size_t messagelen,
                                char **signature, size_t *siglen) {
    
    assert(message != NULL);
    assert(signature != NULL);
    assert(siglen != NULL);
    
    if (messagelen >= UINT_MAX) return TokenError_Unknown;
    
    // Find the certificate for the token
    STACK_OF(X509) *certList = pkcs12_listCerts(token->sharedP12->data);
    if (!certList) return TokenError_Unknown;
    
    X509 *cert = findCert(certList, token->subjectName,
                          token->base.backend->notifier->keyUsage);             
    if (!cert) {
        sk_X509_pop_free(certList, X509_free);
        return TokenError_Unknown;
    }
    
    // Get the corresponding private key
    EVP_PKEY *key = getPrivateKey(token->sharedP12->data, cert,
                                  token->base.password);
    sk_X509_pop_free(certList, X509_free);
    
    if (!key) return TokenError_BadPassword;
    
    // Sign with the default crypto with SHA1
    unsigned int sig_len = EVP_PKEY_size(key);
    *siglen = sig_len;
    *signature = malloc(sig_len);
    
    EVP_MD_CTX sig_ctx;
    EVP_MD_CTX_init(&sig_ctx);
    bool success = (EVP_SignInit(&sig_ctx, EVP_sha1()) &&
                    EVP_SignUpdate(&sig_ctx, message, messagelen) &&
                    EVP_SignFinal(&sig_ctx, (unsigned char*)*signature,
                                  &sig_len, key));
    EVP_MD_CTX_cleanup(&sig_ctx);
    EVP_PKEY_free(key);
    *siglen = sig_len;
    
    if (success) {
        return TokenError_Success;
    } else {
        free(*signature);
        return TokenError_Unknown;
    }
}

typedef struct CertReq {
    struct CertReq *next;
    
    const RegutilPKCS10 *pkcs10;
    EVP_PKEY *privkey;
    RSA *rsa;
    //X509 *x509;
    X509_REQ *x509;
} CertReq;

// This is just what Nexus Personal uses
#define MAC_ITER 8192
#define ENC_ITER 8192
#define ENC_NID NID_pbe_WithSHA1And3_Key_TripleDES_CBC
// EVP_R_UNKNOWN_PBE_ALGORITHM (!)

// Debug stuff
#define errstr (ERR_error_string(ERR_get_error(), NULL))
#include <openssl/err.h>

static TokenError saveKeys(const CertReq *reqs, const char *password,
                           FILE *file) {
    // TODO error handling
    ERR_load_crypto_strings();
    ERR_clear_error();
    
    // Add PKCS7 safes with the keys
    STACK_OF(PKCS7) *authsafes = NULL;
    while (reqs) {
        STACK_OF(SAFEBAG) *bags = NULL;
        
        // FIXME can we use the X509 here?
        
        PKCS12_SAFEBAG *bag = PKCS12_add_key(&bags, reqs->privkey,
            opensslKeyUsages[reqs->pkcs10->keyUsage], ENC_ITER, ENC_NID, (char*)password);
        // TODO extract name from subject DN
        //      maybe we can add the whole DN somehow?
        char *name = "names are not implemented yet";
        // friendlyName is always blank in asn1dump, why? (also in other P12 files)
        X509at_add1_attr_by_NID(&bag->attrib, NID_friendlyName, MBSTRING_UTF8,
                                (unsigned char*)name, strlen(name));
        //PKCS12_add_friendlyname(bag, name, strlen(name)); -- doesn't work either
        
        fprintf(stderr, "bag: %p,  bags: %p:   %s\n", bag, bags, errstr);
        PKCS12_add_safe(&authsafes, bags, -1, 0, NULL);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        reqs = reqs->next;
    }
    fprintf(stderr, "safes: %p:  %s\n", authsafes, errstr);
    
    // Create the PKCS12 wrapper
    PKCS12 *p12 = PKCS12_add_safes(authsafes, 0);
    fprintf(stderr, "p12: %p:    %s\n", p12, errstr);
    sk_PKCS7_pop_free(authsafes, PKCS7_free);
    PKCS12_set_mac(p12, (char*)password, -1, NULL, 0, MAC_ITER, NULL);
    
    // Save file
    i2d_PKCS12_fp(file, p12);
    PKCS12_free(p12);
    return TokenError_Success;
}

/**
 * Adds a key usage extension to the list of extensions in a request.
 */
static void addKeyUsage(STACK_OF(X509_EXTENSION) *exts, KeyUsage keyUsage) {
    static const char *const keyUsages[] = {
        NULL,                /* Issuing */
        "nonRepudiation",    /* Signing */
        "digitalSignature",  /* Authentication (yes, this is correct!) */
    };
    
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL,
        NID_key_usage, (char*)keyUsages[keyUsage]);
    if (!ext) abort();
    sk_X509_EXTENSION_push(exts, ext);
}

TokenError _backend_createRequest(const RegutilInfo *info,
                                  const char *password,
                                  char **request, size_t *reqlen) {
    // OpenSSL seeds the PRNG automatically, see the manual page for RAND_add.
    
    // Create certificate requests
    CertReq *reqs = NULL;
    //STACK_OF(X509) *x509s = NULL;
    STACK *x509reqs = sk_new_null();
    for (const RegutilPKCS10 *pkcs10 = info->pkcs10; pkcs10 != NULL;
         pkcs10 = pkcs10->next) {
        // Generate key pair
        // FIXME deprecated function
        // TODO use OPENSSL_NO_DEPRECATED
        RSA *rsa = RSA_generate_key(pkcs10->keySize, RSA_F4, NULL, NULL);
        EVP_PKEY *privkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(privkey, rsa);
        
        // Subject name
        // FIXME check for NULL subjectDN and return value
        X509_NAME *subject = dn_from_string(pkcs10->subjectDN, pkcs10->includeFullDN);
        
        // Create request
        X509_REQ *x509req = X509_REQ_new();
        X509_REQ_set_version(x509req, 0);
        X509_REQ_set_subject_name(x509req, subject);
        X509_REQ_set_pubkey(x509req, privkey); // appears to be correct(!)
        
        // Set attributes
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        addKeyUsage(exts, pkcs10->keyUsage);
        X509_REQ_add_extensions(x509req, exts);
        
        // Add signature
        X509_REQ_sign(x509req, privkey, EVP_sha1());
        
        // Store in list
        CertReq *req = malloc(sizeof(CertReq));
        req->pkcs10 = pkcs10;
        req->privkey = privkey;
        req->rsa = rsa;
        //req->x509 = x509;
        req->x509 = x509req;
        req->next = reqs;
        reqs = req;
        
        //sk_X509_push(x509s, x509);
        sk_push(x509reqs, (char*)x509req);
    }
    
    // Build the certificate request
    // TODO
    fprintf(stderr, "call req wrap\n");
    request_wrap(x509reqs, request, reqlen);
    fprintf(stderr, "leave req wrap\n");
    
    // Create the key file in ~/.cbt/name.p12
    // TODO get path
    FILE *keyfile = fopen("/home/samuellb/test_output.p12", "wb");
    TokenError error = saveKeys(reqs, password, keyfile);
    fclose(keyfile);
    
    // Free reqs
    while (reqs) {
        RSA_free(reqs->rsa);
        // The X509_REQs are free'd in request_wrap
        
        CertReq *next = reqs->next;
        free(reqs);
        reqs = next;
    }
    
    fprintf(stderr, "returning %d\n", error);
    return error;
}


TokenError _backend_storeCertificates(const char *p7data, size_t length) {
    // TODO
    fprintf(stderr, BINNAME ": StoreCertificates has not been implemented yet! (data=%p, length=%d)\n", p7data, length);
    return TokenError_NotImplemented;
}


/* Backend functions */
static const Backend backend_template = {
    .init = _backend_init,
    .free = _backend_free,
    .freeToken = _backend_freeToken,
    .addFile = _backend_addFile,
    .createRequest = _backend_createRequest,
    .storeCertificates = _backend_storeCertificates,
    .getBase64Chain = _backend_getBase64Chain,
    .sign = _backend_sign,
};

Backend *pkcs12_getBackend() {
    Backend *backend = malloc(sizeof(Backend));
    memcpy(backend, &backend_template, sizeof(Backend));
    return backend;
}


