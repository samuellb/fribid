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
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>

typedef struct PKCS12Token PKCS12Token;
#define TokenType PKCS12Token

#include "../common/defines.h"
#include "certutil.h"
#include "misc.h"
#include "platform.h"
#include "request.h"
#include "backend_private.h"

typedef struct {
    int refCount;
    PKCS12 *data;
} SharedPKCS12;

struct PKCS12Token {
    Token base;
    
    SharedPKCS12 *sharedP12;
    int p12Index;
    const X509_NAME *subjectName;
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
 * Creates a PKCS12 Token structure.
 */
static PKCS12Token *createToken(const Backend *backend, SharedPKCS12 *sharedP12,
                                X509_NAME *id, void *tag) {
    PKCS12Token *token = calloc(1, sizeof(PKCS12Token));
    if (!token) return NULL;
    token->base.backend = backend;
    token->base.status = TokenStatus_NeedPassword;
    token->base.displayName = certutil_getNamePropertyByNID(id, NID_name);
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
        
        if (!certutil_hasKeyUsage(x, backend->notifier->keyUsage)) goto dontAddCert;
        
        X509_NAME *id = X509_get_subject_name(x);
        if (!certutil_matchSubjectFilter(backend->notifier->subjectFilter, id))
            goto dontAddCert;
        
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

/**
 * Returns a list of DER-BASE64 encoded certificates, from the subject
 * to the root CA.
 */
static TokenError _backend_getBase64Chain(const PKCS12Token *token,
                                          char ***certs, size_t *count) {
    
    STACK_OF(X509) *certList = pkcs12_listCerts(token->sharedP12->data);
    if (!certList) return TokenError_Unknown;
    
    X509 *cert = certutil_findCert(certList, token->subjectName,
                                   token->base.backend->notifier->keyUsage,
                                   false);
    if (!cert) {
        sk_X509_pop_free(certList, X509_free);
        return TokenError_Unknown;
    }
    
    *count = 0;
    *certs = NULL;
    if (!certutil_addToList(certs, count, cert)) goto error;
    
    X509_NAME *issuer = X509_get_issuer_name(cert);
    while (issuer != NULL) {
        cert = certutil_findCert(certList, issuer, KeyUsage_Issuing, false);
        if (!cert) break;
        
        issuer = X509_get_issuer_name(cert);
        
        if (!certutil_addToList(certs, count, cert)) goto error;
    }
    
    sk_X509_pop_free(certList, X509_free);
    return TokenError_Success;
    
  error:
    certutil_freeList(certs, count);
    return TokenError_Unknown;
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
    
    X509 *cert = certutil_findCert(certList, token->subjectName,
                                   token->base.backend->notifier->keyUsage,
                                   false);
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
    X509_REQ *x509;
} CertReq;

// This is just what Nexus Personal uses
#define MAC_ITER 8192
#define ENC_ITER 8192
#define ENC_NID NID_pbe_WithSHA1And3_Key_TripleDES_CBC

// Used to implement same-origin checks in CreateRequest/StoreCertificates
#define OID_OWNING_HOST "2.25.30775131415393438240374622843663926555"

/**
 * Adds a key usage extension to the list of extensions in a request.
 */
static X509_EXTENSION *makeKeyUsageExt(KeyUsage keyUsage) {
    static const char *const keyUsages[] = {
        NULL,                /* Issuing */
        "nonRepudiation",    /* Signing */
        "digitalSignature",  /* Authentication (yes, this is correct!) */
    };
    
    return X509V3_EXT_conf_nid(NULL, NULL,
        NID_key_usage, (char*)keyUsages[keyUsage]);
}

static TokenError saveKeys(const CertReq *reqs, const char *hostname,
                           const char *password, FILE *file) {
    TokenError error = TokenError_Unknown;
    PKCS12 *p12 = NULL;
    
    // Add PKCS7 safes with the keys
    STACK_OF(PKCS7) *authsafes = NULL;
    uint32_t localKeyId = 0;
    size_t error_count = 0;
    while (reqs) {
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
        X509 *cert = NULL;
        ASN1_OBJECT *objOwningHost = NULL;
        uint32_t keyid = htonl(localKeyId++);
        error_count++; // Decremented on success
        
        // Add private key
        PKCS12_SAFEBAG *bag = PKCS12_add_key(&bags, reqs->privkey,
            opensslKeyUsages[reqs->pkcs10->keyUsage], ENC_ITER, ENC_NID, (char*)password);
        if (!bag) goto loop_end;
        
        // Add name and localKeyId to the key bag
        // TODO extract name from subject DN
        char *name = "names are not implemented yet";
        if (!X509at_add1_attr_by_NID(&bag->attrib, NID_friendlyName, MBSTRING_UTF8,
                                     (unsigned char*)name, strlen(name)) ||
            !PKCS12_add_localkeyid(bag, (unsigned char*)&keyid, sizeof(keyid)))
            goto loop_end;
        
        // Add a certificate so we can find the key by the subject name
        cert = X509_REQ_to_X509(reqs->x509, 3650, reqs->privkey);
        if (!cert ||
            !X509_keyid_set1(cert, (unsigned char*)&keyid, sizeof(keyid)))
            goto loop_end;
        
        if (!X509_add_ext(cert, makeKeyUsageExt(reqs->pkcs10->keyUsage), -1))
            goto loop_end;
        
        if (!PKCS12_add_cert(&bags, cert))
            goto loop_end;
        
        // Add hostname (FriBID extension) so we can do same-origin checks
        // TODO maybe we should use document.domain instead of document.location.hostname?
        objOwningHost = OBJ_txt2obj(OID_OWNING_HOST, 1);
        if (!objOwningHost) goto loop_end;
        
        bag = sk_PKCS12_SAFEBAG_value(bags, sk_PKCS12_SAFEBAG_num(bags)-1);
        if (!X509at_add1_attr_by_OBJ(&bag->attrib, objOwningHost, MBSTRING_UTF8,
                                     (unsigned char*)hostname, strlen(hostname)))
            goto loop_end;
        
        
        // Add a new authsafe
        if (!PKCS12_add_safe(&authsafes, bags, -1, 0, NULL))
            goto loop_end;
        
        
        // Success!
        error_count--;
        
      loop_end:
        ASN1_OBJECT_free(objOwningHost);
        X509_free(cert);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        reqs = reqs->next;
    }
    
    if (error_count != 0)
        goto end;
    
    // Create the PKCS12 wrapper
    p12 = PKCS12_add_safes(authsafes, 0);
    if (!p12) goto end;
    PKCS12_set_mac(p12, (char*)password, -1, NULL, 0, MAC_ITER, NULL);
    
    // Save file
    if (i2d_PKCS12_fp(file, p12)) {
        error = TokenError_Success;
    }
    
  end:
    sk_PKCS7_pop_free(authsafes, PKCS7_free);
    PKCS12_free(p12);
    return error;
}

TokenError _backend_createRequest(const RegutilInfo *info,
                                  const char *hostname,
                                  const char *password,
                                  char **request, size_t *reqlen) {
    // OpenSSL seeds the PRNG automatically, see the manual page for RAND_add.
    if (!RAND_status()) {
        fprintf(stderr, BINNAME ": no random state!\n");
        return TokenError_NoRandomState;
    }
    
    // Abort if there are no requests
    *request = NULL;
    if (!info->pkcs10) return TokenError_Unknown;
    
    // Create certificate requests
    bool ok = true;
    CertReq *reqs = NULL;
    STACK *x509reqs = sk_new_null();
    for (const RegutilPKCS10 *pkcs10 = info->pkcs10; pkcs10 != NULL;
         pkcs10 = pkcs10->next) {
        
        RSA *rsa = NULL;
        EVP_PKEY *privkey = NULL;
        X509_NAME *subject = NULL;
        X509_REQ *x509req = NULL;
        STACK_OF(X509_EXTENSION) *exts = NULL;
        
        // Check the parameters.
        // Maximum key size in OpenSSL:
        // http://www.mail-archive.com/openssl-users@openssl.org/msg58229.html
        if (!pkcs10->subjectDN || pkcs10->keySize < 1024 ||
            pkcs10->keySize > 16384)
            goto req_error;
        
        // Generate key pair
        // FIXME deprecated function
        // TODO use OPENSSL_NO_DEPRECATED
        rsa = RSA_generate_key(pkcs10->keySize, RSA_F4, NULL, NULL);
        if (!rsa) goto req_error;
        privkey = EVP_PKEY_new();
        if (!privkey) goto req_error;
        EVP_PKEY_assign_RSA(privkey, rsa);
        
        // Subject name
        subject = certutil_parse_dn(pkcs10->subjectDN, pkcs10->includeFullDN);
        if (!subject) goto req_error;
        
        // Create request
        x509req = X509_REQ_new();
        if (!x509req ||
            !X509_REQ_set_version(x509req, 0) ||
            !X509_REQ_set_subject_name(x509req, subject) ||
            !X509_REQ_set_pubkey(x509req, privkey)) // yes this is correct(!)
            goto req_error;
        
        // Set attributes
        exts = sk_X509_EXTENSION_new_null();
        if (!exts) goto req_error;
        
        X509_EXTENSION *ext = makeKeyUsageExt(pkcs10->keyUsage);
        if (!ext || !sk_X509_EXTENSION_push(exts, ext))
            goto req_error;
        
        if (!X509_REQ_add_extensions(x509req, exts))
            goto req_error;
        exts = NULL;
        
        // Add signature
        if (!X509_REQ_sign(x509req, privkey, EVP_sha1()))
            goto req_error;
        
        // Store in list
        CertReq *req = malloc(sizeof(CertReq));
        req->pkcs10 = pkcs10;
        req->privkey = privkey;
        req->rsa = rsa;
        req->x509 = x509req;
        req->next = reqs;
        reqs = req;
        
        sk_push(x509reqs, (char*)x509req);
        
        continue;
        
      req_error:
        // Clean up and set error flag
        if (privkey) EVP_PKEY_free(privkey);
        else if (rsa) RSA_free(rsa);
        
        X509_NAME_free(subject);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        X509_REQ_free(x509req);
        
        ok = false;
    }
    
    TokenError error = TokenError_Unknown;
    
    if (ok) {
        // Determine filename from certificate name
        char *filename = certutil_makeFilename(X509_REQ_get_subject_name(reqs->x509));
        
        // Build the certificate request
        request_wrap(x509reqs, request, reqlen);
        
        if (*request && filename) {
            // Create the key file in ~/cbt/name.p12
            FILE *keyfile = platform_openLocked(filename, Platform_OpenCreate);
            if (!keyfile) {
                error = TokenError_CantCreateFile;
            } else {
                error = saveKeys(reqs, hostname, password, keyfile);
                if (!platform_closeLocked(keyfile) && !error)
                    error = TokenError_CantCreateFile;
            }
            
        }
        
        if (filename) free(filename);
        if (error && *request) free(*request);
    }
    
    // Free reqs
    while (reqs) {
        RSA_free(reqs->rsa); // This free's privkey too
        X509_REQ_free(reqs->x509);
        
        CertReq *next = reqs->next;
        free(reqs);
        reqs = next;
    }
    sk_free(x509reqs);
    
    return error;
}

static TokenError storeCertificates(STACK_OF(X509) *certs,
                                    const char *hostname,
                                    const char *filename) {
    TokenError error = TokenError_Unknown;
    PKCS12 *p12 = NULL;
    STACK_OF(PKCS7) *authsafes = NULL;
    FILE *newFile = NULL;
    char *tempname = NULL;
    bool modified = false;
    
    // Attempt to create new file first
    // (to avoid race conditions)
    tempname = rasprintf("%s.tmp", filename);
    if (!tempname) goto end;
    newFile = platform_openLocked(tempname, Platform_OpenCreate);
    if (!newFile) goto end;
    
    // Load file
    FILE *orig = platform_openLocked(filename, Platform_OpenRead);
    if (!orig) goto end;
    d2i_PKCS12_fp(orig, &p12);
    platform_closeLocked(orig);
    if (!p12) goto end;
    
    // For each PKCS7 safe
    authsafes = PKCS12_unpack_authsafes(p12);
    if (!authsafes) goto end;
    int nump = sk_PKCS7_num(authsafes);
    for (int p = 0; p < nump; p++) {
        PKCS7 *p7 = sk_PKCS7_value(authsafes, p);
        if (!p7) continue;
        
        STACK_OF(PKCS12_SAFEBAG) *safebags = PKCS12_unpack_p7data(p7);
        if (!safebags) continue;
        
        // For each safebag
        bool match = false;
        int numsb = sk_PKCS12_SAFEBAG_num(safebags);
        for (int i = 0; i < numsb; i++) {
            PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(safebags, i);
            if (!bag || M_PKCS12_bag_type(bag) != NID_certBag) continue;
            
            // Perform same-origin check
            ASN1_OBJECT *objOwningHost = OBJ_txt2obj(OID_OWNING_HOST, 1);
            if (!objOwningHost) continue;
            
            char *origin = certutil_getBagAttr(bag, objOwningHost);
            bool equal = (origin && strcmp(origin, hostname) == 0);
            free(origin);
            ASN1_OBJECT_free(objOwningHost);
            if (!equal) continue;
            
            // Extract cert from bag
            X509 *cert = PKCS12_certbag2x509(bag);
            if (!cert) continue;
            
            // Get subject name and key usage
            X509_NAME *name = X509_get_subject_name(cert);
            
            ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert, NID_key_usage,
                                                      NULL, NULL);
            if (name && usage && usage->length > 0) {
                const KeyUsage keyUsage =
                    ((usage->data[0] & X509v3_KU_NON_REPUDIATION) == X509v3_KU_NON_REPUDIATION ?
                        KeyUsage_Signing : KeyUsage_Authentication);
                
                // Check if it matches
                X509 *issuedCert = certutil_findCert(certs, name,
                                                     keyUsage, true);
                if (issuedCert) {
                    // Remove temporary cert
                    (void)sk_PKCS12_SAFEBAG_delete(safebags, i);
                    int lkidLength;
                    unsigned char *lkid = X509_keyid_get0(cert, &lkidLength);
                    
                    // Link this cert to the key
                    if (lkid) {
                        X509_keyid_set1(issuedCert, lkid, lkidLength);
                    }
                    
                    match = true;
                }
            }
            
            X509_free(cert);
            ASN1_BIT_STRING_free(usage);
        }
        
        if (match) {
            // Add certs
            int num_certs = sk_X509_num(certs);
            for (int ci = 0; ci < num_certs; ci++) {
                X509 *cert = sk_X509_value(certs, ci);
                PKCS12_add_cert(&safebags, cert);
            }
            
            
            // Update PKCS12
            (void)sk_PKCS7_delete(authsafes, p);
            PKCS12_add_safe(&authsafes, safebags, -1, 0, NULL);
            
            p12 = PKCS12_add_safes(authsafes, 0);
            
            // TODO We don't add a MAC here. Does the official client require
            //      a MAC in PKCS#12 certs? Obviously we need the password
            //      to add a MAC, which we no longer have at this point.
            //
            //      The process that created the request (and asked for a
            //      password) could stay alive (it knows the password) a
            //      few minutes so StoreCertificates could add a MAC or
            //      even add certificates through it.
            //PKCS12_set_mac(p12, "123456qwerty", -1, NULL, 0, MAC_ITER, NULL);
            
            modified = true;
            break;
        }
        
        sk_PKCS12_SAFEBAG_pop_free(safebags, PKCS12_SAFEBAG_free);
    }
    
    sk_PKCS7_pop_free(authsafes, PKCS7_free);
    
    if (!modified || !p12) goto end;
    
    // Save
    if (!i2d_PKCS12_fp(newFile, p12)) goto end;
    
    if (platform_closeLocked(newFile)) {
       newFile = NULL;
       
       // Replace old file with the new one
       if (rename(tempname, filename) == 0)
           error = TokenError_Success;
    }
    
  end:
    if (newFile) platform_deleteLocked(newFile, tempname);
    free(tempname);
    PKCS12_free(p12);
    
    // Write error (if any) to stderr
    if (!p12) {
        fprintf(stderr, BINNAME ": failed to open or parse file to store "
                "certs in %s\n", filename);
    } else if (!modified) {
        fprintf(stderr, BINNAME ": no certs matched the key file %s\n",
                filename);
    } else if (error) {
        fprintf(stderr, BINNAME ": failed to store certificates in %s\n",
                filename);
    }
    
    return error;
}

TokenError _backend_storeCertificates(const char *p7data, size_t length,
                                      const char *hostname) {
    
    PKCS7 *p7 = certutil_parseP7SignedData(p7data, length);
    if (!p7) return TokenError_Unknown;
    
    // Find the own cert
    TokenError error = TokenError_Unknown;
    STACK_OF(X509) *certs = p7->d.sign->cert;
    X509 *self = NULL;
    int numc = sk_X509_num(certs);
    for (int i = 0; i < numc; i++) {
        X509 *cert = sk_X509_value(certs, i);
        // TODO maybe we should look at the certificate chain instead?
        ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert, NID_key_usage,
                                                  NULL, NULL);
        if (usage && usage->length > 0 &&
            (usage->data[0] & (X509v3_KU_DIGITAL_SIGNATURE | X509v3_KU_NON_REPUDIATION)) != 0) {
            // CA certs generally can be used for signatures,
            // so assume this is should be our own cert
            self = cert;
            break;
        }
    }
    
    if (self) {
        // Get file name
        char *filename = certutil_makeFilename(X509_get_subject_name(self));
        
        // Add the certs to this file
        if (filename) {
            error = storeCertificates(certs, hostname, filename);
            free(filename);
        }
    }
    
    PKCS7_free(p7);
    return error;
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


