/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
  Copyright (c) 2010 Marcus Carlson <marcus@mejlamej.nu>
  Copyright (c) 2010 Henrik Nordström <henrik@henriknordstrom.net>
 
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
#include <openssl/sha.h>
#include <libp11.h>
#include <openssl/safestack.h>
#include <stdio.h>

typedef struct _PKCS11Token PKCS11Token;
typedef struct _PKCS11Private PKCS11Private;
#define TokenType PKCS11Token
#define BackendPrivateType PKCS11Private

#include "../common/defines.h"
#include "certutil.h"
#include "misc.h"
#include "backend_private.h"

struct _PKCS11Token {
    Token base;
    PKCS11_SLOT *slot;
    PKCS11_CERT *certs;
    unsigned int ncerts;
};

struct _PKCS11Private {
    PKCS11_CTX *ctx;
    unsigned int nslots;
    PKCS11_SLOT *slots;
};

static void _backend_freeToken(PKCS11Token *token) {
    free(token);
}

static X509 *findCert(const PKCS11Token *token,
                      const X509_NAME *name,
                      const KeyUsage keyUsage) {
    for (unsigned int i = 0; i < token->ncerts; i++) {
        X509 *cert = token->certs[i].x509;
        if (!X509_NAME_cmp(X509_get_subject_name(cert), name) &&
            certutil_hasKeyUsage(cert, keyUsage)) {
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
static TokenError _backend_getBase64Chain(const PKCS11Token *token,
                                          char ***certs, size_t *count) {
    
    X509 *cert = token->certs[0].x509;
    if (!cert) {
        return TokenError_Unknown;
    }
    
    *count = 1;
    *certs = malloc(sizeof(char*));
    (*certs)[0] = certutil_derEncode(cert);
    
    X509_NAME *issuer = X509_get_issuer_name(cert);
    while (issuer != NULL) {
        cert = findCert(token, issuer, KeyUsage_Issuing);
        if (!cert) break;
        
        issuer = X509_get_issuer_name(cert);
        (*count)++;
        *certs = realloc(*certs, *count * sizeof(char*));
        (*certs)[*count-1] = certutil_derEncode(cert);
    }
    
    return TokenError_Success;
}

#ifndef SHA1_LENGTH
#define SHA1_LENGTH 20
#endif
static TokenError _backend_sign(PKCS11Token *token,
                                const char *message, size_t messagelen,
                                char **signature, size_t *siglen) {
    
    assert(message != NULL);
    assert(signature != NULL);
    assert(siglen != NULL);
    
    if (messagelen >= UINT_MAX) return TokenError_Unknown;
    
    if (token->slot->token->loginRequired) {
        if (PKCS11_login(token->slot, 0, token->base.password) != 0)
            return TokenError_BadPin;
    }

    // Find the key for the token
    PKCS11_CERT *cert = &token->certs[0];
    PKCS11_KEY *key = PKCS11_find_key(cert);

    if (!key) return TokenError_BadPin;
    
    // Sign with the default crypto with SHA1
    unsigned char shasum[SHA1_LENGTH];
    SHA1((unsigned char*)message, messagelen, shasum);
    unsigned int sigLen = 256;
    *signature = malloc(sigLen);
    int rc = PKCS11_sign(NID_sha1, shasum, SHA1_LENGTH, (unsigned char*)*signature, &sigLen, key);
    *siglen = sigLen;
    if (rc != 1) {
        free(*signature);
        *signature = NULL;
        return TokenError_Unknown;
    }
    return TokenError_Success;
}

/**
 * Load cert from a populated card slot
 */
static void pkcs11_found_token(Backend *backend, PKCS11_SLOT *slot) {
    int rc;
    
    PKCS11Token *token = calloc(1, sizeof(PKCS11Token));
    if (!token) return;

    token->slot = slot;

    // Scan card
    rc = PKCS11_enumerate_certs(slot->token, &token->certs, &token->ncerts);
    if (token->ncerts == 0)
        goto fail;

    // Firts cert in the chain is the user cert. Rest is associated authority certs
    X509 *x = token->certs[0].x509;
    X509_NAME *id = X509_get_subject_name(x);

    if (!certutil_hasKeyUsage(x, backend->notifier->keyUsage))
        goto fail;

    if (!certutil_matchSubjectFilter(backend->notifier->subjectFilter, id))
        goto fail;

    token->base.backend = backend;
    if (slot->token->secureLogin == 0) {
        token->base.status = TokenStatus_NeedPassword;
    } else {
        token->base.status = TokenStatus_NeedPIN;
    }
    token->base.displayName = certutil_getNamePropertyByNID(id, NID_name);
    token->base.tag = slot->token->label;
    backend->notifier->notifyFunction(&token->base, TokenChange_Added);
    return;

fail:
    backend->freeToken(token);
}

/**
 * Load certs from all tokens
 */
static void _backend_scan(Backend *backend) {
    for (unsigned int i = 0; i < backend->private->nslots; i++) {
        if (backend->private->slots[i].token) {
            pkcs11_found_token(backend, &backend->private->slots[i]);
        }
    }
}

static bool expected_error(unsigned long error) {
#if OPTIONAL_PKCS11
    // Use PKCS#11 if available, and ignore errors if it's not
    return ERR_GET_FUNC(error) == SYS_F_FOPEN; // ignore failures to open files
#else
    return false;
#endif
}

static bool _backend_init(Backend *backend) {
    backend->private = calloc(1, sizeof(*backend->private));
    OpenSSL_add_all_algorithms();
    backend->private->ctx = PKCS11_CTX_new();

    /* load pkcs #11 module */
    // TODO: Runtime config parameter
    if (PKCS11_CTX_load(backend->private->ctx, DEFAULT_PKCS11_ENGINE) != 0) {
        unsigned long error = ERR_get_error();
        if (!expected_error(error)) {
            fprintf(stderr, BINNAME ": loading pkcs11 engine failed: %s\n",
                ERR_reason_error_string(error));
        }
        PKCS11_CTX_free(backend->private->ctx);
        return false;
    }

    /* get information on all slots */
    if (PKCS11_enumerate_slots(backend->private->ctx, &backend->private->slots, &backend->private->nslots) < 0) {
        fprintf(stderr, BINNAME ": no slots (card readers) available\n");
        PKCS11_CTX_free(backend->private->ctx);
        return false;
    }

    return true;
}

static void _backend_free(Backend *backend) {
    PKCS11_release_all_slots(backend->private->ctx, backend->private->slots, backend->private->nslots);
    PKCS11_CTX_free(backend->private->ctx);
    free(backend->private);
    EVP_cleanup();
}

/* Backend functions */
static const Backend backend_template = {
    .init = _backend_init,
    .scan = _backend_scan,
    .free = _backend_free,
    .freeToken = _backend_freeToken,
    .getBase64Chain = _backend_getBase64Chain,
    .sign = _backend_sign,
};

Backend *pkcs11_getBackend() {
    Backend *backend = malloc(sizeof(Backend));
    memcpy(backend, &backend_template, sizeof(Backend));
    return backend;
}


