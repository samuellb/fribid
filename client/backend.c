/*

  Copyright (c) 2010-2011 Samuel Lidén Borell <samuel@slbdata.se>
 
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

#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <stdio.h>

#include "../common/defines.h"
#include "backend_private.h"
#include "certutil.h"


// Available backends
Backend *pkcs11_getBackend();
Backend *pkcs12_getBackend();

static void addBackend(BackendNotifier *notifier, Backend *backend) {
    if (backend == NULL) return;
    
    if (!backend->init(backend)) return;
    
    notifier->backends = realloc(notifier->backends,
                                 (notifier->backendCount+1) * sizeof(Backend*));
    notifier->backends[notifier->backendCount] = backend;
    notifier->backendCount++;
    backend->notifier = notifier;
}

/**
 * Subscribes to all changes of tokens that match the subjectFilter (optional)
 * and usage. If any tokens are already present when calling this method, then
 * you're notified about them too.
 *
 * The notification function may be called from a separate thread.
 */
BackendNotifier *backend_createNotifier(const char *subjectFilter,
                                        KeyUsage keyUsage,
                                        BackendNotifyFunction notifyFunction) {
    BackendNotifier *notifier = calloc(1, sizeof(BackendNotifier));
    notifier->subjectFilter = (subjectFilter ? strdup(subjectFilter) : NULL);
    notifier->keyUsage = keyUsage;
    notifier->notifyFunction = notifyFunction;
    
    // Add all backends
    addBackend(notifier, pkcs12_getBackend());
#if ENABLE_PKCS11
    addBackend(notifier, pkcs11_getBackend());
#endif
    return notifier;
}

/**
 * Shuts down and frees a notifier. Don't call while calling token_sign
 * or token_getBase64Chain.
 */
void backend_freeNotifier(BackendNotifier *notifier) {
    for (size_t i = 0; i < notifier->backendCount; i++) {
        Backend *b = notifier->backends[i];
        b->free(b);
        free(b);
        // TODO remove/free tokens?
    }
    free(notifier->subjectFilter);
    free(notifier);
}

/**
 * Manually adds a soft token. The "tag" is assigned to the token, and can
 * point to anything (for example, the filename).
 */
TokenError backend_addFile(BackendNotifier *notifier,
                           const char *file, size_t length, void *tag) {
    TokenError lastError = TokenError_Unknown;
    for (size_t i = 0; i < notifier->backendCount; i++) {
        Backend *backend = notifier->backends[i];
        if (backend->addFile) {
            lastError = backend->addFile(backend, file, length, tag);
            if (!lastError) break;
        }
    }
    return lastError;
}

/**
 * Scan backends for tokens
 */
void backend_scanTokens(BackendNotifier *notifier)
{
    for (size_t i = 0; i < notifier->backendCount; i++) {
        Backend *backend = notifier->backends[i];
        if (backend->scan) {
            backend->scan(backend);
        }
    }
}

/**
 * Generates a key pair and creates a certificate request for it.
 */
TokenError backend_createRequest(const RegutilInfo *info,
                                 const char *hostname,
                                 const char *password,
                                 char **request, size_t *reqlen) {
    // TODO support smartcards too (if this is used anywhere)
    TokenError error = TokenError_NotImplemented;
    
    Backend *backend = pkcs12_getBackend();
    if (backend->init(backend) && backend->createRequest)
        error = backend->createRequest(info, hostname, password,
                                       request, reqlen);
    
    backend->free(backend);
    return error;
}

/**
 * Returns the display name of the given distinguished name
 */
char *backend_getSubjectDisplayName(const char *dn) {
    X509_NAME *xname = certutil_parse_dn(dn, true);
    if (!xname) return NULL;
    
    char *displayName = certutil_getNamePropertyByNID(xname, NID_name);
    
    X509_NAME_free(xname);
    return displayName;
}

/**
 * Stores a certificate chain for a request.
 */
TokenError backend_storeCertificates(const char *p7data, size_t length,
                                     const char *hostname) {
    // TODO support smartcards too (if this is used anywhere)
    TokenError error = TokenError_NotImplemented;
    
    Backend *backend = pkcs12_getBackend();
    if (backend->init(backend) && backend->storeCertificates)
        error = backend->storeCertificates(p7data, length, hostname);
    
    backend->free(backend);
    return error;
}

/**
 * Gets the status of a token.
 */
TokenStatus token_getStatus(const Token *token) {
    return token->status;
}

char *token_getDisplayName(const Token *token) {
    return token->displayName ? strdup(token->displayName) : NULL;
}

void *token_getTag(const Token *token) {
    return token->tag;
}

/**
 * Sets the password to use for signing. Do not free the password until the
 * token is no longer in use.
 */
void token_usePassword(Token *token, const char *password) {
    token->password = password;
    token->lastError = TokenError_Success;
}

/**
 * Gets the tokens certificate chain.
 */
bool token_getBase64Chain(Token *token, char ***certs, size_t *count) {
    token->lastError = token->backend->getBase64Chain(token, certs, count);
    return (token->lastError == TokenError_Success);
}

bool token_sign(Token *token, const char *message, size_t messagelen,
                char **signature, size_t *siglen) {
    token->lastError = token->backend->sign(token, message, messagelen,
                                            signature, siglen);
    return (token->lastError == TokenError_Success);
}

/**
 * Removes a token that was manually added with backend_addFile
 */
bool token_remove(Token *token) {
    if (token->isManuallyAdded) {
        token->backend->notifier->notifyFunction(token, TokenChange_Removed);
        return true;
    }
    return false;
}

/**
 * Free's a token. Don't free a token until it has been removed.
 */
void token_free(Token *token) {
    token->backend->freeToken(token);
}

TokenError token_getLastError(const Token *token) {
    return token->lastError;
}

