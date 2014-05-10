/*

  Copyright (c) 2009-2014 Samuel Lidén Borell <samuel@kodafritt.se>
 
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
#include <time.h>
#include <stdint.h>
#include <inttypes.h>

#include "../common/defines.h"
#include "backend.h"
#include "xmldsig.h"
#include "misc.h"
#include "bankid.h"
#include "platform.h"
#include "prefs.h"

/**
 * Returns the version string. The version string is identical to that of
 * Nexus Personal for Linux in order to be compatible with all servers, which
 * may or may not accept unofficial version strings.
 */
char *bankid_getVersion(void) {
    static const char template[] =
        "Personal=%1$s&"
        "libai_so=%1$s&"
        "libP11_so=%1$s&"
        "libtokenapi_so=%1$s&"
        "libCardSiemens_so=%1$s&"
        "libCardSetec_so=%1$s&"
        "libCardPrisma_so=%1$s&"
        "libBranding_so=%1$s&"
        "libplugins_so=%1$s&"
        "personal_bin=%1$s&"
#if ENABLE_PKCS11
        /* TODO: This should be generated from list of smartcards */
        "SmartCard_Reader=Handelsbanken card reader [MCI_OSR_0205] 00 00&"
#endif
        "platform=linux&"
        "distribution=unknown&"
        "os_version=unknown&"
        "best_before=%2$" PRId64 "&";
    
    int64_t expiry = time(NULL) + 29*24*3600;
    
    const char *versionToEmulate = (prefs_bankid_emulatedversion ?
        prefs_bankid_emulatedversion : /* Manual override */
        EMULATED_VERSION); /* Recommended version number */
    
    return rasprintf(template, versionToEmulate, expiry);
}

/* Authentication and signing objects */
static const char sign_template[] =
    "<bankIdSignedData xmlns=\"http://www.bankid.com/signature/v1.0.0/types\" Id=\"bidSignedData\">"
        "%s" /* Any signed message is inserted here */
        "<srvInfo>"
            "<nonce>%s</nonce>"
            "%s" /* Optional server time value */
        "</srvInfo>"
        "<clientInfo>"
            "<funcId>%s</funcId>"
            "<host>"
                "<fqdn>%s</fqdn>"
                "<ip>%s</ip>"
            "</host>"
            "<version>%s</version>"
        "</clientInfo>"
    "</bankIdSignedData>";

static const char signedText_template[] =
    "<usrVisibleData charset=\"%s\" visible=\"wysiwys\">"
        "%s"
    "</usrVisibleData>";

static const char signedInvisibleText_template[] =
    "<usrNonVisibleData>"
        "%s"
    "</usrNonVisibleData>";

static const char signobj_id[] = "bidSignedData";

/**
 * Creates a BankID-compatible xmldsig signature
 *
 * @param token      The token to sign the data with. (see backend.h)
 *                   If the key of the token encrypted, you must call
 *                   backend_login() on it first.
 * @param challenge  The nonce sent by the server
 * @param serverTime A positive 32-bit, 10-digit integer from server.
 *                   Set it to 0 if absent.
 * @param hostname   Hostname of the server that requested the signature
 * @param ip         IP address of the server
 * @param purpose    Either "Identification" or "Signing"
 * @param extra      Extra data to include. This is generally a
 *                   usrVisibleData tag
 *
 * @param signature  The resulting signature. It's allocated and
 *                   is null-terminated.
 *
 * @return  A status code (see ../common/biderror.h)
 */
static BankIDError sign(Token *token,
                        const char *challenge, int32_t serverTime,
                        const char *hostname, const char *ip,
                        const char *purpose, const char *extra,
                        char **signature) {
    
    // Create the authentication XML
    char *versionStr = bankid_getVersion();
    char *version = base64_encode(versionStr, strlen(versionStr));
    free(versionStr);
    
    char *timeElement = "";
    if (serverTime) {
        timeElement = rasprintf("<serverTime>%" PRIu32 "</serverTime>",
                                serverTime);
    }
    
    char *object = rasprintf(sign_template, extra, challenge, timeElement,
                             purpose, hostname, ip, version);
    
    if (serverTime) free(timeElement);
    free(version);
    
    // Sign
    char *xmlsig = xmldsig_sign(token, signobj_id, object);
    free(object);
    
    if (xmlsig) {
        // Encode with base64
        *signature = base64_encode(xmlsig, strlen(xmlsig));
        free(xmlsig);
        return BIDERR_OK;
    } else {
        *signature = NULL;
        return BIDERR_InternalError;
    }
}

BankIDError bankid_authenticate(Token *token,
                                const char *challenge, int32_t serverTime,
                                const char *hostname, const char *ip,
                                char **signature) {
    return sign(token, challenge, serverTime, hostname, ip,
                "Identification", "", signature);
}

BankIDError bankid_sign(Token *token,
                        const char *challenge, int32_t serverTime,
                        const char *hostname, const char *ip,
                        const char *messageEncoding, const char *message,
                        const char *invisibleMessage,
                        char **signature) {
    BankIDError error;
    
    char *extra = rasprintf(signedText_template, messageEncoding, message);
    
    if (invisibleMessage) {
        extra = rasprintf_append(extra, signedInvisibleText_template, invisibleMessage);
    }
    
    error = sign(token, challenge, serverTime, hostname, ip,
                 "Signing", extra, signature);
    
    free(extra);
    return error;
}

/**
 * Generates a new key pair and creates a certificate request.
 *
 * @param params     Parameters (from SetParam/InitRequest calls).
 * @param password   A password or PIN entered on the keyboard.
 * @param request    The certificate request, Base64 encoded.
 * @param error      A more detailed error code is stored here
 */
BankIDError bankid_createRequest(const RegutilInfo *params,
                                 const char *hostname,
                                 const char *password,
                                 char **request,
                                 TokenError *error) {
    *request = NULL;
    
    char *binaryRequest;
    size_t brlen;
    *error = backend_createRequest(params, hostname, password,
                                   &binaryRequest, &brlen);
    if (*error) return BIDERR_InternalError;
    
    // Encode with Base64
    *request = base64_encode(binaryRequest, brlen);
    free(binaryRequest);
    if (!*request) {
        *error = TokenError_Unknown;
        return BIDERR_InternalError;
    } else {
        return BIDERR_OK;
    }
}

/**
 * Gets the first subject display name in a request.
 */
char *bankid_getRequestDisplayName(const RegutilInfo *params) {
    // params->pkcs10 is the first request
    if (!params->pkcs10 || !params->pkcs10->subjectDN) return NULL;
    
    return backend_getSubjectDisplayName(params->pkcs10->subjectDN);
}

/**
 * Stores a certificate chain for a newly created key.
 */
BankIDError bankid_storeCertificates(const char *certs, const char *hostname) {
    
    size_t length;
    char *p7data = base64_decode_binary(certs, &length);
    
    if (!p7data) return BIDERR_InternalError;
    
    TokenError storeerror = backend_storeCertificates(p7data, length, hostname);
    BankIDError error;
    if (storeerror) {
        error = BIDERR_InternalError;
    } else {
        error = BIDERR_OK;
    }
    
    free(p7data);
    return error;
}


