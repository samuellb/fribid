/*

  Copyright (c) 2009 Samuel Lidén Borell <samuel@slbdata.se>
 
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
#include "keyfile.h"
#include "xmldecisec.h"
#include "misc.h"
#include "bankid.h"
#include "platform.h"

void bankid_init() {
    keyfile_init();
}

void bankid_shutdown() {
    keyfile_shutdown();
}

#define EXPIRY_RAND (rand() % 65535)

static char *getVersionString() {
    static const char *template =
        "Personal=4.10.2.16&libtokenapi_so=4.10.2.16&libBranding_so=4.10.2.16&libCardSetec_so=4.10.2.16&libCardPrisma_so=4.10.2.16&libCardSiemens_so=4.10.2.16&libplugins_so=4.10.2.16&libP11_so=4.10.2.16&libai_so=4.10.2.16&personal_bin=4.10.2.16&"
        "platform=linux&distribution=ubuntu&os_version=8.04&best_before=%" PRId64 "&";
    
    long lexpiry;
    int64_t expiry;
    
    PlatformConfig *cfg = platform_openConfig(BINNAME, "expiry");
    if (platform_getConfigInteger(cfg, "expiry", "best-before", &lexpiry)) {
        expiry = lexpiry;
    } else {
        expiry = RELEASE_TIME - EXPIRY_RAND;
    }
    platform_freeConfig(cfg);
    
    char *result = malloc(strlen(template) -1 + 21 + 1);
    sprintf(result, template, expiry);
    return result;
}

static const char *checkHost = "159.72.128.183";

static void connectionError() {
    fprintf(stderr, BINNAME ": failed to connect to %s and check version validity\n", checkHost);
}

static bool checkValidity(bool *valid) {
    static const char *template =
        "POST / HTTP/1.1\r\n"
        "Host: 159.72.128.183\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: "BINNAME"\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Type: application/xml; charset=utf-8\r\n"
        "\r\n"
        "<?xml version=\"1.0\"?>"
        "<autoUpdateRequest>"
            "<requestVersion>1.0</requestVersion>"
            "<versionString>%s</versionString>"
        "</autoUpdateRequest>";
    
    
    char *versionString = getVersionString();
    char *request = malloc(strlen(template) - 2*2 +
                           10 + strlen(versionString) + 1);
    sprintf(request, template, 127+strlen(versionString), versionString);
    free(versionString);
    
    PlatformSocket *sock = platform_connectToHost(checkHost, true, 80);
    
    if (!sock) {
        connectionError();
        free(request);
        return false;
    }
    
    if (!platform_socketSend(sock, request, strlen(request))) {
        connectionError();
        free(request);
        platform_closeSocket(sock);
        return false;
    }
    free(request);
    
    char *response;
    int responseLen;
    // FIXME: The server could send the response in multiple packets...
    // Note that this function zero-terminates the buffer
    if (!platform_socketReceive(sock, &response, &responseLen)) {
        connectionError();
        platform_closeSocket(sock);
        return false;
    }
    platform_closeSocket(sock);
    
    static const char *httpOk = "HTTP/1.1 200 ";
    
    const bool httpIsOk = (strncmp(response, httpOk, strlen(httpOk)) == 0);
    const char *headersEnd = strstr(response, "\r\n\r\n");
    if (!httpIsOk || !headersEnd) {
        // Not OK
        connectionError();
        free(response);
        platform_closeSocket(sock);
        return false;
    }
    
    // Skip needless "Byte Order Mark"
    const char *ZWSP = "\357\273\277";
    const char *xml = headersEnd+4;
    if (strncmp(xml, ZWSP, 3) == 0) {
        xml += 3;
    }
    
    static const char *start =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<autoUpdateResponse><responseVersion>1.0</responseVersion><action>";
    
    static const char *end =
        "</action></autoUpdateResponse>";
    
    if ((strlen(xml) <= strlen(start) + strlen(end)) ||
        (strncmp(xml, start, strlen(start)) != 0)) {
        connectionError();
        free(response);
        return false;
    }
    
    const char *status = xml + strlen(start);
    const int statusLength = strcspn(status, "<");
    
    if (strcmp(status+statusLength, end) != 0) {
        connectionError();
        free(response);
        return false;
    }
    
    if (strncmp(status, "OK", statusLength) == 0) {
        *valid = true;
    } else if (strncmp(status, "Revoked", statusLength) == 0) {
        *valid = false;
    } else {
        free(response);
        return false;
    }
    
    free(response);
    return true;
}

static void versionCheckFunction(void *param) {
    PlatformConfig *cfg = platform_openConfig(BINNAME, "expiry");
    bool valid;
    
    if (checkValidity(&valid)) {
        if (valid) {
            platform_setConfigInteger(cfg, "expiry", "best-before",
                                      time(NULL) - EXPIRY_RAND + 30*24*3600);
        }
        platform_setConfigBool(cfg, "expiry", "still-valid", valid);
        platform_saveConfig(cfg);
    }
    
    platform_freeConfig(cfg);
}

void bankid_checkVersionValidity() {
    PlatformConfig *cfg = platform_openConfig(BINNAME, "expiry");
    
    long lexpiry;
    time_t expiry;
    if (platform_getConfigInteger(cfg, "expiry", "best-before", &lexpiry)) {
        expiry = lexpiry;
    } else {
        expiry = 0;
    }
    
    platform_freeConfig(cfg);
    
    // Check the expiry
    time_t now = time(NULL);
    if (now >= expiry) {
        // Expired
        bool maybeValid;
        if (!platform_getConfigBool(cfg, "expiry", "still-valid", &maybeValid) || maybeValid) {
            versionCheckFunction(NULL);
        }
    } else if (now >= expiry - 14*24*3600) {
        // Expires in 14 days
        platform_asyncCall(versionCheckFunction, NULL);
    }
}

/* Version objects */
char *bankid_getVersion() {
    return getVersionString();
}

/* Authentication and signing objects */
static const char *sign_template =
    "<bankIdSignedData xmlns=\"http://www.bankid.com/signature/v1.0.0/types\" Id=\"bidSignedData\">"
        "%s"
        "<srvInfo>"
            "<nonce>%s</nonce>"
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

static const char *signedText_template =
    "<usrVisibleData charset=\"UTF-8\" visible=\"wysiwys\">"
        "%s"
    "</usrVisibleData>";

static const char *signobj_id = "bidSignedData";


static BankIDError sign(const char *p12Data, const int p12Length,
                        const char *person, const char *password,
                        const char *challenge,
                        const char *hostname, const char *ip,
                        const unsigned int certMask, const char *purpose, const char *extra,
                        char **signature) {
    
    // Create the authentication XML
    char *versionStr = bankid_getVersion();
    char *version = base64_encode(versionStr, strlen(versionStr));
    free(versionStr);
    
    char *object = malloc(strlen(sign_template) - 6*2 +
                          strlen(extra) +
                          strlen(challenge) +
                          strlen(purpose) +
                          strlen(hostname) + strlen(ip) +
                          strlen(version) +1);
    sprintf(object, sign_template, extra, challenge, purpose, hostname, ip, version);
    free(version);
    
    // Sign
    char *xmlsig = xmldsec_sign(p12Data, p12Length,
                person, certMask, password,
                signobj_id, object);
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

BankIDError bankid_authenticate(const char *p12Data, const int p12Length,
                                const char *person, const char *password,
                                const char *challenge,
                                const char *hostname, const char *ip,
                                char **signature) {
    return sign(p12Data, p12Length, person, password, challenge,
                hostname, ip, CERTUSE_AUTHENTICATION, "Identification", "", signature);
}

BankIDError bankid_sign(const char *p12Data, const int p12Length,
                        const char *person, const char *password,
                        const char *challenge,
                        const char *hostname, const char *ip,
                        const char *message,
                        char **signature) {
    BankIDError error;
    
    char *extra = malloc(strlen(signedText_template) - 1*2 +
                         strlen(message) + 1);
    sprintf(extra, signedText_template, message);
    
    error = sign(p12Data, p12Length, person, password, challenge,
                 hostname, ip, CERTUSE_SIGNING, "Signing", extra, signature);
    
    free(extra);
    return error;
}

