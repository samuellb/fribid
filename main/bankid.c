#define _BSD_SOURCE 1
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <base64.h>

#include "keyfile.h"
#include "xmldecisec.h"
#include "bankid.h"
#include "misc.h"

void bankid_init() {
    keyfile_init();
}

void bankid_shutdown() {
    keyfile_shutdown();
}

/* Version objects */
char *bankid_getVersion() {
    static const char *version =
        "Personal=4.10.2.16&libtokenapi_so=4.10.2.16&libBranding_so=4.10.2.16&libCardSetec_so=4.10.2.16&libCardPrisma_so=4.10.2.16&libCardSiemens_so=4.10.2.16&libplugins_so=4.10.2.16&libP11_so=4.10.2.16&libai_so=4.10.2.16&personal_bin=4.10.2.16&"
        "platform=linux&distribution=ubuntu&os_version=8.04&best_before=1244660548&";
    return strdup(version);
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

