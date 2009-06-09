#define _BSD_SOURCE 1
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <base64.h>

#include "keyfile.h"
#include "xmldecisec.h"
#include "platform.h"
#include "bankid.h"

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

/* Authentication objects */
static const char *authobj_template =
    "<bankIdSignedData xmlns=\"http://www.bankid.com/signature/v1.0.0/types\" Id=\"bidSignedData\">"
        "<srvInfo>"
            "<nonce>%s</nonce>"
        "</srvInfo>"
        "<clientInfo>"
            "<funcId>Identification</funcId>"
            "<host>"
                "<fqdn>%s</fqdn>"
                "<ip>%s</ip>"
            "</host>"
            "<version>%s</version>"
        "</clientInfo>"
    "</bankIdSignedData>";

static const char *authobj_id = "bidSignedData";


BankIDError bankid_authenticate(const char *p12Data, const int p12Length,
                                const char *person, const char *password,
                                const char *challenge,
                                const char *hostname, const char *ip,
                                char **signature) {
    
    // Create the authentication XML
    char *versionStr = bankid_getVersion();
    char *version = base64_encode(versionStr, strlen(versionStr));
    free(versionStr);
    
    char *object = malloc(strlen(authobj_template) - 4*2 +
                          strlen(challenge) +
                          strlen(hostname) + strlen(ip) +
                          strlen(version) +1);
    sprintf(object, authobj_template, challenge, hostname, ip, version);
    free(version);
    
    // Sign
    char *xmlsig = xmldsec_sign(p12Data, p12Length,
                person, CERTUSE_AUTHENTICATION, password,
                authobj_id, object);
    free(object);
    
    // Encode with base64
    
    *signature = base64_encode(xmlsig, strlen(xmlsig));
    free(xmlsig);
    
    if (*signature) {
        return BIDERR_OK;
    } else {
        return BIDERR_InternalError;
    }
}


