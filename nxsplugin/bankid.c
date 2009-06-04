#define _BSD_SOURCE 1
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <base64.h>

#include "keyfile.h"
#include "xmldecisec.h"
#include "plugin.h"

void bankid_init() {
    keyfile_init();
}

void bankid_shutdown() {
    keyfile_shutdown();
}

/* * * *  Javascript API functions * * * */

/* Version objects */
char *version_getVersion(Plugin *plugin) {
    // TODO
    return strdup("");
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

static bool platform_readFile(const char *filename, char **data, int *length) {
    // TODO move platform specific stuff to it's own file
    FILE *file = fopen(filename, "rb");
    if (!file) return false;
    if (fseek(file, 0, SEEK_END) == -1) {
        fclose(file);
        return false;
    }
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);
    *data = malloc(*length);
    bool ok = (fread(*data, *length, 1, file) == 1);
    fclose(file);
    return ok;
}

int auth_performAction_Authenticate(Plugin *plugin) {
    
    // TODO ask for certificate name and password
    char *password = strdup("");
    char *filename = strdup("/home/username/cbt/(YYMMDD HH.MM) FIRSTNAME LAST LASTNAME - BankID pa fil.p12");
    char *person = strdup("CN=FULL NAME,OID.2.5.4.41=(YYMMDD HH.MM) FIRSTNAME LAST LASTNAME - BankID på fil,serialNumber=PERSONAL NUMBER WITH FOUR DIGIT YEAR,givenName=FIRSTNAME MIDDLENAME,SN=LASTNAMES,O=ISSUING BANK (publ),C=COUNRTY CODE");
    
    // Load the PKCS12 file
    char *p12Data;
    int p12Length;
    if (!platform_readFile(filename, &p12Data, &p12Length)) {
        plugin->lastError = PE_UnknownError;
        return 1;
    }
    
    // Create the authentication XML
    char *versionStr = version_getVersion(plugin);
    char *version = base64_encode(versionStr, strlen(versionStr));
    free(versionStr);
    
    char *object = malloc(strlen(authobj_template) - 4*2 +
                          strlen(plugin->info.auth.challenge) +
                          strlen(plugin->hostname) + strlen(plugin->ip) +
                          strlen(version) +1);
    sprintf(object, authobj_template,
            plugin->info.auth.challenge,
            plugin->hostname, plugin->ip,
            version);
    free(version);
    
    // Sign
    free(plugin->info.auth.signature);
    plugin->info.auth.signature = xmldsec_sign(p12Data, p12Length,
                person, CERTUSE_AUTHENTICATION, password,
                authobj_id, object);
    
    free(object);
    free(password);
    free(filename);
    free(person);
    
    if (plugin->info.auth.signature) {
        plugin->lastError = PE_OK;
        return 0;
    } else {
        plugin->lastError = PE_UnknownError;
        return 1;
    }
}


