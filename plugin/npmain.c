#define _BSD_SOURCE 1
#include <stdlib.h>
#include <string.h>

#include <npapi.h>
#include <npruntime.h>
#include <npupp.h>

#include "plugin.h"
#include "npobject.h"

NPError NPP_New(NPMIMEType pluginType, NPP instance, uint16 mode,
                int16 argc, char *argn[], char *argv[], NPSavedData *data) {
    instance->pdata = npobject_fromMIME(instance, pluginType);
    
    if (instance->pdata) {
        return NPERR_NO_ERROR;
    } else {
        return NPERR_INVALID_PARAM;
    }
}

NPError NPP_Destroy(NPP instance, NPSavedData **save) {
    NPN_ReleaseObject((NPObject*)instance->pdata);
    return NPERR_NO_ERROR;
}

NPError NPP_GetValue(NPP instance, NPPVariable variable, void *value) {
    switch (variable) {
        case NPPVpluginNameString:
            *((char**)value) = strdup("BankID e-legitimation");
            return NPERR_NO_ERROR;
        case NPPVpluginDescriptionString:
            *((char**)value) = strdup("Insticksmodul för BankID e-legitimation");
            return NPERR_NO_ERROR;
        case NPPVpluginScriptableNPObject:
            *((NPObject**)value) = (NPObject*)instance->pdata;
            NPN_RetainObject((NPObject*)instance->pdata);
            return NPERR_NO_ERROR;
        case NPPVpluginWindowBool:
        case NPPVpluginTransparentBool:
            *(bool*)value = false;
            return NPERR_NO_ERROR;
        default:
            return NPERR_INVALID_PARAM;
    }
}

char *NPP_GetMIMEDescription() {
    return MIME_VERSION "::Version;"
           MIME_AUTHENTICATION "::Authentication;"
           MIME_SIGNER "::Signer2";
}

NPError NPP_Initialize() {
    return NPERR_NO_ERROR;
}

void NPP_Shutdown() {
}






