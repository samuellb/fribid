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






