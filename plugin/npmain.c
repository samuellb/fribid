/*

  Copyright (c) 2009-2011 Samuel Lidén Borell <samuel@slbdata.se>
 
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

#include "../common/defines.h"
#include "plugin.h"
#include "npobject.h"

// Change to "/" to make this plugin work with Opera
#define NO_FILE_EXTENSIONS ""

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
            *((const char**)value) = "Nexus Personal";
            return NPERR_NO_ERROR;
        case NPPVpluginDescriptionString:
            *((const char**)value) = "<a href=\"" PACKAGEURL "\">" PACKAGENAME
                                     "</a> version " PACKAGEVERSION;
            return NPERR_NO_ERROR;
        case NPPVpluginScriptableNPObject:
            *((NPObject**)value) = (NPObject*)instance->pdata;
            NPN_RetainObject((NPObject*)instance->pdata);
            return NPERR_NO_ERROR;
        case NPPVpluginWindowBool:
        case NPPVpluginTransparentBool:
            *(bool*)value = false;
            return NPERR_NO_ERROR;
        case NPPVpluginNeedsXEmbed:
            *(bool*)value = true;
            return NPERR_NO_ERROR;
        default:
            return NPERR_INVALID_PARAM;
    }
}

char *NPP_GetMIMEDescription() {
    return MIME_VERSION ":" NO_FILE_EXTENSIONS ":Version;"
           MIME_AUTHENTICATION ":" NO_FILE_EXTENSIONS ":Authentication;"
           MIME_SIGNER ":" NO_FILE_EXTENSIONS ":Signer2;"
           MIME_REGUTIL ":" NO_FILE_EXTENSIONS ":Regutil;"
           MIME_WEBADMIN ":" NO_FILE_EXTENSIONS ":Webadmin;"
           MIME_OLDSIGNER ":" NO_FILE_EXTENSIONS ":Signer";
}

const char *NPP_GetPluginVersion() {
    return PACKAGEVERSION;
}

NPError NPP_Initialize() {
    return NPERR_NO_ERROR;
}

void NPP_Shutdown() {
}






