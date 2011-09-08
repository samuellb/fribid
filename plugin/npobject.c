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
#define _POSIX_C_SOURCE 200112
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

#include <npapi.h>
#include <npruntime.h>

#include "pluginutil.h"
#include "npobject.h"

// Prevent concurrent/recursive calls (and multiple windows appearing)
static bool pluginActive = false;

/* Object methods */
static NPObject *objAllocate(NPP npp, NPClass *aClass) {
    return malloc(sizeof(PluginObject));
}

static void objDeallocate(NPObject *npobj) {
    PluginObject *this = (PluginObject*)npobj;
    plugin_free(this->plugin);
    free(this);
}


static bool objHasMethod(NPObject *npobj, NPIdentifier ident) {
    PluginObject *this = (PluginObject*)npobj;
    char name[64];
    if (!copyIdentifierName(ident, name, sizeof(name)))
        return false;
    
    switch (this->plugin->type) {
        case PT_Version:
            return !strcmp(name, "GetVersion");
        case PT_Authentication:
        case PT_Signer:
            return !strcmp(name, "GetParam") || !strcmp(name, "SetParam") ||
                   !strcmp(name, "Reset") ||
                   !strcmp(name, "PerformAction") || !strcmp(name, "GetLastError");
        case PT_Regutil:
            return !strcmp(name, "GetParam") || !strcmp(name, "SetParam") ||
                   !strcmp(name, "InitRequest") || !strcmp(name, "CreateRequest") ||
                   !strcmp(name, "StoreCertificates") || !strcmp(name, "GetLastError");
        case PT_Webadmin:
            return !strcmp(name, "PerformAction") || !strcmp(name, "GetLastError");
        default:
            return false;
    }
}


static bool objInvokeSafe(PluginObject *this, const char *name,
                          const NPVariant *args, uint32_t argCount,
                          NPVariant *result) {
    switch (this->plugin->type) {
        case PT_Version:
            if (IS_CALL_0("GetVersion")) {
                char *version = version_getVersion(this->plugin);
                return convertStringZToVariant(version, result);
            }
            return false;
        case PT_Authentication:
        case PT_Signer:
            if (IS_CALL_1("GetParam", STRING)) {
                // Get parameter
                char *param = variantToStringZ(&args[0]);
                if (!param) return false;
                
                char *value = sign_getParam(this->plugin, param);
                
                free(param);
                return convertStringZToVariant(value, result);
            } else if (IS_CALL_2("SetParam", STRING, STRING)) {
                // Set parameter
                char *param = variantToStringZ(&args[0]);
                char *value = variantToStringZ(&args[1]);
                bool ok = (param && value);
                
                if (ok) {
                    sign_setParam(this->plugin, param, value);
                    INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                }
                
                free(param);
                free(value);
                
                return ok;
            } else if (IS_CALL_0("Reset")) {
                // Clear all parameters
                plugin_reset(this->plugin);
                
                this->plugin->lastError = BIDERR_OK;
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                
                return true;
            } else if (IS_CALL_1("PerformAction", STRING)) {
                // Perform action
                char *action = variantToStringZ(&args[0]);
                if (!action) return false;
                
                int ret = sign_performAction(this->plugin, action);
                
                free(action);
                INT32_TO_NPVARIANT((int32_t)ret, *result);
                return true;
            } else if (IS_CALL_0("GetLastError")) {
                // Get last error
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                return true;
            }
            return false;
        case PT_Regutil:
            if (IS_CALL_1("GetParam", STRING)) {
                // Get parameter. Seems to always return null
                this->plugin->lastError = RUERR_InvalidParameter;
                NULL_TO_NPVARIANT(*result);
                return true;
            } else if (IS_CALL_2("SetParam", STRING, STRING)) {
                // Set parameter
                char *param = variantToStringZ(&args[0]);
                char *value = variantToStringZ(&args[1]);
                bool ok = (param && value);
                
                if (ok) {
                    regutil_setParam(this->plugin, param, value);
                    INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                }
                
                free(param);
                free(value);
                
                return ok;
            } else if (IS_CALL_1("InitRequest", STRING)) {
                // Init request
                char *type = variantToStringZ(&args[0]);
                if (!type) return false;
                
                regutil_initRequest(this->plugin, type);
                
                free(type);
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                return true;
            } else if (IS_CALL_0("CreateRequest")) {
                // Create request
                char *value = regutil_createRequest(this->plugin);
                return convertStringZToVariant(value, result);
            } else if (IS_CALL_2("StoreCertificates", STRING, STRING)) {
                // Store a certificate chain
                // TODO check string lengths
                
                const NPString *type_nps = &NPVARIANT_TO_STRING(args[0]);
                bool type_is_p7c = (type_nps->utf8length == 3 &&
                                    !strncmp(type_nps->utf8characters, "p7c", 3));
                char *certs = variantToStringZ(&args[1]);
                
                // TODO set the error code instead of just failing and throwing a script exception
                bool ok = (type_is_p7c && certs);
                
                if (ok) {
                    regutil_storeCertificates(this->plugin, certs);
                }
                
                free(certs);
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                return ok;
            } else if (IS_CALL_0("GetLastError")) {
                // Get last error
                // TODO fix code duplication!
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                return true;
            }
            return false;
        case PT_Webadmin:
            if (IS_CALL_1("PerformAction", STRING)) {
                // Perform action
                
                // RenewPollDates isn't implemented, but is probably not
                // needed either. The purpose of that call is to download
                // version/expiry information through the browser, in case
                // such requests must be proxied
                this->plugin->lastError = BIDERR_InvalidAction;
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                return true;
            } else if (IS_CALL_0("GetLastError")) {
                // Get last error
                INT32_TO_NPVARIANT((int32_t)this->plugin->lastError, *result);
                return true;
            }
            return false;
        case PT_OldSigner:
            // Not implemented
            return false;
        default:
            return false;
    }
}


static bool objInvoke(NPObject *npobj, NPIdentifier ident,
                      const NPVariant *args, uint32_t argCount,
                      NPVariant *result) {
    PluginObject *this = (PluginObject*)npobj;
    char name[64];
    if (!copyIdentifierName(ident, name, sizeof(name)))
        return false;
    
    // Check argument lengths
    for (uint32_t i = 0; i < argCount; i++) {
        if (NPVARIANT_IS_STRING(args[i]) &&
            NPVARIANT_TO_STRING(args[i]).utf8length > 10*1024*1024) {
            // String is larger than 10 MiB
            return false;
        }
    }
    
    // Prevent recursive calls
    // TODO filter events in the main loop so the browser do anything
    //      except redraw it's window while a call is in progress.
    if (pluginActive) return false;
    pluginActive = true;
    
    bool ok = objInvokeSafe(this, name, args, argCount, result);
    
    pluginActive = false;
    return ok;
}

static bool objInvokeDefault(NPObject *npobj, const NPVariant *args,
                             uint32_t argCount, NPVariant *result) {
    return false;
}

static bool objHasProperty(NPObject *npobj, NPIdentifier name) {
    return false;
}

static bool objGetProperty(NPObject *npobj, NPIdentifier name,
                               NPVariant *result) {
    return false;
}

static bool objSetProperty(NPObject *npobj, NPIdentifier name,
                           const NPVariant *value) {
    return false;
}

static bool objRemoveProperty(NPObject *npobj, NPIdentifier name) {
    return false;
}

static bool objEnumerate(NPObject *npobj, NPIdentifier **value,
                         uint32_t *count) {
    return false;
}

static NPClass baseClass = {
    NP_CLASS_STRUCT_VERSION,
    objAllocate,
    objDeallocate,
    NULL,
    objHasMethod,
    objInvoke,
    objInvokeDefault,
    objHasProperty,
    objGetProperty,
    objSetProperty,
    objRemoveProperty,
    objEnumerate,
    NULL,
};


/* Object construction */
static NPObject *npobject_new(NPP instance, PluginType pluginType) {
    PluginObject *obj;

    obj = (PluginObject*)NPN_CreateObject(instance, &baseClass);
    if (!obj) return NULL;
    assert(obj->base._class != NULL);
    
    char *url = getDocumentURL(instance);
    char *hostname = getDocumentHostname(instance);
    char *ip = getDocumentIP(instance);

    obj->plugin = plugin_new(pluginType,
                             (url != NULL ? url : ""),
                             (hostname != NULL ? hostname : ""),
                             (ip != NULL ? ip : ""),
                             getWindowId(instance));
    free(ip);
    free(hostname);
    free(url);
    
    if (!obj->plugin) {
        NPN_ReleaseObject((NPObject*)obj);
        return NULL;
    }
    
    return (NPObject*)obj;
}

NPObject *npobject_fromMIME(NPP instance, NPMIMEType mimeType) {
    if (!strcmp(mimeType, MIME_VERSION)) {
        return npobject_new(instance, PT_Version);
    } else if (!strcmp(mimeType, MIME_AUTHENTICATION)) {
        return npobject_new(instance, PT_Authentication);
    } else if (!strcmp(mimeType, MIME_SIGNER)) {
        return npobject_new(instance, PT_Signer);
    } else if (!strcmp(mimeType, MIME_REGUTIL)) {
        return npobject_new(instance, PT_Regutil);
    } else if (!strcmp(mimeType, MIME_WEBADMIN)) {
        return npobject_new(instance, PT_Webadmin);
    } else if (!strcmp(mimeType, MIME_OLDSIGNER)) {
        return npobject_new(instance, PT_OldSigner);
    } else {
        return NULL;
    }
}

