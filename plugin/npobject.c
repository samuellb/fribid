/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
 
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <npapi.h>
#include <npruntime.h>

#include "npobject.h"


static char *strndup(const char *source, size_t maxLength) {
    size_t i;
    for (i = 0;; i++) {
        if ((i >= maxLength) || (source[i] == '\0')) break;
    }
    
    char *ret = malloc(i+1);
    if (!ret) return NULL;
    memcpy(ret, source, i);
    ret[i] = '\0';
    return ret;
}

// Re-allocates a string with NPN_MemAlloc instead of malloc
static char *npstr(char *source) {
    size_t size = strlen(source)+1;
    char *dest = NULL;
    if (size <= INT32_MAX && (dest = NPN_MemAlloc(size)) != NULL) {
        memcpy(dest, source, size);
    }
    free(source);
    return dest;
}

static bool getProperty(NPP instance, NPObject *obj, const char *name, NPVariant *result) {
    NPIdentifier ident = NPN_GetStringIdentifier(name);
    if (!ident) return NULL;
    return NPN_GetProperty(instance, obj, ident, result);
}

static char *getWindowProperty(NPP instance, const char *const identifiers[]) {
    NPObject *obj;
    
    NPN_GetValue(instance, NPNVWindowNPObject, &obj);
    if (!obj) return NULL;
    
    const char *const *identifier = &identifiers[0];
    while (1) {
        NPVariant value;
        
        bool ok = getProperty(instance, obj, *identifier, &value);
        NPN_ReleaseObject(obj);
        if (!ok) return NULL;
        
        identifier++;
        if (*identifier) {
            // Expecting an object
            if (!NPVARIANT_IS_OBJECT(value)) {
                NPN_ReleaseVariantValue(&value);
                return NULL;
            }
            obj = NPVARIANT_TO_OBJECT(value);
        } else {
            // Expecting a string
            if (!NPVARIANT_IS_STRING(value)) {
                NPN_ReleaseVariantValue(&value);
                return NULL;
            }
            char *url = strndup(NPVARIANT_TO_STRING(value).utf8characters,
                                NPVARIANT_TO_STRING(value).utf8length);
            NPN_ReleaseVariantValue(&value);
            return url;
        }
    }
}

static char *getDocumentURL(NPP instance) {
    static const char *const identifiers[] = {
        "document", "location", "href", NULL
    };
    return getWindowProperty(instance, identifiers);
}

static char *getDocumentHostname(NPP instance) {
    static const char *const identifiers[] = {
        "document", "location", "hostname", NULL
    };
    return getWindowProperty(instance, identifiers);
}

static char *getDocumentIP(NPP instance) {
    // FIXME This function performs a DNS lookup independently of the
    //       browser. So it's possible that the browser and the plugin
    //       get different addresses. This is a (small) security problem
    //       since the browser might have loaded a maliciuous page while
    //       the plugin authenticates with the real IP.
    char *hostname = getDocumentHostname(instance);
    if (!hostname) return NULL;
    
    struct addrinfo *firstAddrInfo;
    int ret = getaddrinfo(hostname, NULL, NULL, &firstAddrInfo);
    free(hostname);
    if (ret != 0) return NULL;
    
    // Find first INET address
    const struct addrinfo *ai = firstAddrInfo;
    while (ai && (ai->ai_family != AF_INET) && (ai->ai_family != AF_INET6))
        ai = ai->ai_next;
    
    if (!ai) return NULL;
    
    char ip[NI_MAXHOST];
    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ip, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST) != 0) {
        freeaddrinfo(firstAddrInfo);
        return NULL;
    }
    freeaddrinfo(firstAddrInfo);
    
    return strdup(ip);
}

/**
 * Returns the native ID of the browser window, or -1 on error.
 */
static int getWindowId(NPP instance) {
    int id;
    if (NPN_GetValue(instance, NPNVnetscapeWindow, &id) == NPERR_NO_ERROR) {
        return id;
    } else {
        return -1;
    }
}

/* Object methods */
static NPObject *objAllocate(NPP npp, NPClass *aClass) {
    return malloc(sizeof(PluginObject));
}

static void objDeallocate(NPObject *npobj) {
    PluginObject *this = (PluginObject*)npobj;
    plugin_free(this->plugin);
    free(this);
}

static bool copyIdentifierName(NPIdentifier ident, char *name, size_t maxLength) {
    char *heapStr = NPN_UTF8FromIdentifier(ident);
    if (!heapStr) return false;
    size_t len = strlen(heapStr);
    if (len >= maxLength-1) return false;
    memcpy(name, heapStr, len+1);
    NPN_MemFree(heapStr);
    return true;
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
                   !strcmp(name, "PerformAction") || !strcmp(name, "GetLastError");
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
    
    switch (this->plugin->type) {
        case PT_Version:
            if (!strcmp(name, "GetVersion") && (argCount == 0)) {
                char *version = version_getVersion(this->plugin);
                if (!version) return false;
                char *s = npstr(version);
                if (!s) return false;
                STRINGZ_TO_NPVARIANT(s, *result);
                return true;
            }
            return false;
        case PT_Authentication:
        case PT_Signer:
            if (!strcmp(name, "GetParam") && (argCount == 1) &&
                NPVARIANT_IS_STRING(args[0])) {
                // Get parameter
                char *param = strndup(NPVARIANT_TO_STRING(args[0]).utf8characters, NPVARIANT_TO_STRING(args[0]).utf8length);
                if (!param) return false;
                char *value = sign_getParam(this->plugin, param);
                
                free(param);
                if (value) {
                    // The macro below evaluates it's first parameter twice
                    // and npstr frees it's input...
                    value = npstr(value);
                    if (!value) return false;
                    STRINGZ_TO_NPVARIANT(value, *result);
                } else NULL_TO_NPVARIANT(*result);
                
                return true;
            } else if (!strcmp(name, "SetParam") && (argCount == 2) &&
                       NPVARIANT_IS_STRING(args[0]) && NPVARIANT_IS_STRING(args[1])) {
                // Set parameter
                if (NPVARIANT_TO_STRING(args[1]).utf8length >= 10*1024*1024) {
                    // Value is larger than 10 MiB
                    return false;
                }
                
                char *param = strndup(NPVARIANT_TO_STRING(args[0]).utf8characters, NPVARIANT_TO_STRING(args[0]).utf8length);
                char *value = strndup(NPVARIANT_TO_STRING(args[1]).utf8characters, NPVARIANT_TO_STRING(args[1]).utf8length);
                bool ok = (param && value);
                
                if (ok) {
                    sign_setParam(this->plugin, param, value);
                    VOID_TO_NPVARIANT(*result);
                }
                
                free(param);
                free(value);
                return ok;
            } else if (!strcmp(name, "PerformAction") && (argCount == 1) &&
                       NPVARIANT_IS_STRING(args[0])) {
                // Perform action
                char *action = strndup(NPVARIANT_TO_STRING(args[0]).utf8characters, NPVARIANT_TO_STRING(args[0]).utf8length);
                if (!action) return false;
                
                int ret = sign_performAction(this->plugin, action);
                
                free(action);
                INT32_TO_NPVARIANT((int32_t)ret, *result);
                return true;
            } else if (!strcmp(name, "GetLastError") && (argCount == 0)) {
                // Get last error
                int ret = sign_getLastError(this->plugin);
                INT32_TO_NPVARIANT((int32_t)ret, *result);
                return true;
            }
            return false;
        default:
            return false;
    }
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
    PluginObject *obj = (PluginObject*)NPN_CreateObject(instance, &baseClass);
    if (!obj) return NULL;
    assert(obj->base._class != NULL);
    
    char *url = getDocumentURL(instance);
    char *hostname = getDocumentHostname(instance);
    char *ip = getDocumentIP(instance);
    int windowId = getWindowId(instance);
    obj->plugin = plugin_new(pluginType,
                             (url != NULL ? url : ""),
                             (hostname != NULL ? hostname : ""),
                             (ip != NULL ? ip : ""),
                             windowId);
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
    } else {
        return NULL;
    }
}

