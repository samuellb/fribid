#define _BSD_SOURCE 1
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <npapi.h>
#include <npruntime.h>

#include "npobject.h"

/* Object methods */
static NPObject *objAllocate(NPP npp, NPClass *aClass) {
    return malloc(sizeof(PluginObject));
}

static void objDeallocate(NPObject *npobj) {
    PluginObject *this = (PluginObject*)npobj;
    plugin_free(this->plugin);
    free(this);
}

static bool copyIdentifierName(NPIdentifier ident, char *name, int maxLength) {
    char *heapStr = NPN_UTF8FromIdentifier(ident);
    if (!heapStr) return false;
    int len = strlen(heapStr);
    if (len+1 >= maxLength) return false;
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
        case PT_VersionQuerier:
            return !strcmp(name, "GetVersion");
            break;
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
        case PT_VersionQuerier:
            if (!strcmp(name, "GetVersion") && (argCount == 0)) {
                const char *s = strdup("hejhopp");
                STRINGZ_TO_NPVARIANT(s, *result);
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

/*static bool objConstruct(NPObject *npobj, const NPVariant *args,
                         uint32_t argCount, NPVariant *result) {
    return false;
}*/

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
    //objConstruct,
    NULL,
};


/* Object construction */
static NPObject *npobject_new(NPP instance, PluginType pluginType) {
    PluginObject *obj = (PluginObject*)NPN_CreateObject(instance, &baseClass);
    assert(obj->base._class != NULL);
    obj->plugin = plugin_new(pluginType);
    return (NPObject*)obj;
}

NPObject *npobject_fromMIME(NPP instance, NPMIMEType mimeType) {
    if (!strcmp(mimeType, MIME_VERSION)) {
        return npobject_new(instance, PT_VersionQuerier);
    } else {
        return NULL;
    }
}

