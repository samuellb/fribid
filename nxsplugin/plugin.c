#define _BSD_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "plugin.h"

Plugin *plugin_new(PluginType pluginType) {
    Plugin *plugin = calloc(1, sizeof(Plugin));
    plugin->type = pluginType;
    return plugin;
}

void plugin_free(Plugin *plugin) {
    switch (plugin->type) {
        case PT_Version:
            break;
        case PT_Authentication:
            free(plugin->info.auth.challenge);
            free(plugin->info.auth.policys);
            break;
    }
    free(plugin);
}


static char **getParamPointer(Plugin *plugin, const char *name) {
    if (!strcmp(name, "Challenge")) return &plugin->info.auth.challenge;
    if (!strcmp(name, "Policys")) return &plugin->info.auth.policys;
    if (!strcmp(name, "Signature")) return &plugin->info.auth.signature;
    return NULL;
}

char *auth_getParam(Plugin *plugin, const char *name) {
    char **valuePtr = getParamPointer(plugin, name);
    
    char *value = NULL;
    if (*valuePtr) value = strdup(*valuePtr);
    
    return (value != NULL ? value : strdup(""));
}

bool auth_setParam(Plugin *plugin, const char *name, const char *value) {
    char **valuePtr = getParamPointer(plugin, name);
    
    if (valuePtr == NULL) return false;
    
    free(*valuePtr);
    *valuePtr = strdup(value);
    return true;
}


