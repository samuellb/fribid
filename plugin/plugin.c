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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "../common/biderror.h"

#include "plugin.h"

#define MAX_WINDOWS 20  // safety limit to avoid "popup storms"
static const char *activeURLs[MAX_WINDOWS];

Plugin *plugin_new(PluginType pluginType, const char *url,
                   const char *hostname, const char *ip,
                   Window windowId) {
    Plugin *plugin = calloc(1, sizeof(Plugin));

    if (!plugin) return NULL;
    plugin->type = pluginType;
    plugin->url = strdup(url);
    plugin->hostname = strdup(hostname);
    plugin->ip = strdup(ip);
    plugin->windowId = windowId;
    
    if (!plugin->url || !plugin->hostname || !plugin->ip) {
        plugin_free(plugin);
        return NULL;
    }
    
    return plugin;
}

void plugin_free(Plugin *plugin) {
    switch (plugin->type) {
        case PT_Version:
            break;
        case PT_Authentication:
            free(plugin->info.auth.challenge);
            free(plugin->info.auth.policys);
            free(plugin->info.sign.subjectFilter);
            free(plugin->info.auth.signature);
            break;
        case PT_Signer:
            free(plugin->info.sign.challenge);
            free(plugin->info.sign.policys);
            free(plugin->info.sign.subjectFilter);
            free(plugin->info.sign.message);
            free(plugin->info.sign.invisibleMessage);
            free(plugin->info.sign.signature);
            break;
    }
    free(plugin->url);
    free(plugin->hostname);
    free(plugin->ip);
    free(plugin);
}

static bool findURLSlot(const char *url, int *index) {
    for (int i = 0; i < MAX_WINDOWS; i++) {
        const char *other = activeURLs[i];
        if ((other == url) || (other && url && !strcmp(other, url))) {
            if (index) *index = i;
            return true;
        }
    }
    return false;
}

static bool lockURL(const char *url) {
    int index;
    
    // The URL has a window already
    if (findURLSlot(url, NULL)) return false;
    
    // Reached MAX_WINDOWS
    if (!findURLSlot(NULL, &index)) return false;
    
    activeURLs[index] = url;
    return true;
}

static void unlockURL(const char *url) {
    int index;
    bool ok = findURLSlot(url, &index);
    assert(ok);
    activeURLs[index] = NULL;
}

static char **getCommonParamPointer(Plugin *plugin, const char *name) {
    if (!strcmp(name, "Policys")) return &plugin->info.auth.policys;
    if (!strcmp(name, "Signature")) return &plugin->info.auth.signature;
    if (!strcmp(name, "Subjects")) return &plugin->info.sign.subjectFilter;
    return NULL;
}

static char **getParamPointer(Plugin *plugin, const char *name) {
    switch (plugin->type) {
        case PT_Authentication:
            if (!strcmp(name, "Challenge")) return &plugin->info.auth.challenge;
            return getCommonParamPointer(plugin, name);
        case PT_Signer:
            if (!strcmp(name, "Nonce")) return &plugin->info.sign.challenge;
            if (!strcmp(name, "TextToBeSigned")) return &plugin->info.sign.message;
            if (!strcmp(name, "NonVisibleData")) return &plugin->info.sign.invisibleMessage;
            return getCommonParamPointer(plugin, name);
        default:
            return NULL;
    }
}

char *sign_getParam(Plugin *plugin, const char *name) {
    char **valuePtr = getParamPointer(plugin, name);
    
    if (valuePtr && *valuePtr) return strdup(*valuePtr);
    else return NULL;
}

bool sign_setParam(Plugin *plugin, const char *name, const char *value) {
    char **valuePtr = getParamPointer(plugin, name);
    
    if (valuePtr == NULL) return false;
    
    free(*valuePtr);
    *valuePtr = strdup(value);
    return (*valuePtr != NULL);
}

static bool hasSignParams(const Plugin *plugin) {
    return (plugin->info.auth.challenge);
}

int sign_performAction(Plugin *plugin, const char *action) {
    plugin->lastError = PE_UnknownError;
    if ((plugin->type == PT_Authentication) && !strcmp(action, "Authenticate")) {
        if (!hasSignParams(plugin)) {
            return BIDERR_MissingParameter;
        } else {
            if (!lockURL(plugin->url)) return BIDERR_InternalError;
            int ret = sign_performAction_Authenticate(plugin);
            unlockURL(plugin->url);
            return ret;
        }
    } else if ((plugin->type == PT_Signer) && !strcmp(action, "Sign")) {
        if (!hasSignParams(plugin) || !plugin->info.sign.message) {
            return BIDERR_MissingParameter;
        } else {
            if (!lockURL(plugin->url)) return BIDERR_InternalError;
            int ret = sign_performAction_Sign(plugin);
            unlockURL(plugin->url);
            return ret;
        }
    } else {
        return BIDERR_InvalidAction;
    }
}

int sign_getLastError(Plugin *plugin) {
    return plugin->lastError;
}


