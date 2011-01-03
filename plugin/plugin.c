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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
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

static void freePKCS10s(RegutilPKCS10 *pkcs10) {
    while (pkcs10) {
        RegutilPKCS10 *next = pkcs10->next;
        free(pkcs10->subjectDN);
        free(pkcs10);
        pkcs10 = next;
    }
}

static void freeCMCs(RegutilCMC *cmc) {
    while (cmc) {
        RegutilCMC *next = cmc->next;
        free(cmc->oneTimePassword);
        free(cmc->rfc2729cmcoid);
        free(cmc);
        cmc = next;
    }
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
        case PT_Regutil:
            freePKCS10s(&plugin->info.regutil.currentPKCS10);
            freePKCS10s(plugin->info.regutil.input.pkcs10);
            freeCMCs(&plugin->info.regutil.currentCMC);
            freeCMCs(plugin->info.regutil.input.cmc);
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
        case PT_Regutil:
            if (!strcmp(name, "SubjectDN")) return &plugin->info.regutil.currentPKCS10.subjectDN;
            if (!strcmp(name, "OneTimePassword")) return &plugin->info.regutil.currentCMC.oneTimePassword;
            return NULL;
        default:
            return NULL;
    }
}

static int *getIntParamPointer(Plugin *plugin, const char *name) {
    switch (plugin->type) {
        case PT_Regutil:
            if (!strcmp(name, "KeySize")) return &plugin->info.regutil.currentPKCS10.keySize;
            return NULL;
        default:
            return NULL;
    }
}

char *sign_getParam(Plugin *plugin, const char *name) {
    // Handle special parameters
    bool authOrSign = (plugin->type == PT_Authentication ||
                       plugin->type == PT_Signer);
    
    // Server time
    if (authOrSign && !strcmp(name, "ServerTime")) {
        int32_t value = plugin->info.auth.serverTime;
        if (value <= 0) return strdup("");
        
        char *s = malloc(11);
        sprintf(s, "%" PRIu32, value);
        return s;
    }
    
    // Handle string parameters
    char **valuePtr = getParamPointer(plugin, name);
    
    if (valuePtr && *valuePtr) return strdup(*valuePtr);
    else return NULL;
}

bool sign_setParam(Plugin *plugin, const char *name, const char *value) {
    // Handle special parameters
    bool authOrSign = (plugin->type == PT_Authentication ||
                       plugin->type == PT_Signer);
    
    // Server time: This value is a 10-digit integer
    if (authOrSign && !strcmp(name, "ServerTime")) {
        plugin->lastError = BIDERR_OK;
        
        size_t length = strlen(value);
        if (length > 10) {
            plugin->lastError = BIDERR_ValueTooLong;
            plugin->info.auth.serverTime = 0;
            return false;
        }
        
        plugin->info.auth.serverTime = (int32_t)atoi(value);
        
        if (plugin->info.auth.serverTime <= 0) {
            plugin->lastError = BIDERR_InvalidValue;
            plugin->info.auth.serverTime = 0;
            return false;
        }
        
        if (length < 10) {
            // Accept the value but return an error code
            plugin->lastError = BIDERR_InvalidValue;
            return false;
        }
        
        return true;
    }
    
    // Handle string parameters
    char **valuePtr = getParamPointer(plugin, name);
    
    if (valuePtr == NULL) {
        plugin->lastError = BIDERR_InvalidParameter;
        return false;
    }
    
    free(*valuePtr);
    *valuePtr = strdup(value);
    if (*valuePtr != NULL) {
        plugin->lastError = BIDERR_OK;
        return true;
    } else {
        plugin->lastError = BIDERR_InternalError;
        return false;
    }
}

static bool hasSignParams(const Plugin *plugin) {
    return (plugin->info.auth.challenge);
}

int sign_performAction(Plugin *plugin, const char *action) {
    int ret = BIDERR_InvalidAction;
    
    if (!lockURL(plugin->url)) return BIDERR_InternalError;
    
    if ((plugin->type == PT_Authentication) && !strcmp(action, "Authenticate")) {
        ret = (hasSignParams(plugin) ?
            sign_performAction_Authenticate(plugin) : BIDERR_MissingParameter);
        
    } else if ((plugin->type == PT_Signer) && !strcmp(action, "Sign")) {
        if (!hasSignParams(plugin) || !plugin->info.sign.message) {
            return BIDERR_MissingParameter;
        }
        ret = (hasSignParams(plugin) && plugin->info.sign.message ?
            sign_performAction_Sign(plugin) : BIDERR_MissingParameter);
    }
    
    unlockURL(plugin->url);
    plugin->lastError = ret;
    return ret;
}

void regutil_setParam(Plugin *plugin, const char *name, const char *value) {
    char **strPtr;
    int *intPtr;
    
    // Special parameters
    if (!strcmp(name, "KeyUsage")) {
        if (!strcmp(value, "digitalSignature")) {
            plugin->info.regutil.currentPKCS10.keyUsage = KeyUsage_Authentication;
        } else if (!strcmp(value, "nonRepudiation")) {
            plugin->info.regutil.currentPKCS10.keyUsage = KeyUsage_Signing;
        }
        
        plugin->lastError = BIDERR_OK; // Never return failure
    } else if ((intPtr = getIntParamPointer(plugin, name)) != NULL) {
        // Integer parameters
        errno = 0;
        int intval = strtol(value, NULL, 10);
        if (!errno) *intPtr = intval;
        plugin->lastError = (!errno ? BIDERR_OK : RUERR_InvalidValue);
    } else if ((strPtr = getParamPointer(plugin, name)) != NULL) {
        // String parameters
        free(*strPtr);
        *strPtr = strdup(value);
        plugin->lastError = (*strPtr ? BIDERR_OK : BIDERR_InternalError);
    } else {
        // Invalid parameter name
        plugin->lastError = RUERR_InvalidParameter;
    }
}

/**
 * Stores the current parameters so they get included with the request.
 */
void regutil_initRequest(Plugin *plugin, const char *type) {
    if (!strcmp(type, "pkcs10")) {
        // PKCS10
        RegutilPKCS10 *copy = malloc(sizeof(RegutilPKCS10));
        copy->keyUsage = plugin->info.regutil.currentPKCS10.keyUsage;
        copy->keySize = plugin->info.regutil.currentPKCS10.keySize;
        copy->subjectDN = strdup(plugin->info.regutil.currentPKCS10.subjectDN);
        
        copy->next = plugin->info.regutil.input.pkcs10;
        plugin->info.regutil.input.pkcs10 = copy;
        
        plugin->lastError = BIDERR_OK;
    } else if (!strcmp(type, "cmc")) {
        // CMC
        RegutilCMC *copy = malloc(sizeof(RegutilCMC));
        copy->oneTimePassword = strdup(plugin->info.regutil.currentCMC.oneTimePassword);
        copy->rfc2729cmcoid = strdup(plugin->info.regutil.currentCMC.rfc2729cmcoid);
        
        copy->next = plugin->info.regutil.input.cmc;
        plugin->info.regutil.input.cmc = copy;
        
        plugin->lastError = BIDERR_OK;
    } else {
        plugin->lastError = RUERR_InvalidValue;
    }
}

