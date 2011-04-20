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
#include <glib.h> // for g_ascii_strcasecmp

#include "plugin.h"


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

static void freePKCS10s(RegutilPKCS10 *pkcs10, bool freeSelf) {
    while (pkcs10) {
        RegutilPKCS10 *next = pkcs10->next;
        free(pkcs10->subjectDN);
        if (freeSelf) free(pkcs10);
        pkcs10 = next;
    }
}

static void freeCMCs(RegutilCMC *cmc, bool freeSelf) {
    while (cmc) {
        RegutilCMC *next = cmc->next;
        free(cmc->oneTimePassword);
        free(cmc->rfc2729cmcoid);
        if (freeSelf) free(cmc);
        cmc = next;
    }
}


void plugin_free(Plugin *plugin) {
    switch (plugin->type) {
        case PT_Version:
        case PT_Webadmin:
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
            freePKCS10s(&plugin->info.regutil.currentPKCS10, false);
            freePKCS10s(plugin->info.regutil.input.pkcs10, true);
            freeCMCs(&plugin->info.regutil.currentCMC, false);
            freeCMCs(&plugin->info.regutil.input.cmc, false);
            break;
    }
    free(plugin->url);
    free(plugin->hostname);
    free(plugin->ip);
    free(plugin);
}

static char **getCommonParamPointer(Plugin *plugin, const char *name) {
    if (!g_ascii_strcasecmp(name, "Policys")) return &plugin->info.auth.policys;
    if (!g_ascii_strcasecmp(name, "Signature")) return &plugin->info.auth.signature;
    if (!g_ascii_strcasecmp(name, "Subjects")) return &plugin->info.sign.subjectFilter;
    return NULL;
}

static char **getParamPointer(Plugin *plugin, const char *name) {
    switch (plugin->type) {
        case PT_Authentication:
            if (!g_ascii_strcasecmp(name, "Challenge")) return &plugin->info.auth.challenge;
            return getCommonParamPointer(plugin, name);
        case PT_Signer:
            if (!g_ascii_strcasecmp(name, "Nonce")) return &plugin->info.sign.challenge;
            if (!g_ascii_strcasecmp(name, "TextToBeSigned")) return &plugin->info.sign.message;
            if (!g_ascii_strcasecmp(name, "NonVisibleData")) return &plugin->info.sign.invisibleMessage;
            return getCommonParamPointer(plugin, name);
        case PT_Regutil:
            if (!g_ascii_strcasecmp(name, "SubjectDN")) return &plugin->info.regutil.currentPKCS10.subjectDN;
            if (!g_ascii_strcasecmp(name, "OneTimePassword")) return &plugin->info.regutil.currentCMC.oneTimePassword;
            return NULL;
        default:
            return NULL;
    }
}

static int *getIntParamPointer(Plugin *plugin, const char *name) {
    switch (plugin->type) {
        case PT_Regutil:
            if (!g_ascii_strcasecmp(name, "KeySize")) return &plugin->info.regutil.currentPKCS10.keySize;
            if (!g_ascii_strcasecmp(name, "MinLen")) return &plugin->info.regutil.input.minPasswordLength;
            if (!g_ascii_strcasecmp(name, "MinChars")) return &plugin->info.regutil.input.minPasswordNonDigits;
            if (!g_ascii_strcasecmp(name, "MinDigits")) return &plugin->info.regutil.input.minPasswordDigits;
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
    if (authOrSign && !g_ascii_strcasecmp(name, "ServerTime")) {
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
    if (authOrSign && !g_ascii_strcasecmp(name, "ServerTime")) {
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
    
    if ((plugin->type == PT_Authentication) && !g_ascii_strcasecmp(action, "Authenticate")) {
        ret = (hasSignParams(plugin) ?
            sign_performAction_Authenticate(plugin) : BIDERR_MissingParameter);
        
    } else if ((plugin->type == PT_Signer) && !g_ascii_strcasecmp(action, "Sign")) {
        if (!hasSignParams(plugin) || !plugin->info.sign.message) {
            return BIDERR_MissingParameter;
        }
        ret = (hasSignParams(plugin) && plugin->info.sign.message ?
            sign_performAction_Sign(plugin) : BIDERR_MissingParameter);
    }
    
    plugin->lastError = ret;
    return ret;
}

void regutil_setParam(Plugin *plugin, const char *name, const char *value) {
    char **strPtr;
    int *intPtr;
    
    // Special parameters
    if (!g_ascii_strcasecmp(name, "KeyUsage")) {
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
        
        if (!g_ascii_strcasecmp(name, "SubjectDN")) {
            plugin->info.regutil.currentPKCS10.includeFullDN = true;
        }
        
    } else {
        // Invalid parameter name
        plugin->lastError = RUERR_InvalidParameter;
    }
}

static char *safestrdup(const char *s) {
    return (s ? strdup(s) : NULL);
}

/**
 * Stores the current parameters so they get included with the request.
 */
void regutil_initRequest(Plugin *plugin, const char *type) {
    if (!g_ascii_strcasecmp(type, "pkcs10")) {
        // Limit number of objects
        RegutilPKCS10 *other = plugin->info.regutil.input.pkcs10;
        size_t count = 0;
        for (; other; other = other->next) {
            if (++count > 10) {
                plugin->lastError = BIDERR_InternalError;
                return;
            }
        }
        
        // Add PKCS10
        RegutilPKCS10 *copy = malloc(sizeof(RegutilPKCS10));
        memcpy(copy, &plugin->info.regutil.currentPKCS10, sizeof(RegutilPKCS10));
        copy->subjectDN = safestrdup(plugin->info.regutil.currentPKCS10.subjectDN);
        
        copy->next = plugin->info.regutil.input.pkcs10;
        plugin->info.regutil.input.pkcs10 = copy;
        
        plugin->info.regutil.currentPKCS10.includeFullDN = false;
        plugin->lastError = BIDERR_OK;
    } else if (!g_ascii_strcasecmp(type, "cmc")) {
        // CMC
        RegutilCMC *cmc = &plugin->info.regutil.input.cmc;
        
        free(cmc->oneTimePassword);
        free(cmc->rfc2729cmcoid);
        cmc->oneTimePassword = safestrdup(plugin->info.regutil.currentCMC.oneTimePassword);
        cmc->rfc2729cmcoid = safestrdup(plugin->info.regutil.currentCMC.rfc2729cmcoid);
        
        plugin->lastError = BIDERR_OK;
    } else {
        plugin->lastError = RUERR_InvalidValue;
    }
}

