/*

  Copyright (c) 2009-2012 Samuel Lidén Borell <samuel@kodafritt.se>
 
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

#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdint.h>
#include <X11/X.h>
#include "../common/biderror.h"
#include "../common/bidtypes.h"

typedef enum {
    PT_Version,
    PT_Authentication,
    PT_Signer,
    PT_Regutil,
    PT_Webadmin,
    PT_OldSigner,
} PluginType;

typedef struct {
    PluginType type;
    
    char *url;
    char *hostname;
    char *ip;
    Window windowId;
    BankIDError lastError;
    
    union {
        struct {
            /* Input parameters */
            char *challenge;
            int32_t serverTime;
            char *policys;
            char *subjectFilter;
            bool onlyAcceptMRU;
            void *dummy0, *dummy1; // To be compatible with .sign below
            /* Output parameters */
            char *signature;
        } auth;
        struct {
            /* Input parameters */
            char *challenge;
            int32_t serverTime;
            char *policys;
            char *subjectFilter;
            bool onlyAcceptMRU;
            char *messageEncoding;
            char *message;
            char *invisibleMessage;
            /* Output parameters */
            char *signature;
        } sign;
        struct {
            RegutilCMC currentCMC;
            RegutilPKCS10 currentPKCS10;
            
            /* Input parameters */
            RegutilInfo input;
        } regutil;
    } info;
} Plugin;

/* Plugin creation */
Plugin *plugin_new(PluginType pluginType, const char *url,
                   const char *hostname, const char *ip,
                   Window windowId);
void plugin_free(Plugin *plugin);
void plugin_reset(Plugin *plugin);

/* Javascript API */
char *version_getVersion(Plugin *plugin);

char *sign_getParam(Plugin *plugin, const char *name);
bool sign_setParam(Plugin *plugin, const char *name, const char *value);
int sign_performAction(Plugin *plugin, const char *action);
int sign_performAction_Authenticate(Plugin *plugin);
int sign_performAction_Sign(Plugin *plugin);
// TODO more functions...

void regutil_setParam(Plugin *plugin, const char *name, const char *value);
void regutil_initRequest(Plugin *plugin, const char *type);
char *regutil_createRequest(Plugin *plugin);
void regutil_storeCertificates(Plugin *plugin, const char *certs);


#endif


