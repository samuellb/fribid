#ifndef __PLUGIN_H__
#define __PLUGIN_H__

typedef enum {
    PT_Version,
    PT_Authentication,
    PT_Signer,
} PluginType;

typedef enum {
    PE_OK = 0,
    PE_UnknownError = 1, // Maybe this is used for something else in the original plugin?
} PluginError;

typedef struct {
    PluginType type;
    
    char *url;
    char *hostname;
    char *ip;
    PluginError lastError;
    
    union {
        struct {
            /* Input parameters */
            char *challenge;
            char *policys;
            void *dummy1; // To be compatible with .sign below
            void *dummy0;
            /* Output parameters */
            char *signature;
        } auth;
        struct {
            /* Input parameters */
            char *challenge;
            char *policys;
            char *subjectFilter;
            char *message;
            /* Output parameters */
            char *signature;
        } sign;
    } info;
} Plugin;

/* Plugin creation */
Plugin *plugin_new(PluginType pluginType, const char *url,
                   const char *hostname, const char *ip);
void plugin_free(Plugin *plugin);

/* Javascript API */
char *version_getVersion(Plugin *plugin);

char *sign_getParam(Plugin *plugin, const char *name);
bool sign_setParam(Plugin *plugin, const char *name, const char *value);
int sign_performAction(Plugin *plugin, const char *action);
int sign_performAction_Authenticate(Plugin *plugin);
int sign_performAction_Sign(Plugin *plugin);
int sign_getLastError(Plugin *plugin);
// TODO more functions...

#endif


