#ifndef __PLUGIN_H__
#define __PLUGIN_H__

typedef enum {
    PT_VersionQuerier,
} PluginType;

typedef enum {
    PE_OK = 0,
    PE_UnknownError = 1, // Maybe this is used for something else in the original plugin?
} PluginError;

typedef struct {
    PluginType type;
    
    PluginError lastError;
} Plugin;

Plugin *plugin_new(PluginType pluginType);
void plugin_free(Plugin *plugin);

/* The functions below are forwarded to the Nexus Personal main program
   via IPC. These functions will be implemented in the plugin in the future
   so the plugin will become independent of Nexus. */
char *plugin_getVersion(Plugin *plugin);
// TODO more functions...

#endif


