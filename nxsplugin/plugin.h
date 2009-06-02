#ifndef __PLUGIN_H__
#define __PLUGIN_H__

typedef enum {
    PT_VersionQuerier,
} PluginType;

typedef struct {
    PluginType type;
} Plugin;

Plugin *plugin_new(PluginType pluginType);
void plugin_free(Plugin *plugin);

#endif


