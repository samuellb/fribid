#include <stdlib.h>

#include "plugin.h"

Plugin *plugin_new(PluginType pluginType) {
    Plugin *plugin = calloc(1, sizeof(Plugin));
    plugin->type = pluginType;
    return plugin;
}

void plugin_free(Plugin *plugin) {
    free(plugin);
}

