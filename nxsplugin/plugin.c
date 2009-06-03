#include <stdlib.h>

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
            if (plugin->info.auth.challenge) free(plugin->info.auth.challenge);
            if (plugin->info.auth.policys) free(plugin->info.auth.policys);
            break;
    }
    free(plugin);
}

