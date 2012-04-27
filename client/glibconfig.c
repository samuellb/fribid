/*

  Copyright (c) 2009 Samuel Lidén Borell <samuel@kodafritt.se>
 
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "platform.h"
#include "misc.h"

char *platform_getConfigPath(const char *appname) {
    return rasprintf("%s/%s", g_get_user_config_dir(), appname);
}


struct PlatformConfig {
    char *path;
    char *filename;
    GKeyFile *keyfile;
    bool changed;
};

PlatformConfig *platform_openConfig(const char *appname,
                                    const char *configname) {
    PlatformConfig *result = malloc(sizeof(PlatformConfig));
    
    result->path = platform_getConfigPath(appname);
    result->filename = rasprintf("%s/%s", result->path, configname);
    result->keyfile = g_key_file_new();
    result->changed = false;
    
    g_key_file_load_from_file(result->keyfile, result->filename,
                              G_KEY_FILE_KEEP_COMMENTS |
                              G_KEY_FILE_KEEP_TRANSLATIONS, NULL);
    return result;
}

bool platform_saveConfig(PlatformConfig *config) {
    if (!config->changed) return true;
    
    gsize length;
    gchar *data = g_key_file_to_data(config->keyfile, &length, NULL);
    if (!data) return false;
    
    g_mkdir_with_parents(config->path, 0700);
    
    bool result = g_file_set_contents(config->filename, data, length, NULL);
    g_free(data);
    
    return result;
}

void platform_freeConfig(PlatformConfig *config) {
    free(config->filename);
    free(config->path);
    g_key_file_free(config->keyfile);
    free(config);
}

bool platform_getConfigInteger(const PLATFORM_CFGPARAMS, long *value) {
    GError *err = NULL;
    *value = g_key_file_get_integer(config->keyfile,
                                    section, name, &err);
    return (err == NULL);
}

bool platform_getConfigBool(const PLATFORM_CFGPARAMS, bool *value) {
    GError *err = NULL;
    *value = g_key_file_get_boolean(config->keyfile,
                                    section, name, &err);
    return (err == NULL);
}

bool platform_getConfigString(const PLATFORM_CFGPARAMS, char **value) {
    GError *err = NULL;
    *value = g_key_file_get_string(config->keyfile,
                                   section, name, &err);
    return (err == NULL);
}


void platform_setConfigInteger(PLATFORM_CFGPARAMS, long value) {
    config->changed = true;
    g_key_file_set_integer(config->keyfile,
                           section, name, value);
}

void platform_setConfigBool(PLATFORM_CFGPARAMS, bool value) {
    config->changed = true;
    g_key_file_set_boolean(config->keyfile,
                           section, name, value);
}

void platform_setConfigString(PLATFORM_CFGPARAMS, const char *value) {
    config->changed = true;
    g_key_file_set_string(config->keyfile,
                          section, name, value);
}


