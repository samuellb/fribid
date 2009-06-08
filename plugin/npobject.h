#ifndef __NPOBJECT_H__
#define __NPOBJECT_H__

#include "plugin.h"

#define MIME_VERSION "application/x-personal-version"
#define MIME_AUTHENTICATION "application/x-personal-authentication"

typedef struct {
    NPObject base;
    Plugin *plugin;
} PluginObject;

NPObject *npobject_fromMIME(NPP instance, NPMIMEType mimeType);

#endif

