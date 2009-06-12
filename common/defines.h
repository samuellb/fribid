#ifndef __DEFINES_H__
#define __DEFINES_H__

#include "config.h"

#define BINNAME  "bankid-se"

#define LIB_PATH            EPREFIX "/lib/" BINNAME
#define SHARE_PATH          PREFIX "/share/" BINNAME

#define SIGNING_EXECUTABLE  LIB_PATH "/sign"
#define UI_PATH             SHARE_PATH "/ui"
#define UI_GTK_XML          UI_PATH "/sign.xml"
#define NPAPI_PLUGIN_LIB    LIB_PATH "/libplugins.so"
#define NPAPI_PLUGIN_LINK1   "/usr/lib/mozilla/plugins/libplugins.so"
#define NPAPI_PLUGIN_LINK2   "/usr/lib/xulrunner-addons/plugins/libplugins.so"
#define NPAPI_PLUGIN_REL    NPAPI_PLUGIN_LIB

#endif

