#ifndef __DEFINES_H__
#define __DEFINES_H__

#include "config.h"

#define PACKAGENAME         "FriBID"
#define PACKAGEVERSION      "0.1.0"

#define BINNAME             "fribid"
#define RELEASE_TIME        1245853443

#define EMULATED_VERSION    "4.10.2.16"
#define DNSVERSION          "1"
#define STATUSDOMAIN        ".status.fribid.se"

#define LIB_PATH            EPREFIX "/lib/" BINNAME
#define SHARE_PATH          PREFIX "/share/" BINNAME
#define LOCALEDIR           PREFIX "/share/locale"

#define SIGNING_EXECUTABLE  LIB_PATH "/sign"
#define UI_PATH             SHARE_PATH "/ui"
#define UI_GTK_XML          UI_PATH "/sign.xml"
#define NPAPI_PLUGIN_LIB    LIB_PATH "/libplugins.so"

#endif

