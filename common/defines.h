#ifndef __DEFINES_H__
#define __DEFINES_H__

#define PREFIX   "/usr/local"
#define EPREFIX  PREFIX

#define BINNAME  "bankid-se"

#define SIGNING_EXECUTABLE  EPREFIX "/lib/" BINNAME "/sign"
#define UI_PATH             PREFIX "/share/" BINNAME "/ui"
#define UI_GTK_XML          UI_PATH "/sign.xml"

#endif

