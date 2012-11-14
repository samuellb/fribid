/*

  Copyright (c) 2009-2011 Samuel Lidén Borell <samuel@kodafritt.se>
 
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

#ifndef __DEFINES_H__
#define __DEFINES_H__

#include "config.h"

#if (!defined(CONFIGVERSION) || CONFIGVERSION < 3) && !defined(CALLED_FROM_CONFIGURE)
#error config.h is outdated or non-existent. Please run ./configure
#endif

#define PACKAGENAME         "FriBID"
#define PACKAGEVERSION      "1.0.2"
#define PACKAGEURL          "https://www.fribid.se/"

#define BINNAME             "fribid"
#define RELEASE_TIME        1352912534
#define IPCVERSION          "10"

#define EMULATED_VERSION    "4.15.0.14"
#define DNSVERSION          "2"
#define STATUSDOMAIN        ".status.fribid.se"

#define LIB_PATH            LIBDIR "/" BINNAME
#define LIBEXEC_PATH        LIBEXECDIR "/" BINNAME
#define SHARE_PATH          DATADIR "/" BINNAME
#define DOC_PATH            DATADIR "/doc/" BINNAME

#define SIGNING_EXECUTABLE  LIBEXEC_PATH "/sign"
#define UI_PATH             SHARE_PATH "/ui"
#define UI_GTK_XML          UI_PATH "/sign.xml"
#define NPAPI_PLUGIN_LIB    LIB_PATH "/libfribidplugin.so"

#endif

