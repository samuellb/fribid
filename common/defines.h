/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
 
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

#define PACKAGENAME         "FriBID"
#define PACKAGEVERSION      "0.2.2"

#define BINNAME             "fribid"
#define RELEASE_TIME        1292676673
#define IPCVERSION          "5"

#define EMULATED_VERSION    "4.15.0.14"
#define DNSVERSION          "2"
#define STATUSDOMAIN        ".status.fribid.se"

#define LIB_PATH            LIBDIR "/" BINNAME
#define SHARE_PATH          DATADIR "/" BINNAME
#define DOC_PATH            DATADIR "/doc/" BINNAME
#define MANDIR              DATADIR "/man"
#define LOCALEDIR           DATADIR "/locale"

#define SIGNING_EXECUTABLE  LIB_PATH "/sign"
#define UI_PATH             SHARE_PATH "/ui"
#define UI_GTK_XML          UI_PATH "/sign.xml"
#define NPAPI_PLUGIN_LIB    LIB_PATH "/libfribidplugin.so"

#endif

