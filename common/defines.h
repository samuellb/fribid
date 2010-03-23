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
#define PACKAGEVERSION      "0.1.2"

#define BINNAME             "fribid"
#define RELEASE_TIME        1269387016
#define IPCVERSION          "3"

#define EMULATED_VERSION    "4.10.2.16"
#define DNSVERSION          "1"
#define STATUSDOMAIN        ".status.fribid.se"

#define LIB_PATH            EPREFIX "/lib/" BINNAME
#define SHARE_PATH          PREFIX "/share/" BINNAME
#define DOC_PATH            PREFIX "/share/doc/" BINNAME
#define LOCALEDIR           PREFIX "/share/locale"

#define SIGNING_EXECUTABLE  LIB_PATH "/sign"
#define UI_PATH             SHARE_PATH "/ui"
#define UI_GTK_XML          UI_PATH "/sign.xml"
#define NPAPI_PLUGIN_LIB    LIB_PATH "/libfribidplugin.so"

#endif

