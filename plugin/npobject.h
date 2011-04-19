/*

  Copyright (c) 2009-2011 Samuel Lidén Borell <samuel@slbdata.se>
 
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

#ifndef __NPOBJECT_H__
#define __NPOBJECT_H__

#include "plugin.h"

#define MIME_VERSION "application/x-personal-version"
#define MIME_AUTHENTICATION "application/x-personal-authentication"
#define MIME_SIGNER "application/x-personal-signer2"
#define MIME_REGUTIL "application/x-personal-regutil"
#define MIME_WEBADMIN "application/x-personal-webadmin"

typedef struct {
    NPObject base;
    Plugin *plugin;
} PluginObject;

NPObject *npobject_fromMIME(NPP instance, NPMIMEType mimeType);

#endif

