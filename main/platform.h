/*

  Copyright (c) 2009 Samuel Lidén Borell <samuel@slbdata.se>
 
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

#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdbool.h>

/* Initialization */
void platform_init(int *argc, char ***argv);

/* Random number generation */
void platform_seedRandom();
void platform_makeRandomString(char *buff, int length);

/* Pipe I/O */
typedef void (PlatformPipeFunction) ();
void platform_setupPipe(PlatformPipeFunction *pipeFunction);

/* File IO */
bool platform_readFile(const char *filename, char **data, int *length);
bool platform_deleteFile(const char *filename);
bool platform_deleteDir(const char *filename);

typedef struct PlatformDirIter PlatformDirIter;
PlatformDirIter *platform_openDir(const char *pathname);
bool platform_iterateDir(PlatformDirIter *iter);
char *platform_currentName(PlatformDirIter *iter);
char *platform_currentPath(PlatformDirIter *iter);
void platform_closeDir(PlatformDirIter *iter);

PlatformDirIter *platform_openKeysDir();
char *platform_makeMemTempDir();

/* User interface */
void platform_mainloop();
void platform_leaveMainloop();

void platform_startSign(const char *url, const char *hostname, const char *ip);
void platform_endSign();
void platform_setMessage(const char *message);
bool platform_sign(char **signature, int *siglen, char **person, char **password);

void platform_signError();

#endif

