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

#ifndef __KEYFILE_H__
#define __KEYFILE_H__

#include <stdbool.h>

#define CERTUSE_ISSUER            6
#define CERTUSE_SIGNING          64
#define CERTUSE_AUTHENTICATION  128

void keyfile_init();
void keyfile_shutdown();

bool keyfile_listPeople(const char *data, const int datalen,
                         char ***people, int *count);
char *keyfile_getDisplayName(const char *person);
bool keyfile_matchSubjectFilter(const char *person, const char *subjectFilter);
bool keyfile_getBase64Chain(const char *data, const int datalen,
                            const char *person, const unsigned int certMask,
                            char ***certs, int *count);

bool keyfile_sign(const char *data, const int datalen,
                  const char *person, const unsigned int certMask, const char *password,
                  const char *message, const int messagelen,
                  char **signature, int *siglen);

#endif


