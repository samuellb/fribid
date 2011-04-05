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

#ifndef __MISC_H__
#define __MISC_H__

#include <stdbool.h>

char *rasprintf(const char *format, ...);
char *rasprintf_append(char *str, const char *format, ...);
void *guaranteed_memset(void *v, int c, size_t n);

char *base64_encode(const char *data, const int length);
char *base64_decode(const char *encoded);
char *base64_decode_binary(const char *encoded, size_t *decodedLength);
bool is_canonical_base64(const char *encoded);
char *sha_base64(const char *str);

bool is_valid_domain_name(const char *domain);
bool is_valid_ip_address(const char *ip);
bool is_valid_hostname(const char *hostname);
bool is_https_url(const char *url);

#endif


