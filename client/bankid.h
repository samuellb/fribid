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

#ifndef __BANKID_H__
#define __BANKID_H__

#include <stdbool.h>
#include <stdint.h>

#include "backend.h"
#include "../common/biderror.h"
#include "../common/bidtypes.h"

void bankid_checkVersionValidity();
bool bankid_versionHasExpired();
char *bankid_getVersion();


BankIDError bankid_authenticate(Token *token,
                                const char *challenge, int32_t serverTime,
                                const char *hostname, const char *ip,
                                char **signature);

BankIDError bankid_sign(Token *token,
                        const char *challenge, int32_t serverTime,
                        const char *hostname, const char *ip,
                        const char *messageEncoding, const char *message,
                        const char *invisibleMessage,
                        char **signature);

BankIDError bankid_createRequest(const RegutilInfo *info,
                                 const char *hostname,
                                 const char *password,
                                 char **request,
                                 TokenError *error);

char *bankid_getRequestDisplayName(const RegutilInfo *params);

BankIDError bankid_storeCertificates(const char *certs, const char *hostname);

#endif

