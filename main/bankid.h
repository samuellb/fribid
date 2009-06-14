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

#ifndef __BANKID_H__
#define __BANKID_H__

typedef enum {
    BIDERR_OK =               0,
    BIDERR_InternalError =    1,
    BIDERR_UserCancel =    8002,
} BankIDError;

void bankid_init();
void bankid_shutdown();
char *bankid_getVersion();


BankIDError bankid_authenticate(const char *p12Data, const int p12Length,
                                const char *person, const char *password,
                                const char *challenge,
                                const char *hostname, const char *ip,
                                char **signature);

BankIDError bankid_sign(const char *p12Data, const int p12Length,
                        const char *person, const char *password,
                        const char *challenge,
                        const char *hostname, const char *ip,
                        const char *message,
                        char **signature);

#endif

