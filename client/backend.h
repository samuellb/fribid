/*

  Copyright (c) 2010 Samuel Lidén Borell <samuel@slbdata.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, token to the following conditions:
  
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

#ifndef __BACKEND_H__
#define __BACKEND_H__

#include <stdbool.h>

typedef enum {
    KeyUsage_Issuing,
    KeyUsage_Signing,
    KeyUsage_Authentication,
} KeyUsage;

typedef struct _Token Token;

typedef enum {
    TokenChange_Added,
    TokenChange_Changed,
    TokenChange_Removed,
} TokenChange;

/**
 * A backend notifier object monitors all supported backends for tokens that
 * are used to identify a certain person.
 */
typedef struct _BackendNotifier BackendNotifier;

typedef void (*BackendNotifyFunction)(Token *token, TokenChange change);

typedef enum {
    // The token needs...
    TokenStatus_NeedPassword = 1, // a password on the keyboard
    TokenStatus_NeedCard,         // an inserted smart card
    TokenStatus_NeedPIN,          // a pin code to be entered on a device
    TokenStatus_NeedConfirm,      // a confirm button to be pressed on a device
} TokenStatus;

typedef enum  {
    TokenError_Success =      0,
    TokenError_Unknown =      1,
    // File errors
    TokenError_FileNotReadable,
    TokenError_BadFile,
    TokenError_BadPassword,
    // Smart card errors
    TokenError_BadPin,
} TokenError;

/* Notification methods */
BackendNotifier *backend_createNotifier(const char *subjectFilter,
                                        KeyUsage keyUsage,
                                        BackendNotifyFunction notifyFunction);
void backend_freeNotifier(BackendNotifier *notifier);

/* Function to manually add files */
TokenError backend_addFile(BackendNotifier *notifier,
                           const char *file, size_t length, void *tag);

/* Token methods */
TokenStatus token_getStatus(const Token *token);
char *token_getDisplayName(const Token *token);
void *token_getTag(const Token *token);
// The password must not be free'd until the signature has been generated
void token_usePassword(Token *token, const char *password);
bool token_getBase64Chain(Token *token, char ***certs, size_t *count);
bool token_sign(Token *token, const char *message, size_t messagelen,
                char **signature, size_t *siglen);
bool token_remove(Token *token);
void token_free(Token *token);
TokenError token_getLastError(const Token *token);

#endif

