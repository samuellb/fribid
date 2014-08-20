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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../common/defines.h"
#include "../common/pipe.h"
#include "backend.h"
#include "bankid.h"
#include "certutil.h"
#include "platform.h"
#include "prefs.h"
#include "misc.h"
#include "secmem.h"

static const char version[] = PACKAGEVERSION;
static unsigned long browserWindowId = PLATFORM_NO_WINDOW;

/**
 * Called when a token has been added or removed.
 */
static void notifyCallback(Token *token, TokenChange change) {
    switch (change) {
        case TokenChange_Added:
            platform_addToken(token);
            break;
        case TokenChange_Changed:
            // Not supported
            break;
        case TokenChange_Removed:
            platform_removeToken(token);
            token_free(token);
            break;
    }
}

/**
 * Called when a command is being sent from the plugin.
 */
void pipeCommand(PipeCommand command, const char *url, const char *hostname,
                 const char *ip) {
    switch (command) {
        case PC_GetVersion: {
            char *versionString = bankid_getVersion();
            
            pipe_sendString(stdout, versionString);
            free(versionString);
            pipe_flush(stdout);
            
            platform_leaveMainloop();
            break;
        }
        case PC_Authenticate:
        case PC_Sign: {
            char *challenge = pipe_readString(stdin);
            int32_t serverTime = pipe_readInt(stdin);
            free(pipe_readOptionalString(stdin)); // Just ignore the policies list for now
            char *subjectFilter = pipe_readOptionalString(stdin);
            char *messageEncoding = NULL, *message = NULL,
                 *invisibleMessage = NULL;
            if (command == PC_Sign) {
                messageEncoding = pipe_readString(stdin);
                message = pipe_readString(stdin);
                invisibleMessage = pipe_readOptionalString(stdin);
            }
            
            // Validate input
            BankIDError error = BIDERR_OK;
            
            if (!is_https_url(url)) {
                error = BIDERR_NotSSL;
            } else if (!is_canonical_base64(challenge) ||
                       !is_valid_hostname(hostname) ||
                       !is_valid_ip_address(ip) ||
                       (command == PC_Sign && (
                           !is_canonical_base64(message) ||
                           (invisibleMessage && !is_canonical_base64(invisibleMessage))
                       ))) {
                error = BIDERR_InternalError;
            }
            
            if (error != BIDERR_OK) {
                pipe_sendInt(stdout, error);
                pipe_sendString(stdout, "");
                pipe_flush(stdout);
                
                platform_leaveMainloop();
                return;
            }
            
            if (subjectFilter && !is_canonical_base64(subjectFilter)) {
                // The subject filter is invalid. Ignore it
                free(subjectFilter);
                subjectFilter = NULL;
            }
            
            Token *token;
            char *password = NULL;
            long password_maxsize = 0;
            char *signature = NULL;
            char *decodedSubjectFilter = NULL;
            error = BIDERR_UserCancel;

            // Allocate a secure page for the password
            password = secmem_get_page(&password_maxsize);
            if (!password || !password_maxsize) {
                pipe_sendInt(stdout, BIDERR_InternalError);
                pipe_sendString(stdout, "");
                pipe_flush(stdout);
                
                platform_leaveMainloop();
                return;
            }

            if (subjectFilter) {
                decodedSubjectFilter = base64_decode(subjectFilter);
                free(subjectFilter);
            }
            
            // Pass all parameters to the user interface
            platform_startSign(url, hostname, ip, browserWindowId);
            BackendNotifier *notifier = backend_createNotifier(
                decodedSubjectFilter,
                (command == PC_Sign ?
                    KeyUsage_Signing : KeyUsage_Authentication),
                notifyCallback);
            platform_setNotifier(notifier);
            platform_addKeyDirectories();
            backend_scanTokens(notifier);
            free(decodedSubjectFilter);
            
            if (command == PC_Sign) {
                if (!message) abort();
                char *decodedMessage = base64_decode(message);
                platform_setMessage(decodedMessage);
                free(decodedMessage);
            }

            while (platform_sign(&token, password, password_maxsize)) {
                // Set the password (not used by all backends)
                token_usePassword(token, password);
                
                // Try to authenticate/sign
                if (command == PC_Authenticate) {
                    error = bankid_authenticate(token, challenge, serverTime,
                                                hostname, ip, &signature);
                } else {
                    error = bankid_sign(token, challenge, serverTime,
                                        hostname, ip, messageEncoding,
                                        message, invisibleMessage,
                                        &signature);
                }
                
                guaranteed_memset(password, 0, password_maxsize);
                
                if (error == BIDERR_OK) break;
                
                // An error occurred
                const TokenError tokenError = token_getLastError(token);
                platform_showError(tokenError);
                if (tokenError == TokenError_BadPassword || tokenError == TokenError_BadPin) {
                    platform_focusPassword(); // also removes focus from the Sign button
                }
                error = BIDERR_UserCancel;
            }

            secmem_free_page(password);

            platform_endSign();
            
            backend_freeNotifier(notifier);
            free(messageEncoding);
            free(message);
            free(invisibleMessage);
            free(challenge);
            
            pipe_sendInt(stdout, error);
            pipe_sendString(stdout, (signature ? signature : ""));
            pipe_flush(stdout);
            
            free(signature);
            platform_leaveMainloop();
            break;
        }
        case PC_CreateRequest: {
            char *request = NULL;
            BankIDError error = BIDERR_InternalError;
            long password_maxsize = 0;
            char *name = NULL;
            char *password = NULL;
            
            // Read input
            RegutilInfo input;
            memset(&input, 0, sizeof(input));
            
            input.minPasswordLength = pipe_readInt(stdin);
            input.minPasswordNonDigits = pipe_readInt(stdin);
            input.minPasswordDigits = pipe_readInt(stdin);
            
            while (pipe_readInt(stdin) == PLS_MoreData) {
                // PKCS10
                RegutilPKCS10 *pkcs10 = malloc(sizeof(RegutilPKCS10));
                pkcs10->keyUsage = pipe_readInt(stdin);
                pkcs10->keySize = pipe_readInt(stdin);
                pkcs10->subjectDN = pipe_readString(stdin);
                pkcs10->includeFullDN = pipe_readInt(stdin);
                
                pkcs10->next = input.pkcs10;
                input.pkcs10 = pkcs10;
            }
            
            // CMC
            input.cmc.oneTimePassword = pipe_readString(stdin);
            input.cmc.rfc2729cmcoid = pipe_readString(stdin);
            
            // Check for broken pipe
            if (feof(stdin)) goto createReq_end;
            
            // Check input
            if (!input.pkcs10) goto createReq_end;
            
            // Get name to display
            name = bankid_getRequestDisplayName(&input);
            if (!name) goto createReq_end;
            
            // Allocate a secure page for the password
            password = secmem_get_page(&password_maxsize);
            if (!password || !password_maxsize) goto createReq_end;
            
            platform_startChoosePassword(name, browserWindowId);
            platform_setPasswordPolicy(input.minPasswordLength,
                                       input.minPasswordNonDigits,
                                       input.minPasswordDigits);
            
            for (;;) {
                error = RUERR_UserCancel;
                // Ask for a password
                if (!platform_choosePassword(password, password_maxsize))
                    break;
                
                // Try to authenticate/sign
                // Generate key pair and construct the request
                TokenError tokenError;
                error = bankid_createRequest(&input, hostname, password,
                                             &request, &tokenError);
                
                guaranteed_memset(password, 0, password_maxsize);
                
                if (error == BIDERR_OK) break;
                
                platform_showError(tokenError);
            }
            
            platform_endChoosePassword();
            
            // Send result
          createReq_end:
            secmem_free_page(password);
            pipe_sendInt(stdout, error);
            
            if (!request) pipe_sendString(stdout, "");
            else {
                pipe_sendString(stdout, request);
                free(request);
            }
            
            pipe_flush(stdout);
            platform_leaveMainloop();
            break;
        }
        case PC_StoreCertificates: {
            char *certs = pipe_readString(stdin);
            
            TokenError tokenError;
            BankIDError error = bankid_storeCertificates(certs, hostname,
                                                         &tokenError);
            if (error != BIDERR_OK) {
                if (prefs_debug_dump) {
                    certutil_dumpCertsP7(certs);
                }
                platform_showError(tokenError);
            }
            
            pipe_sendInt(stdout, error);
            pipe_flush(stdout);
            
            platform_leaveMainloop();
            break;
        }
        default: {
            fprintf(stderr, BINNAME ": invalid command from pipe\n");
            platform_leaveMainloop();
            break;
        }
    }
}

/**
 * pipeData is called when the plugin has sent some data.
 * This happens when one of the Javascript methods of an
 * plugin object is called.
 */
void pipeData(void) {
    PipeCommand command = pipe_readCommand(stdin);
    char *url = pipe_readString(stdin);
    char *hostname = pipe_readString(stdin);
    char *ip = pipe_readString(stdin);
    
    pipeCommand(command, url, hostname, ip);
    
    free(ip);
    free(hostname);
    free(url);
}

int main(int argc, char **argv) {
    bool ipc = false, error = false;
    
    prefs_load();
    error = secmem_init_pool();
    if (error) {
        fprintf(stderr, BINNAME ": could not initialize secure memory");
        return 2;
    }

    platform_init(&argc, &argv);
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--internal--ipc=" IPCVERSION)) {
            ipc = true;
        } else if (!strncmp(argv[i], "--internal--ipc", 15)) {
            fprintf(stderr, BINNAME ": Version mismatch. "
                    "Plugin version: %s,  Signer version: " IPCVERSION "\n",
                    (argv[i][15] != '\0' ? &argv[i][16] : "1"));
            error = true;
        } else if (!strcmp(argv[i], "--internal--window-id")) {
            i++;
            if (i == argc) {
                fprintf(stderr, BINNAME ": Missing window id\n");
                error = true;
                break;
            }
            browserWindowId = atol(argv[i]);
        } else {
            fprintf(stderr, BINNAME ": Invalid option: %s\n", argv[i]);
            error = true;
        }
    }
    
    if (error) {
        secmem_destroy_pool();
        return 2;
    }

    /* Set up pipe */
    if (ipc) {
        platform_setupPipe(pipeData);
    } else {
        fprintf(stderr, "This is an internal program.\n");
        secmem_destroy_pool();
        return 2;
    }
    
    platform_mainloop();

    secmem_destroy_pool();
    return 0;
}

