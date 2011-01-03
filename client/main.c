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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../common/defines.h"
#include "../common/pipe.h"
#include "backend.h"
#include "bankid.h"
#include "platform.h"
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
 * pipeData is called when the plugin has sent some data.
 * This happens when one of the Javascript methods of an
 * plugin object is called.
 */
void pipeData() {
    PipeCommand command = pipe_readCommand(stdin);
    switch (command) {
        case PC_Authenticate:
        case PC_Sign: {
            char *challenge = pipe_readString(stdin);
            int32_t serverTime = pipe_readInt(stdin);
            free(pipe_readOptionalString(stdin)); // Just ignore the policies list for now
            char *subjectFilter = pipe_readOptionalString(stdin);
            char *url = pipe_readString(stdin);
            char *hostname = pipe_readString(stdin);
            char *ip = pipe_readString(stdin);
            char *message = NULL, *invisibleMessage = NULL;
            if (command == PC_Sign) {
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
            
            if (message != NULL) {
                char *decodedMessage = base64_decode(message);
                platform_setMessage(decodedMessage);
                free(decodedMessage);
            }
            
            if (bankid_versionHasExpired()) {
                platform_versionExpiredError();
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
                                        hostname, ip, message,
                                        invisibleMessage, &signature);
                }
                
                guaranteed_memset(password, 0, password_maxsize);
                
                if (error == BIDERR_OK) break;
                
                platform_showError(token_getLastError(token));
                error = BIDERR_UserCancel;
            }

            secmem_free_page(password);

            platform_endSign();
            
            backend_freeNotifier(notifier);
            free(message);
            free(invisibleMessage);
            free(challenge);
            free(url);
            free(hostname);
            free(ip);
            
            pipe_sendInt(stdout, error);
            pipe_sendString(stdout, (signature ? signature : ""));
            pipe_flush(stdout);
            
            free(signature);
            platform_leaveMainloop();
            break;
        }
        case PC_CreateRequest: {
            // Read input
            RegutilInfo input;
            memset(&input, 0, sizeof(input));
            
            while (pipe_readInt(stdin) == PLS_MoreData) {
                // PKCS10
                RegutilPKCS10 *pkcs10 = malloc(sizeof(RegutilPKCS10));
                pkcs10->keyUsage = pipe_readInt(stdin);
                pkcs10->keySize = pipe_readInt(stdin);
                pkcs10->subjectDN = pipe_readString(stdin);
                
                pkcs10->next = input.pkcs10;
                input.pkcs10 = pkcs10;
            }
            
            while (pipe_readInt(stdin) == PLS_MoreData) {
                // CMC
                RegutilCMC *cmc = malloc(sizeof(RegutilCMC));
                cmc->oneTimePassword = pipe_readString(stdin);
                cmc->rfc2729cmcoid = pipe_readString(stdin);
                
                cmc->next = input.cmc;
                input.cmc = cmc;
            }
            
            // Check for broken pipe
            if (feof(stdin)) goto createReq_error;
            
            // Ask for a new password
            // TODO
            char *password = "123456qwerty";
            
            // Generate key pair and construct the request
            char *request;
            BankIDError error = bankid_createRequest(&input, password,
                                                     &request);
            
            // Send result
            if (error) {
              createReq_error:
                pipe_sendInt(stdout, BIDERR_InternalError);
                pipe_sendString(stdout, "");
            } else {
                // TODO send BIDERR_OK here when the implementation is complete
                pipe_sendInt(stdout, BIDERR_InternalError);
                pipe_sendString(stdout, request);
            }
            
            pipe_flush(stdout);
            platform_leaveMainloop();
            break;
        }
    }
}

/**
 * Processes some command line options that neither require a GUI or the NSS
 * libraries.
 */
int process_non_ui_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--internal--bankid-version-string")) {
            char *versionString = bankid_getVersion();
            printf("%s", versionString);
            free(versionString);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    bool ipc = false, error = false;
    
    /* Check whether the current version is still valid */
    platform_seedRandom();
    bankid_checkVersionValidity();
    
    /* Parse command line and set up the UI component */
    if (process_non_ui_args(argc, argv)) {
        return 0;
    }

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

