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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../common/defines.h"
#include "../common/pipe.h"
#include "bankid.h"
#include "platform.h"
#include "misc.h"

static const char *version = "0.1.0";

void pipeData() {
    int command = pipe_readCommand(stdin);
    switch (command) {
        case PMC_Authenticate:
        case PMC_Sign: {
            char *challenge = pipe_readString(stdin);
            free(pipe_readString(stdin)); // Policy -- What's this doing?
            char *url = pipe_readString(stdin);
            char *hostname = pipe_readString(stdin);
            char *ip = pipe_readString(stdin);
            
            char *message = NULL;
            char *subjectFilter = NULL;
            if (command == PMC_Sign) {
                message = pipe_readString(stdin);
                subjectFilter = pipe_readString(stdin);
            }
            
            // Validate input
            if (!is_canonical_base64(challenge) ||
                !is_valid_hostname(hostname) ||
                !is_valid_ip_address(ip) ||
                !is_https_url(url) ||
                (command == PMC_Sign && (
                    !is_canonical_base64(message) ||
                    !is_canonical_base64(subjectFilter)
                ))) {
                pipe_sendInt(stdout, BIDERR_InternalError);
                pipe_sendString(stdout, "");
                pipe_flush(stdout);
                
                platform_leaveMainloop();
                return;
            }
            
            char *p12Data = NULL, *person = NULL, *password = NULL;
            int p12Length;
            char *signature = NULL;
            BankIDError error = BIDERR_UserCancel;
            
            // TODO set subject filter
            platform_startSign(url, hostname, ip);
            if (message != NULL) {
                char *decodedMessage = base64_decode(message);
                platform_setMessage(decodedMessage);
                free(decodedMessage);
            }
            
            while (platform_sign(&p12Data, &p12Length, &person, &password)) {
                // Try to authenticate/sign
                if (command == PMC_Authenticate) {
                    error = bankid_authenticate(p12Data, p12Length, person, password,
                                                challenge, hostname, ip,
                                                &signature);
                } else {
                    error = bankid_sign(p12Data, p12Length, person, password,
                                        challenge, hostname, ip,
                                        message, &signature);
                }
                if (error == BIDERR_OK) break;
                
                platform_signError();
                error = BIDERR_UserCancel;
            }
            
            platform_endSign();
            
            free(subjectFilter);
            free(message);
            free(challenge);
            free(url);
            free(hostname);
            free(ip);
            free(p12Data);
            free(person);
            free(password);
            
            pipe_sendInt(stdout, error);
            pipe_sendString(stdout, (signature ? signature : ""));
            pipe_flush(stdout);
            
            free(signature);
            platform_leaveMainloop();
            break;
        }
    }
}


int process_non_ui_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--internal--bankid-version-string")) {
            char *versionString = bankid_getVersion();
            printf("%s\n", versionString);
            free(versionString);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    bool ipc = false, error = false;
    
    /* Parse command line and set up the UI component */
    if (process_non_ui_args(argc, argv)) {
        return 0;
    }
    
    platform_init(&argc, &argv);
    bankid_init();
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--internal--ipc")) {
            ipc = true;
        } else {
            fprintf(stderr, BINNAME ": Invalid option: %s\n", argv[i]);
            error = true;
        }
    }
    
    if (error) return 2;
    
    /* Set up pipe */
    if (ipc) {
        platform_setupPipe(pipeData);
    } else {
        fprintf(stderr, "This is an internal program.\n");
        return 2;
    }
    
    platform_mainloop();
    
    bankid_shutdown();
    return 0;
}

