#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bankid.h"
#include "../common/pipe.h"
#include "platform.h"

static const char *version = "0.1.0";


void pipeData() {
    switch (pipe_readCommand(stdin)) {
        case PMC_Authenticate: {
            char *challenge = pipe_readString(stdin);
            free(pipe_readString(stdin)); // Policy -- What's this doing?
            char *url = pipe_readString(stdin);
            char *hostname = pipe_readString(stdin);
            char *ip = pipe_readString(stdin);
            
            char *p12Data = NULL, *person = NULL, *password = NULL;
            int p12Length;
            char *signature = NULL;
            BankIDError error = BIDERR_UserCancel;
            
            platform_startAuthenticate(url, hostname, ip);
            
            while (platform_authenticate(&p12Data, &p12Length, &person, &password)) {
                // Try to authenticate
                error = bankid_authenticate(p12Data, p12Length, person, password,
                                            challenge, hostname, ip,
                                            &signature);
                if (error == BIDERR_OK) break;
            }
            
            platform_endAuthenticate();
            
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
            exit(0);
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
            fprintf(stderr, "Invalid option: %s\n", argv[i]);
            error = true;
        }
    }
    
    if (error) return 2;
    
    /* Set up pipe */
    if (ipc) {
        platform_setupPipe(pipeData);
    }
    
    platform_mainloop();
    
    bankid_shutdown();
    return 0;
}

