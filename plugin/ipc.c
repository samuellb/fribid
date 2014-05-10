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

#define _BSD_SOURCE 1
#define _POSIX_C_SOURCE 200112
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "../common/defines.h"
#include "../common/pipe.h"
#include "plugin.h"

static const char mainBinary[] = SIGNING_EXECUTABLE;
static const char ipcOption[] = "--internal--ipc=" IPCVERSION;
static const char windowIdOption[] = "--internal--window-id";

#define PIPE_READ_END  0
#define PIPE_WRITE_END 1

typedef struct {
    FILE *in;
    FILE *out;

    pid_t child;
} PipeInfo;

BankIDError openPipesWithArgs(PipeInfo *pipeinfo, const char *argv[]) {
    int pipeIn[2];
    int pipeOut[2];
    
    if (pipe(pipeIn) == -1 || pipe(pipeOut) == -1) {
        perror(BINNAME ": Failed to create pipe");
        return BIDERR_InternalError;
    }
    
    pipeinfo->child = fork();
    if (pipeinfo->child == 0) {
        // Child process
        close(STDOUT_FILENO);
        close(STDIN_FILENO);
        close(pipeIn[PIPE_READ_END]);
        close(pipeOut[PIPE_WRITE_END]);
        dup2(pipeIn[PIPE_WRITE_END], STDOUT_FILENO);
        dup2(pipeOut[PIPE_READ_END], STDIN_FILENO);
        
        // These have been copied now
        //close(pipeIn[PIPE_WRITE_END]);
        //close(pipeOut[PIPE_READ_END]);
        
        execvp(mainBinary, (char *const *)argv);
        perror(BINNAME ": Failed to execute main binary");
        exit(1);
    } else {
        // Parent process
        close(pipeOut[PIPE_READ_END]);
        close(pipeIn[PIPE_WRITE_END]);
        
        pipeinfo->in = fdopen(pipeIn[PIPE_READ_END], "r");
        pipeinfo->out = fdopen(pipeOut[PIPE_WRITE_END], "w");
        return BIDERR_OK;
    }
}

BankIDError openPipes(PipeInfo *pipeinfo, const Plugin *plugin) {
    char windowId[21]; // This holds a native window id (such as an XID)
    const char *argv[] = {
        mainBinary, ipcOption, windowIdOption, windowId, (char *)NULL,
    };
    
    snprintf(windowId, 21, "%ld", plugin->windowId);
    BankIDError error = openPipesWithArgs(pipeinfo, argv);
    return error;
}

static void sendHeader(PipeInfo *pipeinfo, const Plugin *plugin,
                       PipeCommand command) {
    pipe_sendCommand(pipeinfo->out, command);
    pipe_sendString(pipeinfo->out, plugin->url);
    pipe_sendString(pipeinfo->out, plugin->hostname);
    pipe_sendString(pipeinfo->out, plugin->ip);
}

static BankIDError waitReply(PipeInfo *pipeinfo) {
    pipe_finishCommand(pipeinfo->out);
    
    pipe_waitData(pipeinfo->in);
    
    // Return error code
    return pipe_readInt(pipeinfo->in);
}

static void closePipes(PipeInfo *pipeinfo) {
    fclose(pipeinfo->out);
    fclose(pipeinfo->in);
    waitpid(pipeinfo->child, NULL, 0);
}


char *version_getVersion(Plugin *plugin) {
    PipeInfo pipeinfo;
    
    if(openPipes(&pipeinfo, plugin) != BIDERR_OK) {
        return 0;
    }
    sendHeader(&pipeinfo, plugin, PC_GetVersion);
    pipe_finishCommand(pipeinfo.out);
    
    char *version = pipe_readString(pipeinfo.in);
    closePipes(&pipeinfo);
    return version;
}


static void sendSignCommon(PipeInfo *pipeinfo, const Plugin *plugin) {
    pipe_sendString(pipeinfo->out, plugin->info.auth.challenge);
    pipe_sendInt(pipeinfo->out, plugin->info.auth.serverTime);
    pipe_sendOptionalString(pipeinfo->out, plugin->info.auth.policys);
    pipe_sendOptionalString(pipeinfo->out, plugin->info.auth.subjectFilter);
}

BankIDError sign_performAction_Authenticate(Plugin *plugin) {
    PipeInfo pipeinfo;
    
    if(openPipes(&pipeinfo, plugin) != BIDERR_OK) {
        return BIDERR_InternalError;
    }
    sendHeader(&pipeinfo, plugin, PC_Authenticate);
    sendSignCommon(&pipeinfo, plugin);
    
    plugin->lastError = waitReply(&pipeinfo);
    plugin->info.auth.signature = pipe_readString(pipeinfo.in);
    closePipes(&pipeinfo);
    return plugin->lastError;
}

BankIDError sign_performAction_Sign(Plugin *plugin) {
    PipeInfo pipeinfo;
    
    if(openPipes(&pipeinfo, plugin) != BIDERR_OK) {
        return BIDERR_InternalError;
    }
    sendHeader(&pipeinfo, plugin, PC_Sign);
    sendSignCommon(&pipeinfo, plugin);
    
    pipe_sendString(pipeinfo.out, plugin->info.sign.messageEncoding);
    pipe_sendString(pipeinfo.out, plugin->info.sign.message);
    pipe_sendOptionalString(pipeinfo.out, plugin->info.sign.invisibleMessage);
    
    plugin->lastError = waitReply(&pipeinfo);
    plugin->info.auth.signature = pipe_readString(pipeinfo.in);
    closePipes(&pipeinfo);
    return plugin->lastError;
}

char *regutil_createRequest(Plugin *plugin) {
    PipeInfo pipeinfo;
    
    if(openPipes(&pipeinfo, plugin) != BIDERR_OK) {
        return NULL;
    }
    sendHeader(&pipeinfo, plugin, PC_CreateRequest);
    
    // Send password policy
    pipe_sendInt(pipeinfo.out, plugin->info.regutil.input.minPasswordLength);
    pipe_sendInt(pipeinfo.out, plugin->info.regutil.input.minPasswordNonDigits);
    pipe_sendInt(pipeinfo.out, plugin->info.regutil.input.minPasswordDigits);
    
    // Send PKCS10 info
    RegutilPKCS10 *pkcs10 = plugin->info.regutil.input.pkcs10;
    while (pkcs10) {
        pipe_sendInt(pipeinfo.out, PLS_MoreData);
        
        pipe_sendInt(pipeinfo.out, pkcs10->keyUsage);
        pipe_sendInt(pipeinfo.out, pkcs10->keySize);
        pipe_sendOptionalString(pipeinfo.out, pkcs10->subjectDN);
        pipe_sendInt(pipeinfo.out, pkcs10->includeFullDN);
        
        pkcs10 = pkcs10->next;
    }
    pipe_sendInt(pipeinfo.out, PLS_End);
    
    // Send CMC info
    RegutilCMC *cmc = &plugin->info.regutil.input.cmc;
    pipe_sendOptionalString(pipeinfo.out, cmc->oneTimePassword);
    pipe_sendOptionalString(pipeinfo.out, cmc->rfc2729cmcoid);
    
    plugin->lastError = waitReply(&pipeinfo);
    char *request = pipe_readString(pipeinfo.in);
    if (plugin->lastError) {
        free(request);
        request = NULL;
    }
    
    closePipes(&pipeinfo);
    return request;
}

void regutil_storeCertificates(Plugin *plugin, const char *certs) {
    PipeInfo pipeinfo;
    
    if(openPipes(&pipeinfo, plugin) != BIDERR_OK) {
        return;
    }
    sendHeader(&pipeinfo, plugin, PC_StoreCertificates);
    
    pipe_sendOptionalString(pipeinfo.out, certs);
    
    plugin->lastError = waitReply(&pipeinfo);
    closePipes(&pipeinfo);    
}


