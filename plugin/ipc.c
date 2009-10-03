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

static const char *mainBinary = SIGNING_EXECUTABLE;
static const char *versionOption = "--internal--bankid-version-string";
static const char *ipcOption = "--internal--ipc";
static const char *windowIdOption = "--internal--window-id";

static int savedOut;
static int savedIn;

#define PIPE_READ_END  0
#define PIPE_WRITE_END 1
static int pipeIn[2];
static int pipeOut[2];

#define PIPEOUT (pipeOut[1])
#define PIPEIN (pipeIn[0])

static FILE *pipein;
static FILE *pipeout;

static pid_t child;

static void openPipes(const char *argv[]) {
    savedOut = dup(STDOUT_FILENO);
    savedIn = dup(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDIN_FILENO);
    
    pipe(pipeIn);
    pipe(pipeOut);
    
    child = fork();
    if (child == 0) {
        // Child process
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
        
        pipein = fdopen(PIPEIN, "r");
        pipeout = fdopen(PIPEOUT, "w");
    }
}

static void openVersionPipes() {
    const char *argv[] = {
        mainBinary, versionOption, (char *)NULL,
    };
    openPipes(argv);
}

static void openInteractivePipes(Plugin *plugin) {
    char windowId[11]; // This holds a native window id (such as an XID)
    const char *argv[] = {
        mainBinary, ipcOption, windowIdOption, windowId, (char *)NULL,
    };
    
    snprintf(windowId, 11, "%d", plugin->windowId);
    openPipes(argv);
}

static void closePipes() {
    close(PIPEOUT);
    close(PIPEIN);
    waitpid(child, NULL, WNOHANG);
}


char *version_getVersion(Plugin *plugin) {
    char buff[1000];
    
    openVersionPipes();
    if (fgets(buff, sizeof(buff), pipein) != NULL) {
        buff[strlen(buff)-1] = '\0';
    } else {
        buff[0] = '\0';
    }
    closePipes();
    
    return strdup(buff);
}


static void sendSignCommon(const Plugin *plugin) {
    pipe_sendString(pipeout, plugin->info.auth.challenge);
    pipe_sendString(pipeout, (plugin->info.auth.policys != NULL ?
                              plugin->info.auth.policys : ""));
    pipe_sendString(pipeout, plugin->url);
    pipe_sendString(pipeout, plugin->hostname);
    pipe_sendString(pipeout, plugin->ip);
}

int sign_performAction_Authenticate(Plugin *plugin) {
    openInteractivePipes(plugin);
    pipe_sendCommand(pipeout, PMC_Authenticate);
    
    sendSignCommon(plugin);
    
    pipe_finishCommand(pipeout);
    
    plugin->lastError = pipe_readInt(pipein);
    plugin->info.auth.signature = pipe_readString(pipein);
    closePipes();
    return plugin->lastError;
}

int sign_performAction_Sign(Plugin *plugin) {
    openInteractivePipes(plugin);
    pipe_sendCommand(pipeout, PMC_Sign);
    
    sendSignCommon(plugin);
    pipe_sendString(pipeout, plugin->info.sign.message);
    pipe_sendString(pipeout, plugin->info.sign.subjectFilter);
    
    pipe_finishCommand(pipeout);
    
    plugin->lastError = pipe_readInt(pipein);
    plugin->info.auth.signature = pipe_readString(pipein);
    closePipes();
    return plugin->lastError;
}


