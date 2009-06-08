#define _BSD_SOURCE 1
#define _POSIX_C_SOURCE 199012
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "../common/pipe.h"
#include "plugin.h"

//static const char *mainBinary = "bankid-se";
static const char *mainBinary = "/home/samuellb/Projekt/e-leg/main/bankid-se";
static const char *versionOption = "--internal--bankid-version-string";
static const char *ipcOption = "--internal--ipc";

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

static void openPipes(const char *option) {
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
        
        execlp(mainBinary, mainBinary, option, (char *)NULL);
        perror("bankid-se: Failed to execute main binary");
        exit(1);
    } else {
        // Parent process
        close(pipeOut[PIPE_READ_END]);
        close(pipeIn[PIPE_WRITE_END]);
        
        pipein = fdopen(PIPEIN, "r");
        pipeout = fdopen(PIPEOUT, "w");
    }
}

static void closePipes() {
    close(PIPEOUT);
    close(PIPEIN);
    waitpid(child, NULL, WNOHANG);
}


char *version_getVersion(Plugin *plugin) {
    char buff[1000];
    
    openPipes(versionOption);
    if (fgets(buff, sizeof(buff), pipein) != NULL) {
        buff[strlen(buff)-1] = '\0';
    } else {
        buff[0] = '\0';
    }
    closePipes();
    
    return strdup(buff);
}


int auth_performAction_Authenticate(Plugin *plugin) {
    openPipes(ipcOption);
    pipe_sendCommand(pipeout, PMC_Authenticate);
    
    pipe_sendString(pipeout, plugin->info.auth.challenge);
    pipe_sendString(pipeout, plugin->info.auth.policys);
    pipe_sendString(pipeout, plugin->url);
    pipe_sendString(pipeout, plugin->hostname);
    pipe_sendString(pipeout, plugin->ip);
    
    pipe_finishCommand(pipeout);
    fprintf(stderr, "plugin: sent everything\n");
    
    plugin->lastError = pipe_readInt(pipein);
    fprintf(stderr, "plugin: read error code\n");
    plugin->info.auth.signature = pipe_readString(pipein);
    fprintf(stderr, "plugin: read sig\n");
    closePipes();
    return (plugin->info.auth.signature != NULL ? 0 : 1);
}



