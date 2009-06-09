#ifndef __PIPE_H__
#define __PIPE_H__

#include <stdio.h>

#define PIPE_COMMAND_MAX 200

// Commands to the main program
#define PMC_Authenticate    1
#define PMC_Sign            2

int pipe_readCommand(FILE *in);
void pipe_sendCommand(FILE *out, int command);
void pipe_finishCommand(FILE *out);
void pipe_flush(FILE *out);

void pipe_readData(FILE *in, char **data, int *length);
char *pipe_readString(FILE *in);
int pipe_readInt(FILE *in);

void pipe_sendData(FILE *out, const char *data, int length);
void pipe_sendString(FILE *out, const char *str);
void pipe_sendInt(FILE *out, int value);

#endif

