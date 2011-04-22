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

#ifndef __PIPE_H__
#define __PIPE_H__

#include <stdio.h>

// Commands to the main program
typedef enum {
    PC_GetVersion = 1,
    PC_Authenticate,
    PC_Sign,
    PC_CreateRequest,
    PC_StoreCertificates,
} PipeCommand;

typedef enum {
    PLS_End = 0,
    PLS_MoreData,
} PipeListStatus;

PipeCommand pipe_readCommand(FILE *in);
void pipe_sendCommand(FILE *out, PipeCommand command);
void pipe_finishCommand(FILE *out);
void pipe_flush(FILE *out);

void pipe_waitData(FILE *file);

void pipe_readData(FILE *in, char **data, int *length);
char *pipe_readString(FILE *in);
char *pipe_readOptionalString(FILE *in);
int pipe_readInt(FILE *in);

void pipe_sendData(FILE *out, const char *data, int length);
void pipe_sendString(FILE *out, const char *str);
void pipe_sendOptionalString(FILE *out, const char *str);
void pipe_sendInt(FILE *out, int value);

#endif

