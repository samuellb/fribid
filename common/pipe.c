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
#include <stdlib.h>
#include <string.h>

#include "../common/defines.h"
#include "../common/pipe.h"

int pipe_readCommand(FILE *in) {
    int command = 0;
    if (fscanf(in, " %d;", &command) != 1) {
        fprintf(stderr, BINNAME ": pipe error\n");
        abort();
    }
    return command;
}

void pipe_sendCommand(FILE *out, int command) {
    fprintf(out, "%d;", command);
}

void pipe_finishCommand(FILE *out) {
    fprintf(out, "\n");
    fflush(out);
}

void pipe_flush(FILE *out) {
    fflush(out);
}

void pipe_readData(FILE *in, char **data, int *length) {
    fscanf(in, "%d;", length);
    if (*length < 0) *length = 0;
    *data = malloc(*length);
    fread(*data, *length, 1, in);
}

char *pipe_readString(FILE *in) {
    int length;
    fscanf(in, "%d;", &length);
    if (length < 0) return strdup("");
    char *data = malloc(length +1);
    data[length] = '\0';
    fread(data, length, 1, in);
    return data;
}

int pipe_readInt(FILE *in) {
    int value;
    fscanf(in, "%d;", &value);
    return value;
}

void pipe_sendData(FILE *out, const char *data, int length) {
    fprintf(out, "%d;", length);
    fwrite(data, length, 1, out);
}

void pipe_sendString(FILE *out, const char *str) {
    pipe_sendData(out, str, strlen(str));
}

void pipe_sendInt(FILE *out, int value) {
    fprintf(out, "%d;", value);
}
