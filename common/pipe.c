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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <glib.h>

#include "../common/defines.h"
#include "../common/pipe.h"

static void pipeError() {
    fprintf(stderr, BINNAME ": pipe error\n");
}

static gboolean stopWaiting(GIOChannel *source,
                            GIOCondition condition, gpointer data) {
    *((bool*)data) = true;
    return FALSE;
}

/**
 * Waits in the event loop until there's data to read.
 * 
 * Data may be buffered by stdio so only call this function
 * when you know that the other side will send data since
 * the last time this function was called.
 */
void pipe_waitData(FILE *file) {
    bool hasData = false;
    GIOChannel *channel = g_io_channel_unix_new(fileno(file));
    assert(channel != NULL);
    g_io_channel_set_encoding(channel, NULL, NULL);
    g_io_add_watch(channel, G_IO_IN | G_IO_HUP | G_IO_ERR,
                   stopWaiting, &hasData);
    g_io_channel_unref(channel);
    
    while (!hasData) {
        g_main_context_iteration(NULL, TRUE);
    }
}

int pipe_readCommand(FILE *in) {
    int command = 0;
    if (fscanf(in, " %d;", &command) != 1) {
        pipeError();
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
    if ((fscanf(in, "%d;", length) != 1) || (*length < 0)) {
        pipeError();
        *length = 0;
    }
    *data = malloc(*length);
    if ((*data == NULL) || (fread(*data, *length, 1, in) != 1)) {
        pipeError();
        *data = realloc(*data, 0);
        *length = 0;
    }
}

char *pipe_readString(FILE *in) {
    int length = -1;
    fscanf(in, "%d;", &length);
    if (length < 0) {
        pipeError();
        return strdup("");
    }
    
    char *data = malloc(length +1);
    if (!data) {
        pipeError();
        return strdup("");
    }
    
    data[length] = '\0';
    if (fread(data, length, 1, in) == 1) {
        return data;
    } else {
        pipeError();
        free(data);
        return strdup("");
    }
}

int pipe_readInt(FILE *in) {
    int value = -1;
    if (fscanf(in, "%d;", &value) != 1) {
        pipeError();
    }
    return value;
}

void pipe_sendData(FILE *out, const char *data, int length) {
    assert(data != NULL);
    fprintf(out, "%d;", length);
    fwrite(data, length, 1, out);
}

void pipe_sendString(FILE *out, const char *str) {
    assert(str != NULL);
    pipe_sendData(out, str, strlen(str));
}

void pipe_sendInt(FILE *out, int value) {
    fprintf(out, "%d;", value);
}

