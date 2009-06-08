#define _BSD_SOURCE 1
#include <stdlib.h>
#include <string.h>

#include "../common/pipe.h"

int pipe_readCommand(FILE *in) {
    int command = 0;
    if (fscanf(in, " %d;", &command) != 1) {
        fprintf(stderr, "bankid-se: pipe error\n");
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
