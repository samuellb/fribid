/*

  Copyright (c) 2004 Samuel Lidén Borell <samuel@kodafritt.se>
 
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

#define _BSD_SOURCE
#define _POSIX_C_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define IPCVERSION "10"


/* this program is multiprocess with fork() so it's ok to have global data */
static char request[100*1024]; /* max 100 KiB */
static char result[400*1024]; /* max 400 KiB */

static pid_t signbinary_pid;
static FILE *pipe_in, *pipe_out;

static const char *ipc_argv[] = {
    NULL /* assigned in main() */, "--internal--ipc=" IPCVERSION, (char *)NULL,
};

#define PIPE_READ_END  0
#define PIPE_WRITE_END 1

static int open_pipes() {
    int pipeIn[2];
    int pipeOut[2];
    
    if (pipe(pipeIn) == -1 || pipe(pipeOut) == -1) {
        perror("failed to create pipe");
        return 0;
    }
    
    signbinary_pid = fork();
    if (signbinary_pid == 0) {
        /* Child process */
        close(STDOUT_FILENO);
        close(STDIN_FILENO);
        close(pipeIn[PIPE_READ_END]);
        close(pipeOut[PIPE_WRITE_END]);
        dup2(pipeIn[PIPE_WRITE_END], STDOUT_FILENO);
        dup2(pipeOut[PIPE_READ_END], STDIN_FILENO);
        
        /* These have been copied now */
        /*close(pipeIn[PIPE_WRITE_END]);
        close(pipeOut[PIPE_READ_END]);*/
        
        execvp(ipc_argv[0], (char *const *)ipc_argv);
        perror("failed to execute main binary");
        exit(1);
    } else {
        /* Parent process */
        close(pipeOut[PIPE_READ_END]);
        close(pipeIn[PIPE_WRITE_END]);
        
        pipe_in = fdopen(pipeIn[PIPE_READ_END], "r");
        pipe_out = fdopen(pipeOut[PIPE_WRITE_END], "w");
        return 1;
    }
}

static void ipc_send_str(FILE *out, const char *data)
{
    if (data) {
        int length = strlen(data);
        fprintf(out, "%d;", length);
        fwrite(data, length, 1, out);
        fprintf(out, "\n");
    } else {
        fprintf(out, "0;\n");
    }
}

static int ipc_read_int(FILE *in)
{
    int value = -1;
    if (fscanf(in, " %d;", &value) != 1) {
        perror("reading from pipe");
    }
    return value;
}

static char *ipc_read_string(FILE *in, int *lenptr) {
    char *data;
    int length = ipc_read_int(in);
    if (length <= 0) return strdup("");
    if (lenptr) {
        *lenptr = length;
    }
    
    data = malloc(length +1);
    if (!data) {
        perror("malloc string from pipe");
        return strdup("");
    }
    
    data[length] = '\0';
    if (fread(data, length, 1, in) == 1) {
        return data;
    } else {
        fprintf(stderr, "failed to read string from pipe");
        free(data);
        return strdup("");
    }
}


static int unhex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    else if (c >= 'a' && c <= 'f') return c - 'a' + 0xa;
    else if (c >= 'A' && c <= 'F') return c - 'A' + 0xa;
    else return 0;
}

static int ipc_request(const char *url, const char *host, const char *ip,
                       const char *urlencoded, char **signature, int *siglen)
{
    /* Common parameters */
    int requestcmd = -1;
    char *requesttype = NULL, *nonce = NULL, *serverTime = NULL, *policys = NULL, *subjects = NULL;
    /* Signing paramters */
    char *messageEncoding = NULL, *message = NULL, *invisibleMessage = NULL;
    /* Result data */
    int errorcode;
    
    /* Parse request content */
    while (*urlencoded && *urlencoded != '\r' && *urlencoded != '\n') {
        char **valueptr = NULL;
        size_t valuelen;
        if (!strncmp(urlencoded, "requestType=", 12)) {
            urlencoded += 12;
            valueptr = &requesttype;
        } else if (!strncmp(urlencoded, "nonce=", 6)) {
            urlencoded += 6;
            valueptr = &nonce;
        } else if (!strncmp(urlencoded, "challenge=", 10)) {
            urlencoded += 10;
            valueptr = &nonce; /* yes, "challenge" is a synonym for "nonce" in this context */
        } else if (!strncmp(urlencoded, "servertime=", 11)) {
            urlencoded += 11;
            valueptr = &serverTime;
        } else if (!strncmp(urlencoded, "policys=", 8)) {
            urlencoded += 8;
            valueptr = &policys;
        } else if (!strncmp(urlencoded, "subjects=", 9)) {
            urlencoded += 9;
            valueptr = &subjects;
        } else if (!strncmp(urlencoded, "textcharacterencoding=", 22)) {
            urlencoded += 22;
            valueptr = &messageEncoding;
        } else if (!strncmp(urlencoded, "texttobesigned=", 15)) {
            urlencoded += 15;
            valueptr = &message;
        } else if (!strncmp(urlencoded, "nonvisibledata=", 15)) {
            urlencoded += 15;
            valueptr = &invisibleMessage;
        /* Ignored parameters and return parameters */
        } else if (!strncmp(urlencoded, "onlyacceptmru=", 14)) {
            urlencoded += 14;
            valueptr = NULL;
        } else if (!strncmp(urlencoded, "signature=", 10)) {
            urlencoded += 10;
            valueptr = NULL;
        } else {
            fprintf(stderr, "unrecognized url encoded data: %s\n", urlencoded);
            break;
        }
        
        
        valuelen = strcspn(urlencoded, "&");
        if (valueptr) {
            char *value = malloc(valuelen+1);
            const char *inp = urlencoded;
            char *outp = value;
            while (*inp && *inp != '&') {
                int val;
                if (*inp == '%' && inp[1] && inp[2]) {
                    val = (unhex(inp[1]) << 4) | unhex(inp[2]);
                    inp += 3;
                } else {
                    val = *inp;
                    inp++;
                }
                if (val <= ' ' || val >= 0x7F || val == ';') {
                    val = '_';
                }
                *outp = val;
                outp++;
            }
            
            *outp = '\0';
            *valueptr = value;
        }
        
        urlencoded += valuelen;
        if (*urlencoded == '&') {
            urlencoded++;
        }
    }
    
    if (!requesttype || !url || !host || !ip) return 20;
    
    if (!strcmp(requesttype, "authenticate")) requestcmd = 2;
    else if (!strcmp(requesttype, "sign")) requestcmd = 3;
    else return 50;
    
    if (requestcmd == 3 && !message) return 30;
    
    if (!serverTime || *serverTime == '\0') {
        serverTime = "0";
    } else if (strspn(serverTime, "0123456789") != strlen(serverTime)) {
        return 60;
    }
    
    /* Send IPC request */
    if (!open_pipes()) {
        return 40;
    }
/*    pipe_out = stderr;
fprintf(stderr, "------\n\n");*/
    fprintf(pipe_out, "%d;\n", requestcmd);
    ipc_send_str(pipe_out, url);
    ipc_send_str(pipe_out, host);
    ipc_send_str(pipe_out, ip);
    
    ipc_send_str(pipe_out, nonce);
    fprintf(pipe_out, "%s;\n", serverTime);
    ipc_send_str(pipe_out, policys);
    ipc_send_str(pipe_out, subjects);
    if (requestcmd == 3) {
        /* Sign */
        ipc_send_str(pipe_out, messageEncoding);
        ipc_send_str(pipe_out, message);
        ipc_send_str(pipe_out, invisibleMessage);
    }
    fprintf(pipe_out, "end\n");
    fflush(pipe_out);
    
    /* Read response */
    errorcode = ipc_read_int(pipe_in);
    *signature = ipc_read_string(pipe_in, siglen);
    
    /* Clean up */
    fclose(pipe_out);
    fclose(pipe_in);
    waitpid(signbinary_pid, NULL, 0);
    return errorcode;
}

static ssize_t findnlnl(const char *req, ssize_t from, ssize_t len)
{
    const char *r;
    ssize_t pos = 0;
    
    if (from > 0) {
        r = req+from-1;
        pos = from-1;
        len++;
    } else {
        r = req+from;
        pos = from;
    }
    
    while (len) {
        if (*r == '\n') {
            if (len >= 3 && r[1] == '\r' && r[2] == '\n') return pos+3;
            if (len >= 2 && r[1] == '\n') return pos+2;
        }
        len--;
        pos++;
        r++;
    }
    
    return 0;
}

static void skipws(const char **s, ssize_t *len)
{
    while (*len && (**s == ' ' || **s == '\t')) {
        ++*s;
        --*len;
    }
}

static const char *extract_header(const char *req, ssize_t len, const char *headername)
{
    ssize_t namelen = strlen(headername);
    while (len > 0) {
        if (*req == '\r' || *req == '\n') break;
        if (len <= namelen) break;
        
        if (!strncasecmp(req, headername, namelen)) {
            req += namelen;
            len -= namelen;
            
            skipws(&req, &len);
            if (*req == ':') {
                req++;
                len--;
                skipws(&req, &len);
                return req; /* terminated with a line end, \r\n, \n or \r */
            }
        }
        
        /* skip to end of line */
        while (len && *req != '\r' && *req != '\n') {
            req++;
            len--;
        }
        
        if (len >= 2 && *req == '\r' && req[1] == '\n') {
            req += 2;
            len -= 2;
        } else {
            req++;
            len--;
        }
    }
    return NULL;
}

/* XXX There's an unavoidable race condition in this function.
   The IP address returned might have changed and might not be what the
   browser has connected to. */
static char *get_ip_from_host(const char *hostname)
{
    char ip[NI_MAXHOST];
    const struct addrinfo *ai;
    struct addrinfo *firstai;
    
    int ret = getaddrinfo(hostname, NULL, NULL, &firstai);
    if (ret != 0) return NULL;
    
    /* Find first INET (IPv4) address (BankID supports IPv4 addresses only) */
    ai = firstai;
    while (ai && ai->ai_family != AF_INET)
        ai = ai->ai_next;
    
    if (!ai) return NULL;
    
    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ip, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST) != 0) {
        freeaddrinfo(firstai);
        return NULL;
    }
    freeaddrinfo(firstai);
    
    return strdup(ip);
}

static int handle_req(int sock, char *req, ssize_t len, ssize_t contentlen)
{
    int resultlen;
    
    (void)contentlen; /* unused */
    
    if (!strncasecmp(req, "POST /FriBID_NPAPI_Request HTTP/1.", 34)) {
        int errorcode, siglen, jsonlength;
        char *signature;
        /* Parse headers. Note: these are newline terminated! */
        const char *contenttype = extract_header(req, len, "Content-Type");
        char *origin = (char*)extract_header(req, len, "Origin");
        const char *domain = NULL, *ip = NULL;
        
        if (strncasecmp(contenttype, "application/x-www-form-urlencoded", 33)) {
            goto badreq;
        }
        
        /* Determine host/ip */
        if (origin) {
            origin[strcspn(origin, "\r\n")] = '\0';
            /* This depends on the browser providing reliable data, of course */
            if (!strncmp("https://", origin, 8)) {
                domain = origin+8;
                ip = get_ip_from_host(domain);
            }
        }
        
        /* Parse content */
        signature = NULL;
        siglen = 0;
        errorcode = ipc_request(origin, domain, ip,
                                req+len, &signature, &siglen);
        
        jsonlength = sprintf(result, "%d", errorcode) + siglen + 49;
        
        resultlen = sprintf(result,
            "HTTP/1.0 200 Ok\r\n"
            "Access-Control-Allow-Headers: content-type\r\n"
            "Access-Control-Allow-Methods: POST\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: keep-alive\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: text/json\r\n"
            "\r\n"
            "{ \"errorCode\": %d, \"params\": { \"signature\": \"%.*s\" } }\n",
            jsonlength, errorcode, siglen, signature);
    } else if (!strncasecmp(req, "OPTIONS ", 8)) {
        resultlen = sprintf(result,
            "HTTP/1.0 200 Ok\r\n"
            "Access-Control-Allow-Headers: content-type\r\n"
            "Access-Control-Allow-Methods: POST\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Allow: POST\r\n"
            "Connection: keep-alive\r\n"
            "Content-Length: 0\r\n"
            "\r\n");
    } else {
      badreq:
        resultlen = sprintf(result,
            "HTTP/1.0 400 Bad Request\r\n"
            "Connection: keep-alive\r\n"
            "Content-Length: 12\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "Bad Request\n");
    }
    
    
    if (send(sock, result, resultlen, 0) == -1) {
        perror("failed to send data");
    }
    return 1;
}

static int extract_contentlength(const char *req, ssize_t len)
{
    const char *value = extract_header(req, len, "Content-Length");
    return value ? atoi(value) : 0;
}

static void handle_connection(int sock)
{
    ssize_t bytesrecv = 0;
    
    while (1) {
        ssize_t nbytes = recv(sock, &request[bytesrecv], 4096-bytesrecv, 0);
        ssize_t reqend;
        if (nbytes == -1) {
            perror("failed to receive data");
            return;
        }
        
        if (nbytes == 0) return;
        
        reqend = findnlnl(request, bytesrecv, nbytes);
        bytesrecv += nbytes;
        if (reqend) {
            /* Read request body (if any) */
            int contentlength = extract_contentlength(request, reqend);
            if (contentlength > 90*1024) {
                int resultlen = sprintf(result,
                    "HTTP/1.0 413 Request Entity Too Large\r\n"
                    "Connection: close\r\n"
                    "Content-Length: 23\r\n"
                    "Content-Type: text/html\r\n"
                    "\r\n"
                    "Request Body Too Large\n");
                
                if (send(sock, result, resultlen, 0) == -1) {
                    perror("failed to send data");
                }
                return;
            }
            
            while (bytesrecv-reqend < contentlength) {
                ssize_t nbytes = recv(sock, &request[bytesrecv], contentlength-bytesrecv+reqend, 0);
                if (nbytes == -1) {
                    perror("failed to receive data");
                    return;
                }
                if (nbytes == 0) return;
                bytesrecv += nbytes;
            }
            request[reqend+contentlength] = '\0';
            
            /* Process the request */
            if (!handle_req(sock, request, reqend, contentlength)) {
                return;
            }
            memmove(request, request+reqend, bytesrecv-reqend);
            bytesrecv -= reqend+contentlength;
        }
    }
}

#define NUM_COMMON_PATHS 8
static const char *common_fribid_paths[NUM_COMMON_PATHS] = {
    "/usr/lib/fribid/sign",
    "/usr/local/lib/fribid/sign",
    "/usr/lib/x86_64-linux-gnu/fribid/sign",
    "/usr/local/lib/x86_64-linux-gnu/fribid/sign",
    "/usr/lib64/fribid/sign",
    "/usr/local/lib64/fribid/sign",
    "/usr/lib/i386-linux-gnu/fribid/sign",
    "/usr/local/lib/i386-linux-gnu/fribid/sign"
};

int main(int argc, const char **argv)
{
    int srvsock, opt, i;
    struct stat typecheck;
    struct sockaddr_in addr;
    
    /* Check arguments */
    if (argc > 2 || (argc > 1 && argv[1][0] == '-')) {
        printf("Usage: %s [path_to_signing_binary]\n\n"
               "For example:\n", argv[0]);
        for (i = 0; i < NUM_COMMON_PATHS; i++) {
            char exists = access(common_fribid_paths[i], X_OK) == 0 ? 'X' : ' ';
            printf(" <%c>  %s %s\n", exists, argv[0], common_fribid_paths[i]);
        }
        printf("\n<X> = exists on your system\n");
        return 1;
    }
    
    if (argc == 2) {
        if (access(argv[1], X_OK) != 0) {
            perror(argv[1]);
            return 1;
        }
        ipc_argv[0] = argv[1];
    } else {
        /* Try to autodetect path */
        for (i = 0; i < NUM_COMMON_PATHS; i++) {
            if (access(common_fribid_paths[i], X_OK) == 0) {
                ipc_argv[0] = common_fribid_paths[i];
                break;
            }
        }
        
        if (!ipc_argv[0]) {
            fprintf(stderr, "%s: failed to autodetect path to the FriBID \"sign\" binary.\n", argv[0]);
            return 1;
        }
    }
    
    /* Check that it's not e.g. a directory */
    if (stat(ipc_argv[0], &typecheck) == -1) {
        perror("failed to stat signing binary");
        return 1;
    }
    if (!S_ISREG(typecheck.st_mode)) {
        fprintf(stderr, "%s: Signing binary must be a regular executable file\n", ipc_argv[0]);
        return 1;
    }
    
    printf("Using binary: %s\n", ipc_argv[0]);
    
    /* Start the server */
    srvsock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srvsock == -1) {
        perror("failed to create socket");
        return 1;
    }
    
    opt = 1;
    if (setsockopt(srvsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("failed to set socket options");
        close(srvsock);
        return 1;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(20048);
    addr.sin_addr.s_addr = htonl(0x7F000001L);
    if (bind(srvsock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("failed to bind port/address");
        close(srvsock);
        return 1;
    }
    
    if (listen(srvsock, 50) == -1) {
        perror("failed to listen on socket");
        close(srvsock);
        return 1;
    }
    
    printf("Server started on port %d\n", ntohs(addr.sin_port));
    while (1) {
        pid_t pid;
        struct sockaddr connaddr;
        socklen_t connaddrlen = sizeof(connaddr);
        int connsock = accept(srvsock, &connaddr, &connaddrlen);
        
        if (connsock == -1) {
            perror("failed to set socket options");
            close(srvsock);
            return 1;
        }
        
        pid = fork();
        if (connsock == -1) {
            perror("failed to fork");
            close(connsock);
            continue;
        }
        
        if (pid != 0) {
            waitpid(pid, NULL, WNOHANG);
            continue;
        }
        
        /* This is executed in the forked process */
        close(srvsock);
        
        handle_connection(connsock);
        close(connsock);
        exit(0);
    }
}

