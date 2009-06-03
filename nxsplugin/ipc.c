#define _BSD_SOURCE 1
#define _POSIX_C_SOURCE 199309
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>

#include <base64.h> // from npapi

#include "plugin.h"
#include "ipc.h"

static void verifySocket();

/* * * *  Low-level socket I/O  * * * */
static int sock = -1;

#define SENDFLAGS (0)
#define RECVFLAGS (0)

static int sendpacket(const char *data, int len) {
    char packet[4+len];
    
    assert(sizeof(int) == 4);
    memcpy(packet, &len, 4);
    memcpy(&packet[4], data, len);
    
    return send(sock, packet, 4+len, SENDFLAGS);
}

static int sendchar(char ch) {
    return send(sock, &ch, 1, SENDFLAGS);
}

static char recvchar() {
    char ch;
    return (recv(sock, &ch, 1, RECVFLAGS) ==  1 ? ch : '\0');
}

static int recvpacket(int *len, char **packet) {
    if (recv(sock, len, 4, RECVFLAGS) != 4) return -1;
    
    *packet = malloc(*len);
    if (recv(sock, *packet, *len, RECVFLAGS) != *len) return -1;
    
    return 4+*len;
}

static void dumpPacket(const char *filename, char *packet, int len) {
    FILE *dump = fopen(filename, "wb");
    fwrite(packet, len, 1, dump);
    fclose(dump);
}

#define SOCKET_MAXLEN 107
#define NEXUS_EXECUTABLE "/usr/local/lib/personal/personal.sh"

static void startNexus() {
    pid_t nexus = fork();
    if (nexus == 0) {
        execl(NEXUS_EXECUTABLE, NEXUS_EXECUTABLE);
        exit(1);
    }
    waitpid(-1, NULL, WNOHANG);
}

static void disconnect() {
    close(sock);
    sock = -1;
}

static bool isConnected() {
    char dummy;
    int len = recv(sock, &dummy, sizeof(char), MSG_DONTWAIT | MSG_PEEK);
    if (len == 0) return false;      // Socket is closed
    else if (len == 1) return true;  // There's data (not closed)
    else return (errno == EAGAIN); // EAGAIN = no data, but the socket is open
}

static void verifySocket() {
    if (sock != -1) {
        if (isConnected()) return;
        else close(sock);
    }
    
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        return;
    }
    
    int tries = 0;
    while (true) {
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        addr.sun_path[0] = '\0';
        strncat(addr.sun_path, getenv("HOME"), SOCKET_MAXLEN);
        strncat(addr.sun_path, "/.personal/.wxsrv424", SOCKET_MAXLEN);
        addr.sun_path[SOCKET_MAXLEN] = '\0';
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
            if (tries == 0) {
                // Maybe Nexus isn't running
                startNexus();
            } else if (tries > 10) {
                // Timeout
                disconnect();
                return;
            }
            tries++;
            struct timespec delay = { 0, 200000000 };
            nanosleep(&delay, NULL);
        } else {
            break;
        }
    }
    
    sendchar('\n');
    sendpacket("IPC TEST", 8);
    
    if (recvchar(sock) != '\n') {
        disconnect();
        return;
    }
}


/* * * *  Javascript API functions * * * */

/* Version objects */
char *version_getVersion(Plugin *plugin) {
    verifySocket();
    
    sendchar('\2');
    sendpacket("AAAAAQAAAAoAAAAIAAAAAQAAAAA=", 28);
    sendchar('\1');
    
    if (recvchar(sock) != '\10') {
        plugin->lastError = PE_UnknownError;
        return strdup("");
    }
    
    int len;
    char *packet;
    recvpacket(&len, &packet);
    if (packet[len] == '\0') len--;
    
    if ((unsigned int)len >= 64000) {
        // Packet too large
        free(packet);
        plugin->lastError = PE_UnknownError;
        return strdup("");
    }
    
    char *data = (char*)ATOB_AsciiToData(packet, (unsigned int*)&len);
    free(packet);
    
    sendchar('\v'); // Makes Nexus close the socket (the original plugin does this)
    
    // Packet format:
    // 
    //  4 bytes     Unknown BE uint32, 1 in dump
    //  4 bytes     Unknown BE uint32, 0xB  in dump
    //  4 bytes     Unknown BE uint32, 0x13C in dump
    //  4 bytes     Unknown BE uint32, 1 in dump
    //  4 bytes     Length BE uint32
    //  the rest    Version string
    
    if (len < 5*4) {
        // Packet too small
        free(packet);
        plugin->lastError = PE_UnknownError;
        return strdup("");
    }
    
    int versionLength = len - 5*4;
    char *versionString = malloc(versionLength+1);
    memcpy(versionString, &data[5*4], versionLength);
    versionString[versionLength+1] = '\0';
    
    free(packet);
    return versionString;
}




