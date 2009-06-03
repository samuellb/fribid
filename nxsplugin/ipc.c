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
#include <stdint.h>
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

static inline void store_uint32(char *packet, uint32_t value) {
    packet[0] = (char)((value >> 24) & 0xFF);
    packet[1] = (char)((value >> 16) & 0xFF);
    packet[2] = (char)((value >> 8) & 0xFF);
    packet[3] = (char)((value) & 0xFF);
}

static void store_string(char *packet, const char *str, const int length, int *p) {
    store_uint32(&packet[*p], length);
    *p += 4;
    memcpy(&packet[*p], str, length);
    *p += length;
}

static inline uint32_t fetch_uint32(char *packet) {
    return (packet[0] << 24) |
           (packet[1] << 16) |
           (packet[2] << 8) |
            packet[3];
}

// Removes newlines from base64 encoded data
static void removeNewlines(char *s) {
    const char *readp = s;
    char *writep = s;
    
    while (*readp != '\0') {
        if (*readp >= ' ') {
            *writep = *readp;
            writep++;
        }
        readp++;
        
    }
    *writep = '\0';
}

/* * * *  Javascript API functions * * * */

/* Version objects */
char *version_getVersion(Plugin *plugin) {
    verifySocket();
    
    sendchar('\2');
    sendpacket("AAAAAQAAAAoAAAAIAAAAAQAAAAA=", 28);
    sendchar('\1');
    
    if (recvchar() != '\10') {
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
    disconnect();
    
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

/* Authentication objects */
int auth_performAction_Authenticate(Plugin *plugin) {
    verifySocket();
    
    if (!plugin->info.auth.challenge || !plugin->info.auth.policys) {
        plugin->lastError = PE_UnknownError;
        return 1;
    }
    
    const int challengeLength = strlen(plugin->info.auth.challenge);
    const int policysLength = strlen(plugin->info.auth.policys);
    const int urlLength = strlen(plugin->url);
    const int ipLength = strlen(plugin->ip);
    
    const int packetLength = 0x31 + challengeLength +
                             0x19 + policysLength +
                             8 + urlLength +
                             4 + ipLength + 8;
    
    char *packet = calloc(1, packetLength);
    
    store_uint32(&packet[0x0], 1);
    store_uint32(&packet[0x4], 0x14);
    store_uint32(&packet[0x8], packetLength - 12);
    store_uint32(&packet[0xC], 1);
    store_uint32(&packet[0x10], 1);
    store_uint32(&packet[0xC], 1);
    
    int p = 0x2D;
    store_string(packet, plugin->info.auth.policys, policysLength, &p);
    
    p += 0x15;
    store_string(packet, plugin->info.auth.challenge, challengeLength, &p);
    
    p += 0x4;
    store_string(packet, plugin->url, urlLength, &p);
    
    store_string(packet, plugin->ip, ipLength, &p);
    
    packet[p] = 1;
    
    // Encode and send to Nexus Personal
    char *encoded = BTOA_DataToAscii((unsigned char*)packet, packetLength);
    free(packet);
    removeNewlines(encoded);
    
    sendchar('\2');
    sendpacket(encoded, strlen(encoded));
    sendchar('\1');
    free(encoded);
    
    // Get response
    if (recvchar() != '\10') {
        plugin->lastError = PE_UnknownError;
        return 1;
    }
    
    int len;
    recvpacket(&len, &packet);
    if (packet[len-1] == '\0') len--;
    char *data = (char*)ATOB_AsciiToData(packet, (unsigned int*)&len);
    free(packet);
    
    // Parse respose
    if (len < 0x18) {
        plugin->lastError = PE_UnknownError;
        free(data);
        return 1;
    }
    
    int innerLength = fetch_uint32(&data[0x10]);
    if ((innerLength < 0) || (innerLength != len-0x18)) {
        plugin->lastError = PE_UnknownError;
        free(data);
        return 1;
    }
    
    plugin->lastError = fetch_uint32(&data[0x14+innerLength]);
    
    if (plugin->lastError == 0) {
        // No error
        
        // The byte after the encoded result is zero since it's the first
        // byte of the error code. It's used as a null terminator
        plugin->info.auth.signature = strdup(&data[0x14]);
    }
    
    free(data);
    
    // Close IPC channel
    sendchar('\v');
    disconnect();
    
    return 0;
}


