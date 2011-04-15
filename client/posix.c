/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
 
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../common/defines.h"
#include "misc.h"
#include "platform.h"

void platform_seedRandom() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    srand(tv.tv_sec ^ tv.tv_usec ^ getpid());
}

struct PlatformDirIter {
    DIR *dir;
    char *path;
    struct dirent *entry;
};

/**
 * Opens a file and locks it for reading or writing. If Platform_OpenCreate
 * is specified as the mode then the file is created, and the function fails
 * if it already exists to prevent overwrites and race conditions.
 *
 * @param mode  Either Platform_OpenRead or Platform_OpenCreate
 */
FILE *platform_openLocked(const char *filename, PlatformOpenMode mode) {
    static const char *const stdio_modes[] = { "rb", "wb" };
    static const int open_flags[] = { O_RDONLY, O_WRONLY|O_CREAT|O_EXCL };
    static const int lock_flags[] = { LOCK_SH, LOCK_EX };
    
    int fd = open(filename, open_flags[mode], 0600);
    if (fd == -1) return NULL;
    
    if (flock(fd, lock_flags[mode]) != 0) {
        close(fd);
        return NULL;
    }
    
    return fdopen(fd, stdio_modes[mode]);
}

bool platform_closeLocked(FILE *file) {
    flock(fileno(file), LOCK_UN);
    return (fclose(file) == 0);
}

bool platform_deleteLocked(FILE *file, const char *filename) {
    bool deleted = (remove(filename) == 0);
    return platform_closeLocked(file) && deleted;
}

bool platform_readFile(const char *filename, char **data, int *length) {
    FILE *file = platform_openLocked(filename, Platform_OpenRead);
    if (!file) return false;
    if (fseek(file, 0, SEEK_END) == -1) {
        platform_closeLocked(file);
        return false;
    }
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);
    *data = malloc(*length);
    bool ok = (fread(*data, *length, 1, file) == 1);
    platform_closeLocked(file);
    return ok;
}

PlatformDirIter *platform_openDir(const char *pathname) {
    PlatformDirIter *iter = malloc(sizeof(PlatformDirIter));
    iter->dir = opendir(pathname);
    if (!iter->dir) {
        free(iter);
        return NULL;
    }
    
    iter->path = strdup(pathname);
    iter->entry = NULL;
    return iter;
}

bool platform_iterateDir(PlatformDirIter *iter) {
    // Read until a visible file is found
    do {
        iter->entry = readdir(iter->dir);
    } while (iter->entry && (iter->entry->d_name[0] == '.'));
    return (iter->entry != NULL);
}

char *platform_currentName(PlatformDirIter *iter) {
    return strdup(iter->entry->d_name);
}

char *platform_currentPath(PlatformDirIter *iter) {
    char *path = malloc(strlen(iter->path) + strlen(iter->entry->d_name) + 2);
    strcpy(path, iter->path);
    strcat(path, "/");
    strcat(path, iter->entry->d_name);
    return path;
}

void platform_closeDir(PlatformDirIter *iter) {
    closedir(iter->dir);
    free(iter->path);
    free(iter);
}

#define NUM_PATHS 2
void platform_keyDirs(char*** path, size_t* len) {
    static const char suffix[] = "cbt";
    static const char hidden_suffix[] = ".cbt";
    static char *paths[NUM_PATHS];
    *len = (NUM_PATHS - 1);
    *path = paths;
    paths[0] = malloc(strlen(getenv("HOME")) + strlen(suffix) + 2);
    sprintf(paths[0], "%s/%s", getenv("HOME"), suffix);

    paths[1] = malloc(strlen(getenv("HOME")) + strlen(hidden_suffix) + 2);
    sprintf(paths[1], "%s/%s", getenv("HOME"), hidden_suffix);
}

PlatformDirIter *platform_openKeysDir(char *path) {
    PlatformDirIter *iter = platform_openDir(path);
    return iter;
}

/**
 * Removes illegal characters from a filename.
 *
 * Returns NULL if the file name contains no legal characters.
 */
char *platform_filterFilename(const char *filename) {
    // TODO remove invalid UTF-8 characters somewhere?
    //      (maybe after decoding the base64 encoded input?)
    
    // Hidden files are not allowed
    while (*filename == '.') filename++;
    
    // Strip out illegal characters
    char *result = malloc(strlen(filename)+1);
    char *p = result;
    char c;
    bool lastWasSpace = true;
    while ((c = *(filename++)) != '\0') {
        // Control chars
        if (c >= '\0' && c < ' ') c = ' ';
        
        // File system and shell characters
        if (strchr("/\\:\"'$*?~&|#!;`", c)) c = '_';
        if (c == '{' || c == '[') c = '(';
        if (c == '}' || c == '}') c = ')';
        
        // Remove repeated spaces and leading space
        bool isSpace = (c == ' ');
        if (lastWasSpace && isSpace) continue;
        lastWasSpace = isSpace;
        
        *(p++) = c;
    }
    
    *p = '\0';
    return result;
}

/**
 * Makes a filename for a new certificate with a given name. This function
 * is removes all dangerous special characters from nameAttr.
 *
 * The key store directory is created if needed.
 */
char *platform_getFilenameForKey(const char *nameAttr) {
    char *basename = platform_filterFilename(nameAttr);
    
    // Get key store path
    size_t numPaths;
    char **paths;
    platform_keyDirs(&paths, &numPaths);
    
    // Create directories
    // TODO
    
    // Merge
    char *filename = rasprintf("%s/%s.p12", paths[0], basename);
    free(basename);
    return filename;
}

void platform_asyncCall(AsyncCallFunction *function, void *param) {
    pid_t child = fork();
    if (child == -1) {
        // Call the function synchronously instead
        function(param);
    } else if (child == 0) {
        // This is done asynchronously
        function(param);
        exit(0);
    } else {
        // "Dereference" the process id
        waitpid(-1, NULL, WNOHANG);
    }
}

/**
 * Looks up an A record, and returns it as an 32-bit integer.
 * Useful for API:s that use DNS.
 */
uint32_t platform_lookupTypeARecord(const char *hostname) {
    assert(hostname != NULL);
    
    const struct addrinfo hints = {
        .ai_flags = 0,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *ai;
    
    if (getaddrinfo(hostname, NULL, &hints, &ai) != 0) {
        return 0;
    }
    
    if (ai == NULL) return 0;
    
    uint32_t arecord = 0;
    if (ai->ai_addr && ai->ai_addr->sa_family == AF_INET) {
        arecord = ntohl(((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr);
    }
    
    freeaddrinfo(ai);
    return arecord;
}


