/*

  Copyright (c) 2009-2014 Samuel Lidén Borell <samuel@kodafritt.se>
 
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
#define _XOPEN_SOURCE 600
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
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../common/defines.h"
#include "misc.h"
#include "platform.h"

struct flock file_lock(short ltype);

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
    static const int lock_flags[] = { F_RDLCK, F_WRLCK };

    int fd = open(filename, open_flags[mode], 0600);
    if (fd == -1) return NULL;
    
    struct flock lk = file_lock(lock_flags[mode]);
    if (fcntl(fd, F_SETLKW, &lk) != 0) {
        close(fd);
        return NULL;
    }
    
    return fdopen(fd, stdio_modes[mode]);
}

bool platform_closeLocked(FILE *file) {
    struct flock lk = file_lock(F_UNLCK);
    fcntl(fileno(file), F_SETLK, &lk);
    return (fclose(file) == 0);
}

bool platform_deleteLocked(FILE *file, const char *filename) {
    bool deleted = (remove(filename) == 0);
    return platform_closeLocked(file) && deleted;
}

bool platform_readFile(const char *filename, char **data, int *length) {
    bool ok = false;
    FILE *file = platform_openLocked(filename, Platform_OpenRead);
    if (!file) goto end;
    
    // Determine length of file
    if (fseek(file, 0, SEEK_END) == -1) goto end;
    *length = ftell(file);
    if (*length == -1) goto end;
    
    // Read contents
    if (fseek(file, 0, SEEK_SET) == -1) goto end;
    *data = malloc(*length);
    if (*data) {
        ok = (fread(*data, *length, 1, file) == 1);
    }
    
  end:
    if (file) platform_closeLocked(file);
    return ok;
}

PlatformDirIter *platform_openDir(const char *pathname) {
    PlatformDirIter *iter = malloc(sizeof(PlatformDirIter));
    if (!iter) return NULL;
    iter->dir = opendir(pathname);
    iter->path = strdup(pathname);
    iter->entry = NULL;
    
    if (iter->dir && iter->path) return iter;
    
    // Error
    platform_closeDir(iter);
    return NULL;
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
    return rasprintf("%s/%s", iter->path, iter->entry->d_name);
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
    paths[0] = rasprintf("%s/%s", getenv("HOME"), suffix);
    paths[1] = rasprintf("%s/%s", getenv("HOME"), hidden_suffix);
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
    if (!result) return NULL;
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
    char *filename = NULL;
    
    if (!basename || !*basename) goto end;
    
    // Get key store path
    size_t numPaths;
    char **paths;
    platform_keyDirs(&paths, &numPaths);
    
    // Create directory
    if (mkdir(paths[0], 0700) != 0 && errno != EEXIST) goto end;
    
    // Merge
    filename = rasprintf("%s/%s.p12", paths[0], basename);
    
  end:
    if (basename) free(basename);
    return filename;
}

/**
 * Returns a flock struct used as an argument to fcntl to
 * lock a file.
 */
struct flock file_lock(short ltype) {
    struct flock retval;
    retval.l_type = ltype;
    retval.l_start = 0;
    retval.l_whence = SEEK_SET;
    retval.l_len = 0;
    retval.l_pid = getpid();
    return retval;
}



