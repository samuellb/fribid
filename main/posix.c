#define _BSD_SOURCE 1
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

#include "../common/defines.h"
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

bool platform_readFile(const char *filename, char **data, int *length) {
    FILE *file = fopen(filename, "rb");
    if (!file) return false;
    if (fseek(file, 0, SEEK_END) == -1) {
        fclose(file);
        return false;
    }
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);
    *data = malloc(*length);
    bool ok = (fread(*data, *length, 1, file) == 1);
    fclose(file);
    return ok;
}

bool platform_deleteFile(const char *filename) {
    return (unlink(filename) == 0);
}

bool platform_deleteDir(const char *filename) {
    return (rmdir(filename) == 0);
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
    path[0] = '\0';
    strcat(path, iter->path);
    strcat(path, "/");
    strcat(path, iter->entry->d_name);
    return path;
}

void platform_closeDir(PlatformDirIter *iter) {
    closedir(iter->dir);
    free(iter->path);
    free(iter);
}

PlatformDirIter *platform_openKeysDir() {
    static const char *suffix = "/cbt";
    
    char *path = malloc(strlen(getenv("HOME")) + strlen(suffix) +1);
    path[0] = '\0';
    strcat(path, getenv("HOME"));
    strcat(path, suffix);
    
    PlatformDirIter *iter = platform_openDir(path);
    free(path);
    return iter;
}

void platform_makeRandomString(char *buff, int length) {
    static const char *randChars =
        "0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    for (int i = 0; i < length; i++) {
        int randVal = rand();
        buff[i] = randChars[(i ^ randVal ^ (randVal >> 6) ^
                             (randVal >> 12) ^ (randVal >> 18)) % 64];
    }
}

static char *makeTempDir(const char *template) {
    
    
    while (true) {
        // Create template
        char randomString[12];
        platform_makeRandomString(randomString, 12);
        
        // Create directory
        char *dir = malloc(strlen(template) - 2 + 12 + 1);
        sprintf(dir, template, randomString);
        
        if (mkdir(dir, S_IRWXU) == 0) {
            return dir;
        }
        
        // Error
        if (errno != EEXIST) return NULL;
    }
}

char *platform_makeMemTempDir() {
    static const char *paths[] = {
        "/dev/shm/" BINNAME "-%s.tmp",
        "/tmp/" BINNAME "-%s.tmp",
        NULL
    };
    
    for (const char **path = paths; *path; path++) {
        char *dir = makeTempDir(*path);
        if (dir) return dir;
    }
    
    return NULL;
}


