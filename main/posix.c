#define _BSD_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>

#include "platform.h"

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



