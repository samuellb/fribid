#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdbool.h>

/* Initialization */
void platform_init(int *argc, char ***argv);

/* Random number generation */
void platform_seedRandom();
void platform_makeRandomString(char *buff, int length);

/* Pipe I/O */
typedef void (PlatformPipeFunction) ();
void platform_setupPipe(PlatformPipeFunction *pipeFunction);

/* File IO */
bool platform_readFile(const char *filename, char **data, int *length);
bool platform_deleteFile(const char *filename);
bool platform_deleteDir(const char *filename);

typedef struct PlatformDirIter PlatformDirIter;
PlatformDirIter *platform_openDir(const char *pathname);
bool platform_iterateDir(PlatformDirIter *iter);
char *platform_currentName(PlatformDirIter *iter);
char *platform_currentPath(PlatformDirIter *iter);
void platform_closeDir(PlatformDirIter *iter);

PlatformDirIter *platform_openKeysDir();
char *platform_makeMemTempDir();

/* User interface */
void platform_mainloop();

void platform_startSign(const char *url, const char *hostname, const char *ip);
void platform_endSign();
void platform_setMessage(const char *message);
bool platform_sign(char **signature, int *siglen, char **person, char **password);


#endif

