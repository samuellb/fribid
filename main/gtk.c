#define _BSD_SOURCE 1
//#undef GDK_DISABLE_DEPRECATED
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>

#include <unistd.h> // For STDIN_FILENO

#include "bankid.h"
#include "keyfile.h"
#include "platform.h"

void platform_init(int *argc, char ***argv) {
    gtk_init(argc, argv);
}

static gboolean pipeCallback(GIOChannel *source,
                             GIOCondition condition, gpointer data) {
    fprintf(stderr, "pipe callback\n");
    ((PlatformPipeFunction*)data)();
    return TRUE;
}

void platform_setupPipe(PlatformPipeFunction *pipeFunction) {
    GIOChannel *stdinChannel = g_io_channel_unix_new(STDIN_FILENO);
    
    g_io_add_watch(stdinChannel,
                   G_IO_IN | G_IO_HUP | G_IO_ERR, pipeCallback, (void*)pipeFunction);
    g_io_channel_unref(stdinChannel);
}

void platform_mainloop() {
    gtk_main();
}

/* Authentication */
void platform_startAuthenticate(const char *url, const char *hostname, const char *ip) {
    // TODO
    fprintf(stderr, "\n----------------------------------------\n"
           "   Authenticating to: %s\n"
           "----------------------------------------\n",
           hostname);
    
    PlatformDirIter *dir = platform_openKeysDir();
    while (platform_iterateDir(dir)) {
        char *filename = platform_currentPath(dir);
        fprintf(stderr, "file %s:\n", filename);
        
        int fileLen;
        char *fileData;
        platform_readFile(filename, &fileData, &fileLen);
        
        int personCount;
        char **people = NULL;
        keyfile_listPeople(fileData, fileLen, &people, &personCount);
        
        for (int i = 0; i < personCount; i++) {
            fprintf(stderr, "    person: %s\n", people[i]);
            free(people[i]);
        }
        free(people);
        
        free(filename);
    }
    platform_closeDir(dir);
}

void platform_endAuthenticate() {
    // TODO
    fprintf(stderr, "\n---[  Thank you  ]----------------------\n\n");
}

static char *getz() {
    static FILE *in = NULL;
    if (!in) in = fdopen(10, "r");
    
    char *str = malloc(100);
    fgets(str, 100, in);
    str[strlen(str)-1] = '\0';
    return str;
}

bool platform_authenticate(char **signature, int *siglen, char **person, char **password) {
    //fprintf(stderr, "Filename: ");
    //char *filename = getz();
    char *filename = strdup("/home/username/cbt/(YYMMDD HH.MM) FIRST FIRSTNAME LAST LASTNAME - BankID pa fil.p12");
    //fprintf(stderr, "opening >%s<\n", filename);
    if (!platform_readFile(filename, signature, siglen)) {
        free(filename);
        return false;
    }
    free(filename);
    
    //fprintf(stderr, "Person: ");
    //*person = getz();
    *person = strdup("CN=FULL NAME,OID.2.5.4.41=(YYMMDD HH.MM) FIRSTNAME LAST LASTNAME - BankID på fil,serialNumber=PERSONAL NUMBER WITH FOUR DIGIT YEAR,givenName=FIRSTNAME MIDDLENAME,SN=LASTNAMES,O=ISSUING BANK (publ),C=COUNRTY CODE");
    
    fprintf(stderr, "Password: ");
    *password = getz();
    
    fprintf(stdout, "\n");
    return true;
}




