#ifndef __KEYFILE_H__
#define __KEYFILE_H__

#include <stdbool.h>

#define CERTUSE_ISSUER            6
#define CERTUSE_SIGNING          64
#define CERTUSE_AUTHENTICATION  128

char *base64_encode(const char *data, const int length);

void keyfile_init();
void keyfile_shutdown();

bool keyfile_listPeople(const char *data, const int datalen,
                         char ***people, int *count);
char *keyfile_getDisplayName(const char *person);
bool keyfile_getBase64Chain(const char *data, const int datalen,
                            const char *person, const unsigned int certMask,
                            char ***certs, int *count);

bool keyfile_sign(const char *data, const int datalen,
                  const char *person, const unsigned int certMask, const char *password,
                  const char *message, const int messagelen,
                  char **signature, int *siglen);

#endif


