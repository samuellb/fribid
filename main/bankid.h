#ifndef __BANKID_H__
#define __BANKID_H__

typedef enum {
    BIDERR_OK =               0,
    BIDERR_InternalError =    1,
    BIDERR_UserCancel =    8002,
} BankIDError;

void bankid_init();
void bankid_shutdown();
char *bankid_getVersion();


BankIDError bankid_authenticate(const char *p12Data, const int p12Length,
                                const char *person, const char *password,
                                const char *challenge,
                                const char *hostname, const char *ip,
                                char **signature);

BankIDError bankid_sign(const char *p12Data, const int p12Length,
                        const char *person, const char *password,
                        const char *challenge,
                        const char *hostname, const char *ip,
                        const char *message,
                        char **signature);

#endif

