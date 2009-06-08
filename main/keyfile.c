#define _BSD_SOURCE 1

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <pk11func.h>
#include <p12.h>
#include <nss.h>
#include <prinit.h>
#include <p12plcy.h>
#include <ciferfam.h>
#include <cert.h>
#include <base64.h>
#include <secitem.h>
#include <secoid.h>
#include <secport.h>
#include <prerror.h>
#include <secerr.h>
#include <cryptohi.h>

#include "keyfile.h"

typedef struct {
    enum {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;


void keyfile_init() {
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    //if (NSS_NoDB_Init("") != SECSuccess) {
    // NSS_INIT_NOCERTDB maybe?
    if (NSS_Initialize("/home/samuellb/Projekt/e-leg/main/testdb", "", "", "secmod.db",
            NSS_INIT_NOMODDB | NSS_INIT_NOROOTINIT) != SECSuccess) {
        fprintf(stderr, "bankid-se: NSS initialization failed!\n");
    }
    
    SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
    SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
    SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
    SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);
}

void keyfile_shutdown() {
    NSS_Shutdown();
    PR_Cleanup();
}

static SEC_PKCS12DecoderContext *pkcs12_open(const char *data, const int datalen,
                                          const char *password) {
    
    secuPWData dummy = { PW_NONE, NULL };
    
    // "Key" is important here, otherwise things will silently fail later on
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (!slot) {
        fprintf(stderr, "got NULL slot\n");
    }
    
    if (PK11_NeedUserInit(slot)) {
        fprintf(stderr, "Need User Init => this will fail...\n");
        // This doesn't seem to help
        if (PK11_InitPin(slot, NULL, "") != SECSuccess) {
            fprintf(stderr, "FAILED TO SET PIN\n");
        }
    }
    
    if (PK11_Authenticate(slot, PR_TRUE, &dummy) != SECSuccess) {
        fprintf(stderr, "bankid-se: failed to auth slot.\n");
    }
    
    // Convert the password to UCS2
    SECItem *passwordItem = SECITEM_AllocItem(NULL, NULL, 2*(strlen(password)+1));
    if (!PORT_UCS2_UTF8Conversion(PR_TRUE, (unsigned char*)password, strlen(password)+1,
                                  passwordItem->data, passwordItem->len,
                                  &passwordItem->len)) {
        fprintf(stderr, "bankid-se: failed to convert password\n");
        return NULL;
    }
    
    SEC_PKCS12DecoderContext *decoder = SEC_PKCS12DecoderStart(
            passwordItem, slot, &dummy, NULL, NULL, NULL, NULL, NULL);
    
    if (!decoder)
        return NULL;
    
    // Put the data into the decoder
    if (SEC_PKCS12DecoderUpdate(decoder, (unsigned char*)data, datalen) != SECSuccess)
        return NULL;
    
    fprintf(stderr, " decoder verify: %d\n", (SEC_PKCS12DecoderVerify(decoder) == SECSuccess));
    fprintf(stderr, " last error: %d\n", PR_GetError());
    
    return decoder;
}

static void pkcs12_close(SEC_PKCS12DecoderContext *decoder) {
    SEC_PKCS12DecoderFinish(decoder);
}

static CERTCertList *pkcs12_listCerts(const char *data, const int datalen) {
    
    SEC_PKCS12DecoderContext *decoder = pkcs12_open(data, datalen, "");
    
    if (!decoder) return NULL;
    
    CERTCertList *certList = SEC_PKCS12DecoderGetCerts(decoder);
    pkcs12_close(decoder);
    return certList;
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

char *base64_encode(const char *data, const int length) {
    if (length == 0) return strdup("");
    
    char *base64 = BTOA_DataToAscii((const unsigned char*)data, length);
    removeNewlines(base64);
    return base64;
}

static char *der_encode(const CERTCertificate *cert) {
    char *base64 = NULL;
    SECItem *item = SEC_ASN1EncodeItem(NULL, NULL, cert, SEC_ASN1_GET(SEC_SignedCertificateTemplate));
    if (item->type == siBuffer) {
        base64 = base64_encode((char*)item->data, item->len);
    }
    SECITEM_FreeItem(item, PR_TRUE);
    return base64;
}

#define CL_each(node, list) \
        (CERTCertListNode *node = CERT_LIST_HEAD(list); \
         !CERT_LIST_END(node, list); node = CERT_LIST_NEXT(node))

bool keyfile_listPeople(const char *data, const int datalen,
                         char ***people, int *count) {
    *count = 0;
    
    CERTCertList *certList = pkcs12_listCerts(data, datalen);
    if (!certList) return false;
    
    for CL_each(node, certList) {
        if (node->cert->keyUsage & CERTUSE_AUTHENTICATION) (*count)++;
    }
    
    *people = malloc(*count * sizeof(char*));
    char **person = *people;
    for CL_each(node, certList) {
        if (node->cert->keyUsage & CERTUSE_AUTHENTICATION) {
            *person = strdup(node->cert->subjectName);
            person++;
        }
    }
    
    CERT_DestroyCertList(certList);
    return true;
}

char *keyfile_getDisplayName(const char *person) {
    const char *name = strstr(person, "OID.2.5.4.41=");
    if (!name) return strdup(person);
    
    name += 13;
    //return strndup(name, strcspn(name, ","));
    int length = strcspn(name, ",");
    char *displayName = malloc(length+1);
    memcpy(displayName, name, length);
    displayName[length] = '\0';
    return displayName;
}

static CERTCertificate *findCert(const CERTCertList *certList,
                                 const char *person, const unsigned int certMask) {
    for CL_each(node, certList) {
        if (((node->cert->keyUsage & certMask) == certMask) &&
             !strcmp(node->cert->subjectName, person)) {
            return node->cert;
        }
    }
    return NULL;
}

bool keyfile_getBase64Chain(const char *data, const int datalen,
                            const char *person, const unsigned int certMask,
                            char ***certs, int *count) {
    
    CERTCertList *certList = pkcs12_listCerts(data, datalen);
    if (!certList) return false;
    
    CERTCertificate *cert = findCert(certList, person, certMask);
    if (!cert) {
        CERT_DestroyCertList(certList);
        return false;
    }
    
    *count = 1;
    *certs = malloc(sizeof(char*));
    (*certs)[0] = der_encode(cert);
    
    while (cert->issuerName != NULL) {
        cert = findCert(certList, cert->issuerName, CERTUSE_ISSUER);
        if (!cert) break;
        
        (*count)++;
        *certs = realloc(*certs, *count * sizeof(char*));
        (*certs)[*count-1] = der_encode(cert);
    }
    CERT_DestroyCertList(certList);
    return true;
}


static SECItem *nicknameCollisionFunction(SECItem *oldNick, PRBool *cancel, void *wincx) {
    CERTCertificate* cert = (CERTCertificate*)wincx;
    
    if (!cert || (cancel == NULL)) {
        fprintf(stderr, "cert or cancel param is NULL\n");
        return NULL;
    }
    
    char *caNick = CERT_MakeCANickname(cert);
    if (!caNick) {
        fprintf(stderr, "no CA nick\n");
        return NULL;
    }
    
    fprintf(stderr, "oldnick: %*s   canick: %s\n", oldNick->len, oldNick->data, caNick);
    if (oldNick && oldNick->data && (oldNick->data != 0) &&
        (oldNick->len == strlen(caNick)) &&
        !strncmp((const char*)oldNick->data, caNick, oldNick->len)) {
        // Equal
        free(caNick);
        PORT_SetError(SEC_ERROR_IO);
        return NULL;
    }
    
    SECItem *item = SECITEM_AllocItem(NULL, NULL, strlen(caNick));
    item->data = (unsigned char*)caNick;
    
    free(caNick);
    return item;
}


bool keyfile_sign(const char *data, const int datalen,
                  const char *person, const unsigned int certMask, const char *password,
                  const char *message, const int messagelen,
                  char **signature, int *siglen) {
    
    assert(data != NULL);
    assert(person != NULL);
    assert(message != NULL);
    assert(password != NULL);
    assert(signature != NULL);
    assert(siglen != NULL);
    
    SEC_PKCS12DecoderContext *decoder = pkcs12_open(data, datalen, password);
    if (!decoder) return false;
    
    if (SEC_PKCS12DecoderValidateBags(decoder, nicknameCollisionFunction) != SECSuccess) {
        fprintf(stderr, "failed to validate the bags. error = %d\n", PR_GetError());
        pkcs12_close(decoder);
        return false;
    }
    
    if (SEC_PKCS12DecoderImportBags(decoder) != SECSuccess) {
        fprintf(stderr, "failed to import \"bags\". error = %d\n", PR_GetError());
        // -8099 = SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY
        //         seems to occur when there's no public key for a private key
/*        pkcs12_close(decoder);
        return false;*/
    }
    CERTCertList *certList = SEC_PKCS12DecoderGetCerts(decoder);
    pkcs12_close(decoder);
    
    for CL_each(node, certList) {
        if (((node->cert->keyUsage & certMask) == certMask) &&
             !strcmp(node->cert->subjectName, person)) {
             
            secuPWData dummy = { PW_NONE, NULL };
            SECKEYPrivateKey *privkey = PK11_FindPrivateKeyFromCert(PK11_GetInternalKeySlot(), node->cert, &dummy);
            if (!privkey) {
                CERT_DestroyCertList(certList);
                return false;
            }
            
            SECItem result = { siBuffer, NULL, 0 };
            if (SEC_SignData(&result, (unsigned char *)message, messagelen, privkey,
                             SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE) != SECSuccess) {
                fprintf(stderr, "failed to sign data!\n");
                SECKEY_DestroyPrivateKey(privkey);
                CERT_DestroyCertList(certList);
                return false;
            }
            
            SECKEY_DestroyPrivateKey(privkey);
            
            *signature = malloc(result.len);
            memcpy(*signature, result.data, result.len);
            *siglen = result.len;
            SECITEM_FreeItem(&result, PR_FALSE);
            
            CERT_DestroyCertList(certList);
            return true;
        }
    }
    
    CERT_DestroyCertList(certList);
    return false;
}

