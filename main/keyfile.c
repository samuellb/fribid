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

static char *SEC_GetPasswordString(FILE *in, FILE *out, const char *prompt, int mode) {
    fputs(prompt, out);
    char *pw = malloc(100);
    fgets(pw, 100, in);
    pw[strlen(pw)-1] = '\0';
    return pw;
}

// Borrowed from secutil.c from Mozilla. This code will be removed later
static char *SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char prompt[255];
    secuPWData *pwdata = (secuPWData *)arg;
    secuPWData pwnull = { PW_NONE, 0 };
    secuPWData pwxtrn = { PW_EXTERNAL, "external" };

    fprintf(stderr, "GET PASSWORD CALLED!\n");
    
    if (pwdata == NULL)
        pwdata = &pwnull;

    if (PK11_ProtectedAuthenticationPath(slot)) {
        pwdata = &pwxtrn;
    }
    if (retry && pwdata->source != PW_NONE) {
        fprintf(stderr, "Incorrect password/PIN entered.\n");
        return NULL;
    }

    switch (pwdata->source) {
    case PW_NONE:
        sprintf(prompt, "Enter Password or Pin for \"%s\":",
                         PK11_GetTokenName(slot));
        return SEC_GetPasswordString(stdin, stdout, prompt, 1337);
    case PW_FROMFILE:
        abort();
    case PW_EXTERNAL:
        sprintf(prompt,
                "Press Enter, then enter PIN for \"%s\" on external device.\n",
                PK11_GetTokenName(slot));
        (void) SEC_GetPasswordString(stdin, stdout, prompt, 1337);
        // Fall Through
    case PW_PLAINTEXT:
        return strdup(pwdata->data);
    default:
        break;
    }

    fprintf(stderr, "Password check failed:  No password found.\n");
    return NULL;
}

void keyfile_init() {
    //PK11_SetPasswordFunc(SECU_GetModulePassword);
    
    //PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    //if (NSS_NoDB_Init("") != SECSuccess) {
    // NSS_INIT_NOCERTDB maybe?
    if (NSS_Initialize("/home/samuellb/Projekt/e-leg/main/testdb", "", "", "secmod.db",
            NSS_INIT_NOMODDB | NSS_INIT_NOROOTINIT) != SECSuccess) {
        fprintf(stderr, "initialization failed!\n");
    }
    
    SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
    SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
    SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
    SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);
    
    //dummy
    //(void)PK11_IsFIPS();
    
    fprintf(stderr, "need used init = %d\n", PK11_NeedUserInit(PK11_GetInternalSlot()));
}

void keyfile_shutdown() {
    NSS_Shutdown();
    PR_Cleanup();
}

static SEC_PKCS12DecoderContext *pkcs12_open(const char *data, const int datalen,
                                          const char *password) {
    
    secuPWData dummy = { PW_NONE, NULL };
    
    // "Key" is important here, otherwise things will silently fail later on
    //PK11SlotInfo *slot = PK11_GetInternalSlot();
    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (!slot) {
        fprintf(stderr, "got NULL slot\n");
    }
    
    if (PK11_NeedUserInit(slot)) {
        fprintf(stderr, "Need User Init => this will fail...\n");
        //SECU_ChangePW(slot, PR_FALSE, &dummy):
        //PK11_InitPin(slot, NULL, "");
        // This doesn't seem to help
        if (PK11_InitPin(slot, NULL, "") != SECSuccess) {
            fprintf(stderr, "FAILED TO SET PIN\n");
        }
    }
    
    if (PK11_Authenticate(slot, PR_TRUE, &dummy) != SECSuccess) {
        fprintf(stderr, "failed to auth slot.\n");
    }
    
    // Convert the password to UCS2
    SECItem *passwordItem = SECITEM_AllocItem(NULL, NULL, 2*(strlen(password)+1));
    if (!PORT_UCS2_UTF8Conversion(PR_TRUE, (unsigned char*)password, strlen(password)+1,
                                  passwordItem->data, passwordItem->len,
                                  &passwordItem->len)) {
    //if (!PORT_UCS2_ASCIIConversion(PR_TRUE, (unsigned char*)password, strlen(password),
    //                               passwordItem->data, passwordItem->len,
    //                               &passwordItem->len, PR_TRUE)) {
        fprintf(stderr, "conversion error\n");
        return NULL;
    }
    //passwordItem->type = siBMPString;
    
    /*for (int i = 2*strlen(password); i >= 0; i -= 2) {
        char first = passwordItem->data[i];
        passwordItem->data[i] = passwordItem->data[i+1];
        passwordItem->data[i+1] = first;
    }*/
    
    if (passwordItem->len >= 2)
        fprintf(stderr, "new length: %d.  start: %hx %hx\n", passwordItem->len, passwordItem->data[0], passwordItem->data[1]);
    
    SEC_PKCS12DecoderContext *decoder = SEC_PKCS12DecoderStart(
            passwordItem, slot, &dummy, NULL, NULL, NULL, NULL, NULL);
    
    if (!decoder)
        return NULL;
    
    fprintf(stderr, "initial error: %d\n", PR_GetError());
    
    // Put the data into the decoder
    if (SEC_PKCS12DecoderUpdate(decoder, (unsigned char*)data, datalen) != SECSuccess)
        return NULL;
    
    fprintf(stderr, " decoder verify: %d\n", (SEC_PKCS12DecoderVerify(decoder) == SECSuccess));
    fprintf(stderr, " last error: %d\n", PR_GetError());
    
    // -8113
    //SEC_ERROR_PKCS12_INVALID_MAC 		    =	(SEC_ERROR_BASE + 79)  = -8113
    // This can mean that the password is invalid.
    
    //SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM != -8113
    
    // Maybe it needs some initialization?
    
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

/*static void pkcs12_dump(char *data, const int datalen) {
    
    CERTCertList *certList = pkcs12_listCerts(data, datalen);
    
    if (!certList) {
        fprintf(stderr, "Failed to list certs\n");
        return;
    }
    
    for (CERTCertListNode *node = CERT_LIST_HEAD(certList);
         !CERT_LIST_END(node, certList); node = CERT_LIST_NEXT(node)) {
        
        const CERTCertificate *cert = node->cert;
        
        printf("Found cert:\n    issuer=\"%s\"\n    subject=\"%s\"\n    usage=\"%d\"\n\n",
               cert->issuerName, cert->subjectName, cert->keyUsage);
       
        char *encoded = der_encode(cert);
        if (encoded) printf("    encoded=%s\n", encoded);
        free(encoded);
    }
    
    CERT_DestroyCertList(certList);
}*/

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


/*static char *findFriendlyNameOfPerson(SEC_PKCS12DecoderContext *decoder,
                                      const char *person, const unsigned int certMask) {
    
    if (SEC_PKCS12DecoderIterateInit(decoder) != SECSuccess) {
        pkcs12_close(decoder);
        return NULL;
    }
    
    const SEC_PKCS12DecoderItem *item;
    while (SEC_PKCS12DecoderIterateNext(decoder, &item) == SECSuccess) {
        if (item->type != SEC_OID_PKCS12_V1_CERT_BAG_ID || !item->der) continue;
        
        CERTCertificate *cert = CERT_NewTempCertificate(
                CERT_GetDefaultCertDB(), item->der, NULL, PR_FALSE, PR_TRUE);
        
        if (((cert->keyUsage & certMask) == certMask) &&
             !strcmp(cert->subjectName, person)) {
            CERT_FreeCertificate(cert);
            return strdup(item->friendlyName);
        }
        CERT_FreeCertificate(cert);
    }
    
    return NULL;
}*/

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
    
    //SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID
    
    //char *friendlyName = findFriendlyNameOfPerson(decoder, person, certMask);
    //fprintf(stderr, "friendly name: %s\n", friendlyName);
    //free(friendlyName);
    
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
            //SECKEYPrivateKey *privkey = PK11_FindKeyByAnyCert(node->cert, &dummy);
            SECKEYPrivateKey *privkey = PK11_FindPrivateKeyFromCert(PK11_GetInternalKeySlot(), node->cert, &dummy);
            if (!privkey) {
                CERT_DestroyCertList(certList);
                return false;
            }
            
            fprintf(stderr, "found privkey! %p\n", (void*)privkey);
            //fprintf(stderr, "extract pub key = %p\n", (void*)CERT_ExtractPublicKey(node->cert));
            
            //PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
            
            SECItem result = { siBuffer, NULL, 0 };
            fprintf(stderr, "message = %p  messagelen = %d\n", message, messagelen);
            fprintf(stderr, "message = %*s\n", messagelen, message);
/*            if (SEC_DerSignData(arena, &result, (unsigned char *)message, messagelen, privkey,
//                                SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION) != SECSuccess) {
                                SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE) != SECSuccess) {*/
            if (SEC_SignData(&result, (unsigned char *)message, messagelen, privkey,
                             SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE) != SECSuccess) {
                fprintf(stderr, "failed to sign data!\n");
                SECKEY_DestroyPrivateKey(privkey);
                //PORT_FreeArena(arena, PR_TRUE);
                CERT_DestroyCertList(certList);
                return false;
            }
            
            fprintf(stderr, "destroy key\n");
            SECKEY_DestroyPrivateKey(privkey);
            
            fprintf(stderr, "copy over\n");
            *signature = malloc(result.len);
            memcpy(*signature, result.data, result.len);
            *siglen = result.len;
            fprintf(stderr, "free item\n");
            SECITEM_FreeItem(&result, PR_FALSE);
            
            //PORT_FreeArena(arena, PR_TRUE);
            CERT_DestroyCertList(certList);
            return true;
        }
    }
    
    fprintf(stderr, "NO privkey found...\n");
    CERT_DestroyCertList(certList);
    return false;
}

/*int main(int argc, char **argv) {
    
    keyfile_init();
    
    FILE *file = fopen("hej.p12", "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *data = malloc(size);
    if (fread(data, size, 1, file) == 1) {
        if (argc <= 1) {
            // List people
            char **people;
            int count;
            if (keyfile_listPeople(data, size, &people, &count)) {
                for (int i = 0; i < count; i++) {
                    printf("person: %s\n", people[i]);
                }
            }
        } else {
            // Show certificate chain
            char **chain;
            int count;
            if (keyfile_getBase64Chain(data, size, argv[1], CERTUSE_AUTHENTICATION, &chain, &count)) {
                for (int i = 0; i < count; i++) {
                    printf("cert: %s\n", chain[i]);
                }
            }
        }
    } else {
        fprintf(stderr, "Failed to read from file\n");
    }
    fclose(file);
    
    keyfile_shutdown();
    return 0;
}*/

