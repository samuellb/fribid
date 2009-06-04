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

#include "keyfile.h"

void keyfile_init() {
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    NSS_NoDB_Init("/dev/null");
    
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
    
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    SECItem passwordItem;
    passwordItem.data = (unsigned char*)password;
    passwordItem.len = 0;
    
    SEC_PKCS12DecoderContext *decoder = SEC_PKCS12DecoderStart(
            &passwordItem, slot, NULL, NULL, NULL, NULL, NULL, NULL);
    
    if (!decoder)
        return NULL;
    
    // Put the data into the decoder
    if (SEC_PKCS12DecoderUpdate(decoder, (unsigned char*)data, datalen) != SECSuccess)
        return NULL;
    
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

