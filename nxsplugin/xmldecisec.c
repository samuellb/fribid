#define _BSD_SOURCE 1

#include <string.h>
#include <stdlib.h>

#include <sechash.h>
#include <hasht.h>

#include "keyfile.h"
#include "xmldecisec.h"

static const char *xmldsec_template = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
            "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\">"
            "</CanonicalizationMethod>"
            "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\">"
            "</SignatureMethod>"
            "%s"
        "</SignedInfo>"
        "<SignatureValue>%s</SignatureValue>"
        "%s"
        "<Object>%s</Object>"
    "</Signature>";

static const char *references_template =
    "<Reference Type=\"http://www.bankid.com/signature/v1.0.0/types\" URI=\"#bidSignedData\">"
        "<Transforms>"
            "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></Transform>"
        "</Transforms>"
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>"
        "<DigestValue>%s</DigestValue>"
    "</Reference>"
    "<Reference URI=\"#bidKeyInfo\">"
        "<Transforms>"
            "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></Transform>"
        "</Transforms>"
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>"
        "<DigestValue>%s</DigestValue>"
    "</Reference>";

static const char *keyinfo_template =
    "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"bidKeyInfo\">"
        "<X509Data>%s</X509Data>"
    "</KeyInfo>";

static const char *cert_template =
    "<X509Certificate>%s</X509Certificate>";

static char *sha_base64(const char *str) {
    char shasum[SHA256_LENGTH];
    
    HASH_HashBuf(HASH_AlgSHA256, shasum, (unsigned char*)str, strlen(str));
    return base64_encode(shasum, sizeof(shasum));
}

char *xmldsec_sign(const char *p12Data, const int p12Length,
                   const char *person, const unsigned int certMask, const char *password,
                   const char *dataId, const char *data) {
    
    // Keyinfo
    char **certs;
    int certCount;
    if (!keyfile_getBase64Chain(p12Data, p12Length, person, certMask, &certs, &certCount)) {
        return NULL;
    }
    
    int certsLength = (strlen(cert_template)-2) * certCount;
    for (int i = 0; i < certCount; i++) {
        certsLength += strlen(certs[i]);
    }
    
    char *keyinfoInner = malloc(certsLength+1);
    keyinfoInner[0] = '\0';
    char *keyend = keyinfoInner;
    for (int i = 0; i < certCount; i++) {
        keyend += sprintf(keyend, cert_template, certs[i]);
    }
    
    char *keyinfo = malloc(strlen(keyinfo_template) - 2 + certsLength +1);
    sprintf(keyinfo, keyinfo_template, keyinfoInner);
    
    // References
    char *data_sha = sha_base64(data);
    char *keyinfo_sha = sha_base64(keyinfo);
    
    char *references = malloc(strlen(references_template) - 2*2 +
                              strlen(data_sha) + strlen(keyinfo_sha) +1);
    sprintf(references, references_template, data_sha, keyinfo_sha);
    free(keyinfo_sha);
    free(data_sha);
    
    // Signature
    char *signature = strdup(""); // TODO
    
    // Glue everything together
    char *complete = malloc(strlen(xmldsec_template) - 4*2 +
                            strlen(references) + strlen(signature) +
                            strlen(keyinfo) + strlen(data) +1);
    sprintf(complete, xmldsec_template,
            references, signature, keyinfo, data);
    
    free(keyinfo);
    free(references);
    free(signature);
    
    return complete;
}

