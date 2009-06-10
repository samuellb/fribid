#define _BSD_SOURCE 1
#include <string.h>
#include <base64.h>

#include "misc.h"

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

#include <stdio.h>
char *base64_decode(const char *encoded) {
    unsigned int length;

    char *temp = (char*)ATOB_AsciiToData(encoded, &length);
    if (!temp) return NULL;
    char *result = malloc(length+1);
    memcpy(result, temp, length);
    result[length] = '\0';
    free(temp);
    
    if (length != strlen(result)) {
        return NULL;
    }
    return result;
}

bool is_canonical_base64(const char *encoded) {
    char *decoded = base64_decode(encoded);
    if (!decoded) return false;
    
    char *recoded = base64_encode(decoded, strlen(decoded));
    
    fprintf(stderr, " '%s' == '%s'  ?  %d\n", encoded, recoded, !strcmp(recoded, encoded));
    bool equal = !strcmp(recoded, encoded);
    
    free(recoded);
    free(decoded);
    return equal;
}

bool is_valid_domain_name(const char *domain) {
    static const char *allowed = "abcdefghijklmnopqrstuvwxyz0123456789-.";
    return (strspn(domain, allowed) == strlen(domain));
}

bool is_valid_ip_address(const char *ip) {
    static const char *allowed = "0123456789abcdef.[]:";
    return (strspn(ip, allowed) == strlen(ip));
}

bool is_valid_hostname(const char *hostname) {
    return is_valid_domain_name(hostname) || is_valid_ip_address(hostname);
}

bool is_https_url(const char *url) {
    return !strncmp(url, "https://", 8);
}



