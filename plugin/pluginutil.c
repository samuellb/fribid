#define _BSD_SOURCE 1
#define _POSIX_C_SOURCE 200112
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <npapi.h>
#include <npruntime.h>

#include <X11/X.h>

#include "pluginutil.h"

static char *strndup(const char *source, size_t maxLength) {
    size_t i;
    for (i = 0;; i++) {
        if ((i >= maxLength) || (source[i] == '\0')) break;
    }
    
    char *ret = malloc(i+1);
    if (!ret) return NULL;
    memcpy(ret, source, i);
    ret[i] = '\0';
    return ret;
}

/**
 * Creates a new null terminated string from an NPVariant string.
 */
char *variantToStringZ(const NPVariant *variant) {
    return strndup(NPVARIANT_TO_STRING(*variant).utf8characters, NPVARIANT_TO_STRING(*variant).utf8length);
}

// Re-allocates a string with NPN_MemAlloc instead of malloc
static char *npstr(char *source) {
    size_t size = strlen(source)+1;
    char *dest = NULL;
    if (size <= INT32_MAX && (dest = NPN_MemAlloc(size)) != NULL) {
        memcpy(dest, source, size);
    }
    free(source);
    return dest;
}

/**
 * Converts a string to a NPVariant. The original string is freed. If the
 * string pointer is NULL, then the variant is set to the type
 * NPVariantType_Null.
 */
bool convertStringZToVariant(char *string, NPVariant *result) {
    if (!string) {
        NULL_TO_NPVARIANT(*result);
        return true;
    }
    
    // The macro below evaluates it's first parameter twice
    // and npstr frees it's input...
    string = npstr(string);
    if (!string) return false;
    STRINGZ_TO_NPVARIANT(string, *result);
    return true;
}

static bool getProperty(NPP instance, NPObject *obj, const char *name, NPVariant *result) {
    NPIdentifier ident = NPN_GetStringIdentifier(name);
    if (!ident) return NULL;
    return NPN_GetProperty(instance, obj, ident, result);
}

static char *getWindowProperty(NPP instance, const char *const identifiers[]) {
    NPObject *obj;
    
    NPN_GetValue(instance, NPNVWindowNPObject, &obj);
    if (!obj) return NULL;
    
    const char *const *identifier = &identifiers[0];

    while (1) {
        NPVariant value;
        
        bool ok = getProperty(instance, obj, *identifier, &value);
        NPN_ReleaseObject(obj);
        if (!ok) return NULL;
        
        identifier++;
        if (*identifier) {
            // Expecting an object
            if (!NPVARIANT_IS_OBJECT(value)) {
                NPN_ReleaseVariantValue(&value);
                return NULL;
            }
            obj = NPVARIANT_TO_OBJECT(value);
        } else {
            // Expecting a string
            if (!NPVARIANT_IS_STRING(value)) {
                NPN_ReleaseVariantValue(&value);
                return NULL;
            }
            char *url = strndup(NPVARIANT_TO_STRING(value).utf8characters,
                                NPVARIANT_TO_STRING(value).utf8length);
            NPN_ReleaseVariantValue(&value);
            return url;
        }
    }
}

char *getDocumentURL(NPP instance) {
    static const char *const identifiers[] = {
        "document", "location", "href", NULL
    };
    return getWindowProperty(instance, identifiers);
}

char *getDocumentHostname(NPP instance) {
    static const char *const identifiers[] = {
        "document", "location", "hostname", NULL
    };
    return getWindowProperty(instance, identifiers);
}

/**
 * Finds the IP address of the server hosting the document containing the
 * plugin. This IP address is placed in the signature as an additional
 * security measure to detect spoofing.
 */
char *getDocumentIP(NPP instance) {
    // FIXME This function performs a DNS lookup independently of the
    //       browser. So it's possible that the browser and the plugin
    //       get different addresses. This is a (small) security problem
    //       since the browser might have loaded a maliciuous page while
    //       the plugin authenticates with the real IP.
    char *hostname = getDocumentHostname(instance);
    if (!hostname) return NULL;
    
    struct addrinfo *firstAddrInfo;
    int ret = getaddrinfo(hostname, NULL, NULL, &firstAddrInfo);
    free(hostname);
    if (ret != 0) return NULL;
    
    // Find first INET (IPv4) address (BankID supports IPv4 addresses only)
    const struct addrinfo *ai = firstAddrInfo;
    while (ai && ai->ai_family != AF_INET)
        ai = ai->ai_next;
    
    if (!ai) return NULL;
    
    char ip[NI_MAXHOST];
    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ip, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST) != 0) {
        freeaddrinfo(firstAddrInfo);
        return NULL;
    }
    freeaddrinfo(firstAddrInfo);
    
    return strdup(ip);
}

/**
 * Returns the native ID of the browser window, or None (= 0) on error.
 */
Window getWindowId(NPP instance) {
    Window id;
    if (NPN_GetValue(instance, NPNVnetscapeWindow, &id) == NPERR_NO_ERROR) {
        return id;
    } else {
        return None;
    }
}

bool copyIdentifierName(NPIdentifier ident, char *name, size_t maxLength) {
    char *heapStr = NPN_UTF8FromIdentifier(ident);
    if (!heapStr) return false;
    size_t len = strlen(heapStr);
    bool ok = (len < maxLength-1);
    if (ok) memcpy(name, heapStr, len+1);
    NPN_MemFree(heapStr);
    return ok;
}

