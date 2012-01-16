/*

  Copyright (c) 2009-2011 Samuel Lidén Borell <samuel@slbdata.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#define _BSD_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "misc.h"

/**
 * Like sprintf, but allocates and returns a string instead of
 * using a pre-allocated buffer.
 */
char *rasprintf(const char *format, ...) {
    va_list args;
    char *str;
    
    va_start(args, format);
    str = (char*)g_strdup_vprintf((gchar*)format, args);
    va_end(args);
    return str;
}

/**
 * Like rasprintf (above), but appends to an existing string instead of
 * creating a new one. The original string is reallocated as a longer
 * string, which is returned.
 *
 * In case of an error, this function returns NULL and frees str.
 */
char *rasprintf_append(char *str, const char *format, ...) {
    va_list args;
    
    va_start(args, format);
    char *tail = (char*)g_strdup_vprintf((gchar*)format, args);
    va_end(args);
    if (!tail) goto error;
    
    size_t oldlen = strlen(str);
    size_t taillen = strlen(tail);
    
    char *merged = realloc(str, oldlen+taillen+1);
    if (!merged) goto error;
    memcpy(&merged[oldlen], tail, taillen+1);
    free(tail);
    return merged;
  
  error:
    free(tail);
    free(str);
    return NULL;
}

/**
 * This is a modified memset(3) function to cover the
 * problems documented by David Wheeler in:
 * http://www.dwheeler.com/secure-programs/Secure-Programs-HOWTO/\
 * protect-secrets.html
 * Based on a Bugtraq issue filed by Andy Polyakov this
 * workaround was suggested by Michael Howard
 */
void *guaranteed_memset(void *v, int c, size_t n) {
    volatile char *p=v;
    while (n--) *p++=c;
    return v;
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

/**
 * Checks if a string is in UTF-8 format. If not it tries to convert it from
 * ISO-88591-1, and free's the UTF-8 string.
 *
 * @returns  An UTF-8 string, or NULL on error.
 */
static char *utf8_or_latin1(char *input, size_t length) {
    // Check for NULL
    if (length != strlen(input)) {
        free(input);
        return NULL;
    }
    
    // Check for invalid unicode
    if (g_utf8_validate(input, length, NULL)) return input;
    
    // Try to convert from ISO-8859-1
    GError *error = NULL;
    gchar *utf8 = g_convert(input, length, "UTF-8", "ISO-8859-1",
                            NULL, NULL, &error);
    free(input);
    
    if (!error) return (char*)utf8;
    
    // Neither valid UTF-8 or ISO-8859-1
    g_error_free(error);
    g_free(utf8);
    return NULL;
}

char *base64_encode(const char *data, int length) {
    if (length == 0) return strdup("");
    
    char *base64 = (char*)g_base64_encode((const guchar*)data, length);
    if (base64) {
        removeNewlines(base64);
    }
    return base64;
}

char *base64_decode(const char *encoded) {
    gsize length;

    char *temp = (char*)g_base64_decode(encoded, &length);
    if (!temp) goto error;
    
    char *result = malloc(length+1);
    if (!result) goto error;
    
    memcpy(result, temp, length);
    result[length] = '\0';
    free(temp);
    
    return utf8_or_latin1(result, length);
  
  error:
    free(temp);
    return NULL;
}

char *base64_decode_binary(const char *encoded, size_t *decodedLength) {
    gsize length;

    char *result = (char*)g_base64_decode(encoded, &length);
    *decodedLength = length;
    
    if (*decodedLength != length) {
        // Integer overflow
        free(result);
        return NULL;
    }
    
    return result;
}

bool is_canonical_base64(const char *encoded) {
    /* Try to decode */
    gsize length;
    char *decoded = (char*)g_base64_decode(encoded, &length);
    if (!decoded) return false;
    
    /* Recode and verify that it's equal to the encoded data */
    char *recoded = base64_encode(decoded, length);
    bool equal = recoded && !strcmp(recoded, encoded);
    
    free(recoded);
    free(decoded);
    return equal;
}

char *sha_base64(const char *str) {
    unsigned char shasum[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    char *result = NULL;

    md = EVP_sha256();
    EVP_MD_CTX_init(&mdctx);
    
    if (EVP_DigestInit_ex(&mdctx, md, NULL) &&
        EVP_DigestUpdate(&mdctx, str, strlen(str)) &&
        EVP_DigestFinal_ex(&mdctx, shasum, &md_len)) {
        result = base64_encode((const char*)shasum, sizeof(shasum));
    }
    
    EVP_MD_CTX_cleanup(&mdctx);
    return result;
}

bool is_valid_domain_name(const char *domain) {
    static const char allowed[] = "abcdefghijklmnopqrstuvwxyz0123456789-.";
    return (strspn(domain, allowed) == strlen(domain));
}

bool is_valid_ip_address(const char *ip) {
    static const char allowed[] = "0123456789abcdef.[]:";
    return (strspn(ip, allowed) == strlen(ip));
}

bool is_valid_hostname(const char *hostname) {
    return is_valid_domain_name(hostname) || is_valid_ip_address(hostname);
}

bool is_https_url(const char *url) {
    return !strncmp(url, "https://", 8);
}
