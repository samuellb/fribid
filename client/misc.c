/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
 
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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

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
 */
char *rasprintf_append(char *str, const char *format, ...) {
    va_list args;
    
    size_t oldlen = strlen(str);
    va_start(args, format);
    char *tail = (char*)g_strdup_vprintf((gchar*)format, args);
    va_end(args);
    size_t taillen = strlen(tail);
    
    str = realloc(str, oldlen+taillen+1);
    memcpy(&str[oldlen], tail, taillen+1);
    free(tail);
    return str;
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

char *base64_encode(const char *input, const int length) {
  if (length == 0) return strdup("");

  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  //removeNewlines(base64);
  return buff;
}

char *base64_decode(const char *input){
  BIO *b64, *bmem;
  int length = strlen(input);
  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf((void *)input, length);
  bmem = BIO_push(b64, bmem);

  BIO_read(bmem, buffer, length);

  BIO_free_all(bmem);

  return buffer;
}

bool is_canonical_base64(const char *encoded) {
    return true;
    //TODO: xxx
    /* Try to decode */
    /*
    unsigned int length;
    char *decoded = (char*)ATOB_AsciiToData(encoded, &length);
    if (!decoded) return false;
    */
    /* Recode and verify that it's equal to the encoded data */
    /*char *recoded = BTOA_DataToAscii((const unsigned char*)decoded, length);
    removeNewlines(recoded);
    bool equal = !strcmp(recoded, encoded);
    
    free(recoded);
    free(decoded);
    return equal;*/
}

char *sha_base64(const char *str) {
    char shasum[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX mdctx;
    const EVP_MD *md;
    int md_len, i;

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("sha256");

    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, str, strlen(str));
    EVP_DigestFinal_ex(&mdctx, shasum, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);

    return base64_encode(shasum, sizeof(shasum));
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
