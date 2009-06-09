#ifndef __MISC_H__
#define __MISC_H__

#include <stdbool.h>

char *base64_encode(const char *data, const int length);
char *base64_decode(const char *encoded);
bool is_canonical_base64(const char *encoded);

bool is_valid_domain_name(const char *domain);
bool is_valid_ip_address(const char *ip);
bool is_valid_hostname(const char *hostname);
bool is_https_url(const char *url);

#endif


