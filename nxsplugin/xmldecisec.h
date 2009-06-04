#ifndef __XMLDECISEC_H__
#define __XMLDECISEC_H__

char *xmldsec_sign(const char *p12Data, const int p12Length,
                   const char *person, const unsigned int certMask, const char *password,
                   const char *dataId, const char *data);

#endif

