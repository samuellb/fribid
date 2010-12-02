#ifndef __PLUGINUTIL_H__
#define __PLUGINUTIL_H__

#include <stdint.h>

#include <npapi.h>
#include <npruntime.h>

#include <X11/X.h>


char *variantToStringZ(const NPVariant *variant);
bool convertStringZToVariant(char *string, NPVariant *result);
char *getDocumentURL(NPP instance);
char *getDocumentHostname(NPP instance);
char *getDocumentIP(NPP instance);
Window getWindowId(NPP instance);
bool copyIdentifierName(NPIdentifier ident, char *name, size_t maxLength);


#define IS_CALL(NAME, ARGCOUNT) (!strcmp(name, (NAME)) && (argCount == (ARGCOUNT)))
#define ARG(N, TYPE) NPVARIANT_IS_##TYPE(args[N])

#define IS_CALL_0(NAME) IS_CALL((NAME), 0)
#define IS_CALL_1(NAME, T1) (IS_CALL((NAME), 1) && ARG(0, T1))
#define IS_CALL_2(NAME, T1, T2) (IS_CALL((NAME), 2) && ARG(0, T1) && ARG(1, T2))

#endif

