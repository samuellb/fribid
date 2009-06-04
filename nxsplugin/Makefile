
CC=gcc
CCFLAGS=-Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter -I./npapi/include -g -fpic -fvisibility=hidden

# IPC to Nexus Personal
#IMPL_OBJECTS=ipc.o

# Builtin implementation
IMPL_OBJECTS=bankid.o keyfile.o xmldecisec.o

OBJECTS=npmain.o npobject.o plugin.o  npn_gate.o np_entry.o  $(IMPL_OBJECTS)

all: libplugins.so

bankid.o: plugin.h keyfile.h xmldecisec.h
ipc.o: plugin.h
keyfile.o: keyfile.h
npmain.o: npobject.h plugin.h
npobject.o: npobject.h plugin.h
plugin.o: plugin.h
xmldecisec.o: xmldecisec.h keyfile.h

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

libplugins.so: $(OBJECTS)
	$(CC) -shared -Wl,-soname,libplugins.so -o $@ $^ -lc

.PHONY: clean
clean:
	-rm -f $(OBJECTS) libplugins.so


