
CC=gcc
CCFLAGS=-Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter -I./npapi/include -g -fpic -fvisibility=hidden

OBJECTS=ipc.o npmain.o npobject.o plugin.o  npn_gate.o np_entry.o

all: libplugins.so

ipc.o: ipc.h
npmain.o: npobject.h plugin.h
npobject.o: npobject.h plugin.h
plugin.o: ipc.h plugin.h

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

libplugins.so: $(OBJECTS)
	$(CC) -shared -Wl,-soname,libplugins.so -o $@ $^ -lc

.PHONY: clean
clean:
	-rm -f $(OBJECTS) libplugins.so


