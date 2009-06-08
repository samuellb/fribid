
CC=gcc
CCFLAGS=-Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter -g -I../npapi/include -fpic -fvisibility=hidden

OBJECTS=ipc.o npmain.o npobject.o plugin.o pipe.o npn_gate.o np_entry.o

all: libplugins.so

ipc.o: ../common/pipe.h
npmain.o: npobject.h plugin.h
npobject.o: npobject.h plugin.h
pipe.o: ../common/pipe.h ../common/pipe.c
plugin.o: plugin.h

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

libplugins.so: $(OBJECTS)
	$(CC) -shared -Wl,-soname,libplugins.so -o $@ $^ -lc

.PHONY: clean
clean:
	-rm -f $(OBJECTS) libplugins.so


