
CC=gcc
CCFLAGS=-Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter -g -I../npapi/include `pkg-config --cflags gtk+-2.0` -DGTK_DISABLE_DEPRECATED=1 -DGDK_DISABLE_DEPRECATED=1 -DG_DISABLE_DEPRECATED=1
LDFLAGS=`pkg-config --cflags --libs gtk+-2.0` -lnss3 -lsmime3


OBJECTS=bankid.o keyfile.o main.o misc.o pipe.o posix.o gtk.o xmldecisec.o

all: bankid-se

bankid.o: bankid.h keyfile.h xmldecisec.h
keyfile.o: keyfile.h misc.h
gtk.o: platform.h
main.o: bankid.h misc.h platform.h ../common/pipe.h
misc.o: misc.h
pipe.o: ../common/pipe.h ../common/pipe.c
posix.o: platform.h
xmldecisec.o: xmldecisec.h keyfile.h

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

bankid-se: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	-rm -f $(OBJECTS) bankid-se


