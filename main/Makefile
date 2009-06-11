
COMMONCFLAGS=-O2 -g -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter
CCFLAGS=$(COMMONCFLAGS) -I../npapi/include `pkg-config --cflags gtk+-2.0` -DGTK_DISABLE_DEPRECATED=1 -DGDK_DISABLE_DEPRECATED=1 -DG_DISABLE_DEPRECATED=1
LINKFLAGS=`pkg-config --cflags --libs gtk+-2.0` -lnss3 -lsmime3


OBJECTS=bankid.o keyfile.o main.o misc.o pipe.o posix.o gtk.o xmldecisec.o

all: bankid-se

bankid.o: bankid.h keyfile.h misc.h xmldecisec.h
keyfile.o: keyfile.h misc.h platform.h
gtk.o: platform.h bankid.h keyfile.h
main.o: bankid.h misc.h platform.h ../common/pipe.h
misc.o: misc.h
pipe.o: ../common/pipe.h ../common/pipe.c
posix.o: platform.h
xmldecisec.o: xmldecisec.h keyfile.h misc.h

.c.o:
	$(CC) $(CCFLAGS) -c $< -o $@

bankid-se: $(OBJECTS)
	$(CC) $(LINKFLAGS) -o $@ $(OBJECTS)

.PHONY: all clean
clean:
	-rm -f $(OBJECTS) bankid-se

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

