
COMMONCFLAGS=-O2 -g -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter
CCFLAGS=$(COMMONCFLAGS) -I../npapi/include `pkg-config --cflags gtk+-2.0` -DGTK_DISABLE_DEPRECATED=1 -DGDK_DISABLE_DEPRECATED=1 -DG_DISABLE_DEPRECATED=1
LINKFLAGS=`pkg-config --cflags --libs gtk+-2.0` -lnss3 -lsmime3

# Files to be installed
LIB_PATH=`../configure --internal--get-define=LIB_PATH`
SHARE_PATH=`../configure --internal--get-define=SHARE_PATH`
UI_PATH=`../configure --internal--get-define=UI_PATH`
SIGNING_EXECUTABLE=`../configure --internal--get-define=SIGNING_EXECUTABLE`
UI_GTK_XML=`../configure --internal--get-define=UI_GTK_XML`

OBJECTS=bankid.o keyfile.o main.o misc.o pipe.o posix.o gtk.o xmldecisec.o

all: sign

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

sign: $(OBJECTS)
	$(CC) $(LINKFLAGS) -o $@ $(OBJECTS)

.PHONY: all clean install uninstall
clean:
	rm -f $(OBJECTS) sign

install: sign gtk/sign.xml
	install -T -D -s sign $(SIGNING_EXECUTABLE)
	install -T -D -m 644 gtk/sign.xml $(UI_GTK_XML)

uninstall:
	rm -f $(SIGNING_EXECUTABLE) $(UI_GTK_XML)
	[ ! -d $(LIB_PATH) ] || rmdir $(LIB_PATH) 2> /dev/null || true
	[ ! -d $(UI_PATH) ] || rmdir $(UI_PATH)
	[ ! -d $(SHARE_PATH) ] || rmdir $(SHARE_PATH)

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

