#
#  Copyright (c) 2009 Samuel Lidén Borell <samuel@slbdata.se>
# 
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.
#

CFLAGS ?= -O2 -g
COMMONCFLAGS=$(CFLAGS) -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter
CCFLAGS=$(COMMONCFLAGS) -I../npapi/include `pkg-config --cflags 'gtk+-2.0 >= 2.12' glib-2.0 'nss >= 3.10' nspr` -DGTK_DISABLE_DEPRECATED=1 -DGDK_DISABLE_DEPRECATED=1 -DG_DISABLE_DEPRECATED=1
# You may have to add -lpthread after $(LDFLAGS) on OpenBSD
LINKFLAGS=$(CFLAGS) $(LDFLAGS) -Wl,--as-needed
LIBS=`pkg-config --libs 'gtk+-2.0 >= 2.12' glib-2.0 'nss >= 3.10' nspr`

# Files to be installed
LIB_PATH=`../configure --internal--get-define=LIB_PATH`
SHARE_PATH=`../configure --internal--get-define=SHARE_PATH`
UI_PATH=`../configure --internal--get-define=UI_PATH`
SIGNING_EXECUTABLE=`../configure --internal--get-define=SIGNING_EXECUTABLE`
UI_GTK_XML=`../configure --internal--get-define=UI_GTK_XML`

OBJECTS=bankid.o keyfile.o main.o misc.o pipe.o posix.o glibconfig.o gtk.o xmldsig.o secmem.o

all: sign

bankid.o: ../common/biderror.h bankid.h keyfile.h misc.h xmldsig.h
keyfile.o: keyfile.h misc.h platform.h
glibconfig.o: platform.h
gtk.o: ../common/biderror.h platform.h bankid.h keyfile.h
main.o: ../common/biderror.h bankid.h misc.h secmem.h platform.h ../common/pipe.h
misc.o: misc.h
pipe.o: ../common/pipe.h ../common/pipe.c
posix.o: platform.h
xmldsig.o: xmldsig.h keyfile.h misc.h
secmem.o: secmem.h

.c.o:
	$(CC) $(CCFLAGS) -c $< -o $@

sign: $(OBJECTS)
	$(CC) $(LINKFLAGS) $(OBJECTS) $(LIBS) -o $@

.PHONY: all clean install uninstall
clean:
	rm -f $(OBJECTS) sign

install: sign gtk/sign.xml
	install -d $(DESTDIR)$(LIB_PATH)
	install -d $(DESTDIR)$(UI_PATH)
	install sign $(DESTDIR)$(LIB_PATH)
	install -m 644 gtk/sign.xml $(DESTDIR)$(UI_PATH)

uninstall:
	rm -f $(DESTDIR)$(SIGNING_EXECUTABLE) $(DESTDIR)$(UI_GTK_XML)
	[ ! -d $(DESTDIR)$(LIB_PATH) ] || rmdir $(DESTDIR)$(LIB_PATH) 2> /dev/null || true
	[ ! -d $(DESTDIR)$(UI_PATH) ] || rmdir $(DESTDIR)$(UI_PATH)
	[ ! -d $(DESTDIR)$(SHARE_PATH) ] || rmdir $(DESTDIR)$(SHARE_PATH)

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

