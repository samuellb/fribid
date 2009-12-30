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
CCFLAGS=$(COMMONCFLAGS) -I../npapi -fPIC -fvisibility=hidden `pkg-config --cflags glib-2.0` -DG_DISABLE_DEPRECATED=1
LINKFLAGS=$(CFLAGS) $(LDFLAGS) -Wl,-z,defs,-soname,libfribidplugin.so
LIBS=-lc `pkg-config --libs glib-2.0`

# Files to be installed
LIB_PATH=`../configure --internal--get-define=LIB_PATH`
NPAPI_PLUGIN_LIB=`../configure --internal--get-define=NPAPI_PLUGIN_LIB`
NPAPI_PLUGIN_PATHS=`../configure --internal--get-define=NPAPI_PLUGIN_PATHS`

OBJECTS=ipc.o npmain.o npobject.o plugin.o pipe.o npn_gate.o np_entry.o

all: libfribidplugin.so

ipc.o: ../common/pipe.h plugin.h
npmain.o: npobject.h plugin.h
npobject.o: npobject.h plugin.h
pipe.o: ../common/pipe.h ../common/pipe.c
plugin.o: ../common/biderror.h plugin.h
np_entry.o: ../npapi/np_entry.c
npn_gate.o: ../npapi/npn_gate.c

.c.o:
	$(CC) $(CCFLAGS) -c $< -o $@

libfribidplugin.so: $(OBJECTS)
	$(CC) -shared $(LINKFLAGS) -o $@ $(OBJECTS) $(LIBS)

.PHONY: all clean install uninstall
clean:
	rm -f $(OBJECTS) libfribidplugin.so

install:
	install -d $(DESTDIR)$(LIB_PATH)
	install -m 644 libfribidplugin.so $(DESTDIR)$(LIB_PATH)
	for path in $(NPAPI_PLUGIN_PATHS); do \
	    (../configure --internal--remove-link $(DESTDIR)$$path/libfribidplugin.so $(NPAPI_PLUGIN_LIB) || exit 1) && \
	    install -d $(DESTDIR)$$path && \
	    ln -s $(NPAPI_PLUGIN_LIB) $(DESTDIR)$$path/libfribidplugin.so; \
	done

uninstall:
	rm -f $(DESTDIR)$(NPAPI_PLUGIN_LIB)
	[ ! -d $(DESTDIR)$(LIB_PATH) ] || rmdir $(DESTDIR)$(LIB_PATH) 2> /dev/null || true
	for path in $(NPAPI_PLUGIN_PATHS); do \
	    ../configure --internal--remove-link $(DESTDIR)$$path/libfribidplugin.so $(NPAPI_PLUGIN_LIB) || exit 1; \
	done

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

