
COMMONCFLAGS=-O2 -g -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter
CCFLAGS=$(COMMONCFLAGS) -I../npapi -fPIC -fvisibility=hidden `pkg-config --cflags glib-2.0` -DG_DISABLE_DEPRECATED=1
LINKFLAGS=-Wl,-z,defs,-soname,libplugins.so
LIBS=-lc `pkg-config --libs glib-2.0`

# Files to be installed
LIB_PATH=`../configure --internal--get-define=LIB_PATH`
NPAPI_PLUGIN_LIB=`../configure --internal--get-define=NPAPI_PLUGIN_LIB`
NPAPI_PLUGIN_PATHS=`../configure --internal--get-define=NPAPI_PLUGIN_PATHS`

OBJECTS=ipc.o npmain.o npobject.o plugin.o pipe.o npn_gate.o np_entry.o

all: libplugins.so

ipc.o: ../common/pipe.h plugin.h
npmain.o: npobject.h plugin.h
npobject.o: npobject.h plugin.h
pipe.o: ../common/pipe.h ../common/pipe.c
plugin.o: plugin.h

.c.o:
	$(CC) $(CCFLAGS) -c $< -o $@

libplugins.so: $(OBJECTS)
	$(CC) -shared $(LINKFLAGS) -o $@ $(OBJECTS) $(LIBS)

.PHONY: all clean install uninstall
clean:
	rm -f $(OBJECTS) libplugins.so

install:
	install -d $(DESTDIR)$(LIB_PATH)
	install -m 644 libplugins.so $(DESTDIR)$(LIB_PATH)
	for path in $(NPAPI_PLUGIN_PATHS); do \
	    (../configure --internal--remove-link $(DESTDIR)$$path/libplugins.so $(NPAPI_PLUGIN_LIB) || exit 1) && \
	    install -d $(DESTDIR)$$path && \
	    ln -s $(NPAPI_PLUGIN_LIB) $(DESTDIR)$$path/libplugins.so; \
	done

uninstall:
	rm -f $(DESTDIR)$(NPAPI_PLUGIN_LIB)
	[ ! -d $(DESTDIR)$(LIB_PATH) ] || rmdir $(DESTDIR)$(LIB_PATH) 2> /dev/null || true
	for path in $(NPAPI_PLUGIN_PATHS); do \
	    ../configure --internal--remove-link $(DESTDIR)$$path/libplugins.so $(NPAPI_PLUGIN_LIB) || exit 1; \
	done

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

