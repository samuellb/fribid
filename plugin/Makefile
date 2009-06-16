
COMMONCFLAGS=-O2 -g -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter
CCFLAGS=$(COMMONCFLAGS) -I../npapi/include -fPIC -fvisibility=hidden

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
	$(CC) -shared -Wl,-z,defs,-soname,libplugins.so -o $@ $(OBJECTS) -lc

.PHONY: all clean install uninstall
clean:
	rm -f $(OBJECTS) libplugins.so

install:
	install -d $(LIB_PATH)
	install -s -m 644 libplugins.so $(LIB_PATH)
	for path in $(NPAPI_PLUGIN_PATHS); do \
	    (../configure --internal--remove-link $$path/libplugins.so $(NPAPI_PLUGIN_LIB) || exit 1) && \
	    install -d $$path && \
	    ln -s $(NPAPI_PLUGIN_LIB) $$path/libplugins.so; \
	done

uninstall:
	rm -f $(NPAPI_PLUGIN_LIB)
	[ ! -d $(LIB_PATH) ] || rmdir $(LIB_PATH) 2> /dev/null || true
	for path in $(NPAPI_PLUGIN_PATHS); do \
	    ../configure --internal--remove-link $$path/libplugins.so $(NPAPI_PLUGIN_LIB) || exit 1; \
	done

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

