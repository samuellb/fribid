
COMMONCFLAGS=-O2 -g -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter
CCFLAGS=$(COMMONCFLAGS) -I../npapi/include -fPIC -fvisibility=hidden

# Files to be installed
LIB_PATH=`../configure --internal--get-define=LIB_PATH`
NPAPI_PLUGIN_LIB=`../configure --internal--get-define=NPAPI_PLUGIN_LIB`
NPAPI_PLUGIN_LINK1=`../configure --internal--get-define=NPAPI_PLUGIN_LINK1`
NPAPI_PLUGIN_LINK2=`../configure --internal--get-define=NPAPI_PLUGIN_LINK2`
NPAPI_PLUGIN_REL=`../configure --internal--get-define=NPAPI_PLUGIN_REL`

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
	-rm -f $(OBJECTS) libplugins.so

install:
	install -T -D -s -m 644 libplugins.so $(NPAPI_PLUGIN_LIB) && \
	../configure --internal--remove-link $(NPAPI_PLUGIN_LINK1) $(NPAPI_PLUGIN_REL) && \
	../configure --internal--remove-link $(NPAPI_PLUGIN_LINK2) $(NPAPI_PLUGIN_REL) && \
	ln -s $(NPAPI_PLUGIN_REL) $(NPAPI_PLUGIN_LINK1)
	ln -s $(NPAPI_PLUGIN_REL) $(NPAPI_PLUGIN_LINK2)

uninstall:
	rm -f $(NPAPI_PLUGIN_LIB)
	[ ! -d $(LIB_PATH) ] || rmdir $(LIB_PATH) 2> /dev/null || true
	../configure --internal--remove-link $(NPAPI_PLUGIN_LINK1) $(NPAPI_PLUGIN_REL)
	../configure --internal--remove-link $(NPAPI_PLUGIN_LINK2) $(NPAPI_PLUGIN_REL)

$(OBJECTS): ../common/defines.h ../common/config.h
../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

