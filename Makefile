
SUBDIRS=main plugin

all clean install uninstall:
	for dir in $(SUBDIRS); do (cd $$dir && $(MAKE) $@) || exit $?; done

distclean: clean
	rm -f common/config.h

.PHONY: all clean distclean install uninstall $(SUBDIRS)

