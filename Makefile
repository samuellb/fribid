
SUBDIRS=main plugin

all clean install uninstall:
	@sh -c 'for dir in $(SUBDIRS); do (cd $$dir && $(MAKE) $@); done'

.PHONY: all clean install uninstall $(SUBDIRS)

