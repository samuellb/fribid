
SUBDIRS=main plugin

all clean:
	@sh -c 'for dir in $(SUBDIRS); do (cd $$dir && $(MAKE) $@); done'

.PHONY: all clean $(SUBDIRS)

