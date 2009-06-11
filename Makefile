
CC=gcc
COMMONCFLAGS=-O2 -g -Wall -Wextra -std=c99 -pedantic -Wno-unused-parameter


SUBDIRS=main plugin

all clean:
	@sh -c 'export CC="$(CC)" COMMONCFLAGS="$(COMMONCFLAGS)"; for dir in $(SUBDIRS); do (cd $$dir && $(MAKE) $@); done'

.PHONY: all clean $(SUBDIRS)

