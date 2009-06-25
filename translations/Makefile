
.SUFFIXES:
.SUFFIXES: .po .mo

POTFILES=../client/gtk.c ../client/gtk/sign.glade
DOMAIN=`../configure --internal--get-define=BINNAME`

PACKAGENAME=`../configure --internal--get-define=PACKAGENAME`
PACKAGEVERSION=`../configure --internal--get-define=PACKAGEVERSION`
LOCALEDIR=`../configure --internal--get-define=LOCALEDIR`

MOFILES=sv.mo
LANGUAGES=sv

all: template.pot $(MOFILES)

template.pot: $(POTFILES)
	xgettext -k_ -d $(DOMAIN) --package-name=$(PACKAGENAME) --package-version=$(PACKAGEVERSION) --copyright-holder='YOUR NAME' -o $@ $(POTFILES)

.po.mo:
	msgfmt $< -o $@

clean:
	rm -f template.pot $(MOFILES)

install:
	for lang in $(LANGUAGES); do \
	    install -d $(DESTDIR)$(LOCALEDIR)/$$lang/LC_MESSAGES && \
	    install -m 644 -T $$lang.mo $(DESTDIR)$(LOCALEDIR)/$$lang/LC_MESSAGES/$(DOMAIN).mo || exit 1; \
	done 

uninstall:
	for lang in $(LANGUAGES); do \
	    rm -f $(DESTDIR)$(LOCALEDIR)/$$lang/LC_MESSAGES/$(DOMAIN).mo || exit 1; \
	done 

.PHONY: all clean install uninstall

