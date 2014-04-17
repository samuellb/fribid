#
#  Copyright (c) 2010-2014 Samuel Lidén Borell <samuel@kodafritt.se>
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


MANDIR=`../configure --internal--get-define=MANDIR`
DOCDIR=`../configure --internal--get-define=DOCDIR`

LANGUAGES=sv

all:
clean:

install: all
	# Man page
	install -d $(DESTDIR)$(MANDIR)/man7
	gzip -n -c9 fribid.7 > $(DESTDIR)$(MANDIR)/man7/fribid.7.gz
	# Localization
	for lang in $(LANGUAGES); do \
	    install -d $(DESTDIR)$(MANDIR)/$$lang/man7 && \
	    gzip -n -c9 fribid.$$lang.7 > $(DESTDIR)$(MANDIR)/$$lang/man7/fribid.7.gz || exit 1; \
	done
	# Test scripts
	install -d $(DESTDIR)$(DOCDIR)/fribid
	install -d $(DESTDIR)$(DOCDIR)/fribid/examples
	install -m 644 examples/README $(DESTDIR)$(DOCDIR)/fribid/examples/
	install -m 644 examples/README.sv $(DESTDIR)$(DOCDIR)/fribid/examples/
	install -m 644 examples/common.sh $(DESTDIR)$(DOCDIR)/fribid/examples/
	install -m 755 examples/sign.sh $(DESTDIR)$(DOCDIR)/fribid/examples/
	install -m 755 examples/reqcert.sh $(DESTDIR)$(DOCDIR)/fribid/examples/

uninstall:
	rm -f $(DESTDIR)$(MANDIR)/man7/fribid.7.gz
	for lang in $(LANGUAGES); do \
	    rm -f $(DESTDIR)$(MANDIR)/$$lang/man7/fribid.7.gz || exit 1; \
	done
	rm -f $(DESTDIR)$(DOCDIR)/fribid/examples/README
	rm -f $(DESTDIR)$(DOCDIR)/fribid/examples/README.sv
	rm -f $(DESTDIR)$(DOCDIR)/fribid/examples/common.sh
	rm -f $(DESTDIR)$(DOCDIR)/fribid/examples/sign.sh
	rm -f $(DESTDIR)$(DOCDIR)/fribid/examples/reqcert.sh
	[ ! -d $(DESTDIR)$(DOCDIR)/fribid/examples ] || rmdir $(DESTDIR)$(DOCDIR)/fribid/examples
	[ ! -d $(DESTDIR)$(DOCDIR)/fribid ] || rmdir $(DESTDIR)$(DOCDIR)/fribid

.PHONY: all clean install uninstall

../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

