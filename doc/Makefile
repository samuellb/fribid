#
#  Copyright (c) 2010 Samuel Lidén Borell <samuel@slbdata.se>
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

LANGUAGES=sv

all:
clean:

install: all
	install -d $(DESTDIR)$(MANDIR)/man7
	gzip -c9 fribid.7 > $(DESTDIR)$(MANDIR)/man7/fribid.7.gz
	for lang in $(LANGUAGES); do \
	    install -d $(DESTDIR)$(MANDIR)/$$lang/man7 && \
	    gzip -c9 fribid.$$lang.7 > $(DESTDIR)$(MANDIR)/$$lang/man7/fribid.7.gz || exit 1; \
	done

uninstall:
	rm -f $(DESTDIR)$(MANDIR)/man7/fribid.7.gz
	for lang in $(LANGUAGES); do \
	    rm -f $(DESTDIR)$(MANDIR)/$$lang/man7/fribid.7.gz || exit 1; \
	done

.PHONY: all clean install uninstall

../common/config.h:
	@echo "You must run ./configure first." >&2 && false
../common/defines.h:

