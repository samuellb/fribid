#
#  Copyright (c) 2009 Samuel Lidén Borell <samuel@slbdata.se>
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

SUBDIRS=client plugin translations

DISTNAME=`./configure --internal--get-define=BINNAME`-`./configure --internal--get-define=PACKAGEVERSION`

all clean install uninstall:
	for dir in $(SUBDIRS); do (cd $$dir && $(MAKE) $@) || exit $?; done

distclean: clean
	rm -f common/config.h

# Package creation
dist-all: distsig distdebsig

dist:
	git archive --format=tar --prefix=$(DISTNAME)/ HEAD | bzip2 > $(DISTDESTDIR)$(DISTNAME).tar.bz2

distsig: dist
	gpg --sign $(DISTDESTDIR)$(DISTNAME).tar.bz2

distdeb: dist
	distname=$(DISTNAME) && \
	distdest=$(DISTDESTDIR) && \
	tdir=`mktemp -d` && \
	(cp $$distdest$$distname.tar.bz2 $$tdir && cd $$tdir && \
	    tar xjf $$distname.tar.bz2 && \
	    cd $$distname && dpkg-buildpackage -rfakeroot) && \
	cp $$tdir/*.deb $$distdest && \
	rm -rf $$tdir

distdebsig: distdeb
	# FIXME should not use *
	for deb in $(DISTDESTDIR)*.deb; do gpg -o $$deb.sig --sign $$deb; done

.PHONY: all clean dist distclean install uninstall $(SUBDIRS)

