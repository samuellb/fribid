#
#  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
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

all subdirs-clean install uninstall:
	for dir in $(SUBDIRS); do (cd $$dir && $(MAKE) $@) || exit $?; done

clean: subdirs-clean
	rm -f ch-all.tmp ch-entry.tmp ch-other.tmp

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
	    cd $$distname && dpkg-buildpackage -uc -us -rfakeroot) && \
	cp $$tdir/*.deb $$distdest./ && \
	rm -rf $$tdir

distdebsig: distdeb
	# FIXME should not use *
	for deb in $(DISTDESTDIR)*.deb; do gpg -o $$deb.sig --sign $$deb; done

# Release management
prepare-release: refresh-release-time refresh-changelog-time set-version sync-changelog

need-version:
	@[ -n "$$version" ] || (echo "The \`version' environment variable is not set" > /dev/stderr; false)

refresh-release-time:
	date=`date '+%s'` && \
	sed -ri 's/(#define RELEASE_TIME\s+)([0-9]+)/\1'$$date'/' common/defines.h

set-version: need-version
	sed -ri 's/(#define PACKAGEVERSION\s+")([^"]+)(")/\1'$$version'\3/' common/defines.h

sync-changelog: need-version
	# This rule syncs debian/changelog with CHANGELOG
	# Remove the current version (if present)
	cp debian/changelog ch-other.tmp
	[ `head -n 1 debian/changelog | sed -r 's/[^\s]+ \(([^)]+)\).*/\1/'` != "$$version" ] || \
	    sed '/--/{:x n;bx}; d' debian/changelog | tail -n +3 > ch-other.tmp # is there a better way?
	# Debianize the changelog entry for the current version
	echo "fribid ($$version) unstable; urgency=$${urgency:-low}" > ch-entry.tmp
	echo >> ch-entry.tmp
	sed "/^$$version - /{:x /^\n*$$/Q; n;bx };d" CHANGELOG | tail -n +2 >> ch-entry.tmp
	echo >> ch-entry.tmp
	echo " -- "`git config --get user.name`" <"`git config --get user.email`">  "`date -R` >> ch-entry.tmp
	echo >> ch-entry.tmp
	# Merge and add the changelog entry
	cat ch-entry.tmp ch-other.tmp > ch-all.tmp
	echo "$$version" | grep -qvF '-' \
	    && mv ch-all.tmp debian/changelog \
	    || echo "Debian versions entries are not synced from CHANGELOG"
	rm -f ch-all.tmp ch-entry.tmp ch-other.tmp

refresh-changelog-time: need-version
	date=`date '+%F'` && \
	sed -ri "s/^($$version - )([0-9?-]+)(.*)/\1$$date\3/" CHANGELOG


.PHONY: all clean dist distdeb distdebsig distclean distsig install need-version prepare-release refresh-release-time set-version subdirs-clean sync-changelog uninstall $(SUBDIRS)

