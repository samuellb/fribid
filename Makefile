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

SUBDIRS=client plugin translations doc

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
	gpg --detach-sign -a $(GPGFLAGS) $(DISTDESTDIR)$(DISTNAME).tar.bz2


# Release management
prepare-release: refresh-release-time refresh-changelog-time set-version

need-version:
	@[ -n "$$version" ] || (echo "The \`version' environment variable is not set" > /dev/stderr; false)

refresh-release-time:
	date=`date '+%s'` && \
	sed -ri 's/(#define RELEASE_TIME\s+)([0-9]+)/\1'$$date'/' common/defines.h

set-version: need-version
	sed -ri 's/(#define PACKAGEVERSION\s+")([^"]+)(")/\1'$$version'\3/' common/defines.h

refresh-changelog-time: need-version
	date=`date '+%F'` && \
	sed -ri "s/^($$version - )([0-9?-]+)(.*)/\1$$date\3/" CHANGELOG

tag-release: need-version
	GIT_COMMITTER_NAME="FriBID Project" GIT_COMMITTER_EMAIL=releases@fribid.se git tag -u B21DF30E "v$$version"

.PHONY: all clean dist distclean distsig install need-version prepare-release refresh-release-time set-version tag-release uninstall $(SUBDIRS)

