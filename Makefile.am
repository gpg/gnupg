# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

if CROSS_COMPILING
checks =
else
checks = checks
endif

SUBDIRS = intl zlib util mpi cipher tools g10 po doc ${checks}
EXTRA_DIST = VERSION  PROJECTS BUGS
# gettext never gets it right, so we take here care of deleting the
# symlink.
DISTCLEANFILES = g10defs.h intl/libintl.h

dist-hook:
	@set -e; \
	 for file in `cd $(top_srcdir); find . -type f -name distfiles`; do \
	    dir=`dirname $$file` ; $(mkinstalldirs) $(distdir)/$$dir ; \
	    for i in distfiles `cat $(top_srcdir)/$$file` ; do \
		ln $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	    done ; \
	done
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/scripts/gnupg.spec.in \
	    > $(distdir)/scripts/gnupg.spec



