# Copyright (C) 1998,1999,2000,2001,2003 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS = --enable-selinux-support \
                            --enable-camellia --enable-mailto
AUTOMAKE_OPTIONS = dist-bzip2 filename-length-max=99

if CROSS_COMPILING
checks =
else
checks = checks
endif

SUBDIRS = m4 intl zlib util mpi cipher tools g10 keyserver po doc ${checks}
EXTRA_DIST = scripts/config.rpath  PROJECTS BUGS config.h.in autogen.sh
DISTCLEANFILES = 

# Add all the files listed in "distfiles" files to the distribution,
# apply version numbers to some files and create a VERSION file which
# we need for the Prereq: patch file trick.
dist-hook:
	@set -e; \
	 for file in `cd $(top_srcdir); \
		     find scripts mpi include -type f -name distfiles`; do \
	    dir=`dirname $$file` ; $(mkinstalldirs) $(distdir)/$$dir ; \
	    for i in distfiles `cat $(top_srcdir)/$$file` ; do \
		ln $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	    done ; \
	done
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/scripts/gnupg.spec.in \
	    > $(distdir)/gnupg.spec
	echo "$(VERSION)" > $(distdir)/VERSION

