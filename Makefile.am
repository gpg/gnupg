# Copyright (C) 1998,1999,2000,2001,2003,2010,2011,
#               2012 Free Software Foundation, Inc.
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
# We can't use --enable-selinux-support because some of our regression
# tests are importing secret keys and that is not allowed if
# selinux-support is enabled.
DISTCHECK_CONFIGURE_FLAGS = --enable-mailto
AUTOMAKE_OPTIONS = dist-bzip2 filename-length-max=99

GITLOG_TO_CHANGELOG=gitlog-to-changelog

if CROSS_COMPILING
checks =
else
checks = checks
endif

if HAVE_W32_SYSTEM
bzlib = bzlib
else
bzlib =
endif

SUBDIRS = m4 intl zlib ${bzlib} util mpi cipher tools \
          g10 keyserver po doc ${checks}

EXTRA_DIST = scripts/config.rpath PROJECTS BUGS config.h.in	\
             autogen.sh ChangeLog-2011 po/ChangeLog-2011	\
             util/ChangeLog-2011 scripts/ChangeLog-2011		\
             doc/ChangeLog-2011 tools/ChangeLog-2011		\
             zlib/ChangeLog-2011 m4/ChangeLog-2011		\
             include/ChangeLog-2011 g10/ChangeLog-2011		\
             checks/ChangeLog-2011 cipher/ChangeLog-2011	\
             intl/ChangeLog-2011 keyserver/ChangeLog-2011	\
             tests/ChangeLog-2011 mpi/ChangeLog-2011


DISTCLEANFILES =

# We do not install README into the doc directory because that would
# conflict with GnuPG-2.
# dist_doc_DATA = README


# Add all the files listed in "distfiles" files to the distribution,
# apply version numbers to some files and create a VERSION file which
# we need for the Prereq: patch file trick.
dist-hook: gen-ChangeLog
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


gen_start_date = 2011-12-01T06:00:00
.PHONY: gen-ChangeLog
gen-ChangeLog:
	set -e; 							\
	if test -d $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	    $(GITLOG_TO_CHANGELOG) --append-dot --tear-off		\
	    --amend=scripts/git-log-fix	 				\
	    --since=$(gen_start_date) ) > $(distdir)/cl-t;		\
          cat $(top_srcdir)/scripts/git-log-footer >> $(distdir)/cl-t;  \
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi
