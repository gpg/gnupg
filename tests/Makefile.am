# Makefile.am
#     	Copyright (C) 2002 Free Software Foundation, Inc.
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
# along with this program; if not, see <https://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

if TEST_LIBTSS
tpm2dtests = tpm2dtests
else
tpm2dtests =
endif

SUBDIRS = gpgscm openpgp cms migrations gpgme pkits $(tpm2dtests) .

GPGSM = ../sm/gpgsm


EXTRA_DIST = run-tests.scm gpgconf.ctl.in      \
             fake-pinentries/README.txt        \
             fake-pinentries/fake-pinentry.php \
             fake-pinentries/fake-pinentry.pl  \
             fake-pinentries/fake-pinentry.py  \
             fake-pinentries/fake-pinentry.sh  \
	     ChangeLog-2011

CLEANFILES =  x y z out err

if !HAVE_W32_SYSTEM
noinst_PROGRAMS = asschk
endif

asschk_SOURCES = asschk.c

TESTINST_DIRS = bin sbin libexec share etc

clean-local: clean-local-testinst

# We do a cd ../tests here so that we make sure tha the bin dir etc
# are under our tests dir.  This is failsafe thingy in case this
# Makefile rule is accidently run /.
clean-local-testinst:
	-(cd ../tests && rm -rf $(TESTINST_DIRS))

# Before we can run any tests we need to make sure that we have a
# proper test installation with this dir (tests) as root dir.  It is
# too hard to track the built files here thus we do the install step
# always.
check-recursive: bin/gpgconf.ctl

bin/gpgconf.ctl: FORCE
	@echo '==== Installing into a test root ======'
	@-mkdir bin 2>/dev/null
	@cat $(srcdir)/gpgconf.ctl.in > bin/gpgconf.ctl.tmp
	cd .. && \
          $(MAKE) $(AM_MAKEFLAGS) install prefix=$(abs_top_builddir)/tests
	@mv bin/gpgconf.ctl.tmp bin/gpgconf.ctl
	@echo '==== Finished installing into a test root ======'


.PHONY: FORCE clean-local-testinst
