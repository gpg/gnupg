# Makefile.am -tests makefile for libxtime
#     	Copyright (C) 2002 Free Software Foundation, Inc.
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

GPGSM = ../sm/gpgsm

# We can't unset a variable here so we unset GPG_AGENT_INFO in runtest
TESTS_ENVIRONMENT = GNUPGHOME=`pwd` LC_ALL=C GPGSM=$(GPGSM) $(srcdir)/runtest

EXTRA_DIST = runtest inittests \
	     text-1.txt text-2.txt text-3.txt \
	     text-1.osig.pem text-1.dsig.pem text-1.osig-bad.pem \
	     text-2.osig.pem text-2.osig-bad.pem

TESTS = sm-sign+verify sm-verify

CLEANFILES = inittests.stamp x y y z out err 
	     *.lock .\#lk* 

DISTCLEANFILES = keyring.kbx~ random_seed

noinst_PROGRAMS = asschk

asschk_SOURCES = asschk.c


all-local: inittests.stamp

clean-local:
	$(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	$(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp

# Include all files listed in the samplekeys/distfiles
dist-hook:
	@set -e; \
         dir=$(srcdir)/samplekeys ; \
         $(mkinstalldirs) $(distdir)/$$dir ; \
         for i in distfiles `cat $$dir/distfiles` ; do \
		ln $(srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	 done




