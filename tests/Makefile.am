# Makefile.am -tests makefile for libxtime
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

SUBDIRS = gpgscm openpgp migrations gpgsm gpgme pkits .

GPGSM = ../sm/gpgsm

# Note that we need to use /bin/pwd so that we don't get into trouble
# if the shell used for inittests would uses an internal version of
# pwd which handles symlinks differently.
TESTS_ENVIRONMENT = GNUPGHOME=`/bin/pwd` GPG_AGENT_INFO= LC_ALL=C \
                    GPGSM=$(GPGSM) $(srcdir)/runtest

testscripts = sm-sign+verify sm-verify

EXTRA_DIST = runtest inittests $(testscripts) ChangeLog-2011 \
	     text-1.txt text-2.txt text-3.txt \
	     text-1.osig.pem text-1.dsig.pem text-1.osig-bad.pem \
	     text-2.osig.pem text-2.osig-bad.pem \
             fake-pinentries/README.txt        \
             fake-pinentries/fake-pinentry.php \
             fake-pinentries/fake-pinentry.pl  \
             fake-pinentries/fake-pinentry.py  \
             fake-pinentries/fake-pinentry.sh  \
	     samplekeys/steed-self-signing-nonthority.pem \
	     samplekeys/68A638998DFABAC510EA645CE34F9686B2EDF7EA.key \
             samplekeys/32100C27173EF6E9C4E9A25D3D69F86D37A4F939.key \
             samplekeys/cert_g10code_pete1.pem \
             samplekeys/cert_g10code_test1.pem \
             samplekeys/cert_g10code_theo1.pem \
	     run-tests.scm

# We used to run $(testscripts) here but these asschk scripts are not
# completely reliable in all environments and thus we better disable
# them.  The tests are anyway way too minimal.  We will eventually
# write new tests based on gpg-connect-agent which has a full fledged
# script language and thus makes it far easier to write tests than to
# use that low-level asschk stuff.
TESTS =

CLEANFILES = inittests.stamp x y y z out err \
	     *.lock .\#lk*

DISTCLEANFILES = pubring.kbx~ random_seed

if !HAVE_W32_SYSTEM
noinst_PROGRAMS = asschk
endif

asschk_SOURCES = asschk.c


all-local: inittests.stamp

clean-local:
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp
