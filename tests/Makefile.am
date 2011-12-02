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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in


if RUN_GPG_TESTS
openpgp = openpgp
else
openpgp =
endif

SUBDIRS = ${openpgp} . pkits

GPGSM = ../sm/gpgsm

# Note that we need to use /bin/pwd so that we don't get into trouble
# if the shell used for inittests would use an internal version of
# pwd which handles symlinks differently.
TESTS_ENVIRONMENT = GNUPGHOME=`/bin/pwd` GPG_AGENT_INFO= LC_ALL=C \
                    GPGSM=$(GPGSM) $(srcdir)/runtest

testscripts = sm-sign+verify sm-verify

EXTRA_DIST = runtest inittests $(testscripts) ChangeLog-2011 \
	     text-1.txt text-2.txt text-3.txt \
	     text-1.osig.pem text-1.dsig.pem text-1.osig-bad.pem \
	     text-2.osig.pem text-2.osig-bad.pem \
             samplekeys/32100C27173EF6E9C4E9A25D3D69F86D37A4F939.key \
             samplekeys/cert_g10code_pete1.pem \
             samplekeys/cert_g10code_test1.pem \
             samplekeys/cert_g10code_theo1.pem

# We used to run $(testscripts) here but these asschk scripts are not
# completely reliable in all enviromnets and thus we better disable
# them.  The tests are anyway way too minimal.  We will eventually
# write new tests based on gpg-connect-agent which has a full fledged
# script language and thus makes it far easier to write tests than to
# use the low--level asschk stuff.
TESTS =

CLEANFILES = inittests.stamp x y y z out err \
	     *.lock .\#lk*

DISTCLEANFILES = pubring.kbx~ random_seed

noinst_PROGRAMS = asschk

asschk_SOURCES = asschk.c


all-local: inittests.stamp

clean-local:
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp

