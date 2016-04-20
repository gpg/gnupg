# Makefile.am - For tests/openpgp
# Copyright (C) 2016 g10 Code GmbH
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
# Process this file with automake to create Makefile.in


# Programs required before we can run these tests.
required_pgms = ../../g10/gpg$(EXEEXT) ../../agent/gpg-agent$(EXEEXT)

AM_CPPFLAGS = -I$(top_srcdir)/common
include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =

TESTS_ENVIRONMENT = GPG_AGENT_INFO= LC_ALL=C

TESTS = from-classic.test

TEST_FILES = from-classic.gpghome/pubring.gpg.asc \
	     from-classic.gpghome/secring.gpg.asc \
	     from-classic.gpghome/trustdb.gpg.asc

EXTRA_DIST = $(TESTS) $(TEST_FILES)

CLEANFILES = prepared.stamp x y yy z out err  $(data_files) \
	     plain-1 plain-2 plain-3 trustdb.gpg *.lock .\#lk* \
	     *.test.log gpg_dearmor gpg.conf gpg-agent.conf S.gpg-agent \
	     pubring.gpg pubring.gpg~ pubring.kbx pubring.kbx~ \
	     secring.gpg pubring.pkr secring.skr \
	     gnupg-test.stop random_seed gpg-agent.log tofu.db

clean-local:
	-rm -rf from-classic.gpghome/*.gpg

# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms)
