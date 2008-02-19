# Makefile.am - tests using NIST's PKITS
#     	Copyright (C) 2004, 2008 Free Software Foundation, Inc.
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

GPGSM = ../../sm/gpgsm

TESTS_ENVIRONMENT = GNUPGHOME=`pwd` GPG_AGENT_INFO= LC_ALL=C GPGSM=$(GPGSM) \
		    silent=yes


testscripts = import-all-certs validate-all-certs \
	signature-verification        \
	validity-periods              \
	verifying-name-chaining       \
	basic-certificate-revocation  \
	verifying-paths-self-issued   \
	verifying-basic-constraints   \
	key-usage                     \
	certificate-policies          \
	require-explicit-policy       \
	policy-mappings               \
	inhibit-policy-mapping        \
	inhibit-any-policy            \
	name-constraints              \
	distribution-points           \
	delta-crls                    \
	private-certificate-extensions


EXTRA_DIST = PKITS_data.tar.bz2 inittests runtest $(testscripts) 
	     import-all-certs.data 

TESTS = $(testscripts)

CLEANFILES = inittests.stamp x y y z out err  *.lock .\#lk* *.log

DISTCLEANFILES = pubring.kbx~ random_seed

all-local: inittests.stamp

clean-local:
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp


run-all-tests:
	@set -e; \
         GNUPGHOME=`pwd`; export GNUPGHOME;\
         unset GPG_AGENT_INFO; \
         for test in $(testscripts); do \
           ./$${test} && true; \
         done
