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

TESTS_ENVIRONMENT = GNUPGHOME=`/bin/pwd` GPG_AGENT_INFO= LC_ALL=C \
                    GPGSM=$(GPGSM) silent=yes


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


EXTRA_DIST = inittests runtest common.sh $(testscripts) ChangeLog-2011 \
	     import-all-certs.data

TESTS = $(testscripts)

CLEANFILES = inittests.stamp scratch.*.tmp x y z out err  *.lock .\#lk* *.log

DISTCLEANFILES = pubring.kbx~ random_seed

all-local: inittests.stamp

clean-local:
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp


run-all-tests: inittests.stamp
	@set -e; \
         GNUPGHOME=`/bin/pwd`; export GNUPGHOME;\
         unset GPG_AGENT_INFO; \
         for tst in $(testscripts); do \
           if ./$${tst}; then : ; \
           elif test $$? -eq 77; then echo "- SKIP $$tst"; \
	   fi; \
         done


