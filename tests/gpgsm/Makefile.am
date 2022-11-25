# Makefile.am - For tests/gpgme
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
# along with this program; if not, see <https://www.gnu.org/licenses/>.
# Process this file with automake to create Makefile.in


# Programs required before we can run these tests.
required_pgms = ../../g10/gpg$(EXEEXT) ../../agent/gpg-agent$(EXEEXT) \
                ../../tools/gpg-connect-agent$(EXEEXT) \
		../gpgscm/gpgscm$(EXEEXT)

AM_CPPFLAGS = -I$(top_srcdir)/common
include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =

TESTS_ENVIRONMENT = LC_ALL=C \
	EXEEXT=$(EXEEXT) \
	PATH="../gpgscm:$(PATH)" \
	abs_top_srcdir="$(abs_top_srcdir)" \
	objdir="$(abs_top_builddir)" \
	GPGSCM_PATH="$(abs_top_srcdir)/tests/gpgscm"

XTESTS = \
	import.scm \
	encrypt.scm \
	verify.scm \
	decrypt.scm \
	sign.scm \
	export.scm

# XXX: Currently, one cannot override automake's 'check' target.  As a
# workaround, we avoid defining 'TESTS', thus automake will not emit
# the 'check' target.  For extra robustness, we merely define a
# dependency on 'xcheck', so this hack should also work even if
# automake would emit the 'check' target, as adding dependencies to
# targets is okay.
check: xcheck

.PHONY: xcheck
xcheck:
	$(TESTS_ENVIRONMENT) $(abs_top_builddir)/tests/gpgscm/gpgscm$(EXEEXT) \
	  $(abs_srcdir)/run-tests.scm $(TESTFLAGS) $(TESTS)

KEYS =	32100C27173EF6E9C4E9A25D3D69F86D37A4F939
CERTS =	cert_g10code_test1.der \
	cert_dfn_pca01.der \
	cert_dfn_pca15.der
TEST_FILES = plain-1.cms.asc \
	plain-2.cms.asc \
	plain-3.cms.asc \
	plain-large.cms.asc

EXTRA_DIST = $(XTESTS) $(KEYS) $(CERTS) $(TEST_FILES) \
	gpgsm-defs.scm run-tests.scm setup.scm all-tests.scm

CLEANFILES = *.log report.xml

# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms)
