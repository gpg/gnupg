# Makefile.am - For tests/openpgp
# Copyright (C) 1998, 1999, 2000, 2001, 2003,
#               2010 Free Software Foundation, Inc.
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
		../gpgscm/gpgscm$(EXEEXT) ../openpgp/fake-pinentry$(EXEEXT)

AM_CPPFLAGS = -I$(top_srcdir)/common
include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =

TESTS_ENVIRONMENT = LC_ALL=C \
	EXEEXT=$(EXEEXT) \
	PATH="../gpgscm:$(PATH)" \
	abs_top_srcdir="$(abs_top_srcdir)" \
	objdir="$(abs_top_builddir)" \
	TPMSERVER="$(TPMSERVER)" TSSSTARTUP="$(TSSSTARTUP)" \
	SWTPM="$(SWTPM)" \
        GNUPG_BUILD_ROOT="$(abs_top_builddir)" \
	GNUPG_IN_TEST_SUITE=fact \
	GPGSCM_PATH="$(abs_top_srcdir)/tests/gpgscm"

XTESTS = \
	rsa.scm \
	ecc.scm \
	longpassphrase.scm \
	unimportable.scm

# XXX: Currently, one cannot override automake's 'check' target.  As a
# workaround, we avoid defining 'TESTS', thus automake will not emit
# the 'check' target.  For extra robustness, we merely define a
# dependency on 'xcheck', so this hack should also work even if
# automake would emit the 'check' target, as adding dependencies to
# targets is okay.
check: xcheck

.PHONY: xcheck
xcheck: tpm_server_found
	$(TESTS_ENVIRONMENT) $(abs_top_builddir)/tests/gpgscm/gpgscm \
	  $(abs_srcdir)/run-tests.scm $(TESTFLAGS) $(TESTS)

tpm_server_found:
	@if [ -z "$(TPMSERVER)" -a -z "$(SWTPM)" -a -z "$(FORCE)" ]; then echo "ERROR: No Software TPM has been found, cannot run TPM tests.  Set FORCE=1 to force using the physical TPM"; exit 1; fi

EXTRA_DIST = defs.scm shell.scm all-tests.scm run-tests.scm $(XTESTS) \
	     start_sw_tpm.sh setup.scm

CLEANFILES = gpg.conf gpg-agent.conf S.gpg-agent \
	     pubring.gpg pubring.gpg~ pubring.kbx pubring.kbx~ \
	     secring.gpg pubring.pkr secring.skr \
	     gnupg-test.stop random_seed gpg-agent.log tofu.db \
	     passphrases sshcontrol S.gpg-agent.ssh report.xml \
	     msg.txt *.log

clean-local:
	-rm -rf private-keys-v1.d openpgp-revocs.d


# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms)
