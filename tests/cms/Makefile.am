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

GPGSM = ../../sm/gpgsm

# Note that we need to use /bin/pwd so that we don't get into trouble
# if the shell used for inittests would uses an internal version of
# pwd which handles symlinks differently.
OLD_TESTS_ENVIRONMENT = GNUPGHOME=`/bin/pwd` GPG_AGENT_INFO= LC_ALL=C \
                        GNUPG_BUILD_ROOT="$(abs_top_builddir)" \
			GNUPG_IN_TEST_SUITE=fact \
	                GPGSM="$(GPGSM)$(EXEEXT)" "$(srcdir)/runtest"

TESTS_ENVIRONMENT = LC_ALL=C \
	EXEEXT=$(EXEEXT) \
	PATH="../gpgscm:$(PATH)" \
	abs_top_srcdir="$(abs_top_srcdir)" \
	objdir="$(abs_top_builddir)" \
        GNUPG_BUILD_ROOT="$(abs_top_builddir)" \
	GNUPG_IN_TEST_SUITE=fact \
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

# We used to run $(testscripts) here but these asschk scripts are not
# completely reliable in all environments and thus we better disable
# them.  The tests are anyway way too minimal.  We will eventually
# write new tests based on gpg-connect-agent which has a full fledged
# script language and thus makes it far easier to write tests than to
# use that low-level asschk stuff.
testscripts = sm-sign+verify sm-verify

EXTRA_DIST = $(XTESTS) $(KEYS) $(CERTS) $(TEST_FILES) \
             samplemsgs/README \
	     samplekeys/Description-p12 \
	     samplekeys/steed-self-signing-nonthority.pem \
	     samplekeys/68A638998DFABAC510EA645CE34F9686B2EDF7EA.key \
             samplekeys/32100C27173EF6E9C4E9A25D3D69F86D37A4F939.key \
             samplekeys/cert_g10code_pete1.pem \
             samplekeys/cert_g10code_test1.pem \
             samplekeys/cert_g10code_theo1.pem \
             samplekeys/ov-user.p12 \
             samplekeys/ov-server.p12 \
             samplekeys/opensc-test.p12 \
             samplekeys/t5793-openssl.pfx \
             samplekeys/t5793-test.pfx \
             samplekeys/t6752-ov-user-ff.p12 \
             samplekeys/edward.tester@demo.gnupg.com.p12 \
	     samplekeys/nistp256-openssl-self-signed.p12 \
             samplekeys/credential_private_encrypted_AES256.p12 \
             samplekeys/credential_private_encrypted_3DES.p12 \
             samplemsgs/pwri-sample.cbc.p7m \
             samplemsgs/pwri-sample.cbc-2.p7m \
             samplemsgs/pwri-sample.gcm.p7m \
	     text-1.txt text-2.txt text-3.txt \
	     text-1.osig.pem text-1.dsig.pem text-1.osig-bad.pem \
	     text-2.osig.pem text-2.osig-bad.pem \
             runtest inittests $(testscripts) \
	     gpgsm-defs.scm run-tests.scm setup.scm all-tests.scm

CLEANFILES = inittests.stamp *.lock *.log report.xml .\#lk*

DISTCLEANFILES = pubring.kbx~ random_seed

# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms) inittests.stamp

clean-local:
	srcdir=$(srcdir) $(OLD_TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(OLD_TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp
