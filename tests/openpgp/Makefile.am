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
# along with this program; if not, see <http://www.gnu.org/licenses/>.
# Process this file with automake to create Makefile.in


# Programs required before we can run these tests.
required_pgms = ../../g10/gpg2 ../../agent/gpg-agent \
                ../../tools/gpg-connect-agent ../../tools/mk-tdata

TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir) GPG_AGENT_INFO= LC_ALL=C

# Note: version.test needs to be the first test to run and finish.test
# the last one
TESTS = version.test mds.test \
	decrypt.test decrypt-dsa.test \
	sigs.test sigs-dsa.test \
	encrypt.test encrypt-dsa.test  \
	seat.test clearsig.test encryptp.test detach.test \
	armsigs.test armencrypt.test armencryptp.test \
	signencrypt.test signencrypt-dsa.test \
	armsignencrypt.test armdetach.test \
	armdetachm.test detachm.test genkey1024.test \
	conventional.test conventional-mdc.test \
	multisig.test verify.test armor.test \
	import.test ecc.test finish.test


TEST_FILES = pubring.asc secring.asc plain-1o.asc plain-2o.asc plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc plain-1-pgp.asc \
	     pubring.pkr.asc secring.skr.asc secdemo.asc pubdemo.asc \
             gpg.conf.tmpl gpg-agent.conf.tmpl \
	     bug537-test.data.asc bug894-test.asc \
	     bug1223-good.asc bug1223-bogus.asc

data_files = data-500 data-9000 data-32000 data-80000 plain-large

priv_keys = privkeys/50B2D4FA4122C212611048BC5FC31BD44393626E.asc \
            privkeys/7E201E28B6FEB2927B321F443205F4724EBE637E.asc \
            privkeys/13FDB8809B17C5547779F9D205C45F47CE0217CE.asc \
            privkeys/343D8AF79796EE107D645A2787A9D9252F924E6F.asc \
            privkeys/8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34.asc \
            privkeys/0D6F6AD4C4C803B25470F9104E9F4E6A4CA64255.asc \
            privkeys/FD692BD59D6640A84C8422573D469F84F3B98E53.asc \
            privkeys/76F7E2B35832976B50A27A282D9B87E44577EB66.asc \
            privkeys/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD.asc

sample_keys = samplekeys/ecc-sample-1-pub.asc \
              samplekeys/ecc-sample-2-pub.asc \
              samplekeys/ecc-sample-3-pub.asc \
              samplekeys/ecc-sample-1-sec.asc \
              samplekeys/ecc-sample-2-sec.asc \
              samplekeys/ecc-sample-3-sec.asc

EXTRA_DIST = defs.inc pinentry.sh $(TESTS) $(TEST_FILES) ChangeLog-2011 \
	     mkdemodirs signdemokey $(priv_keys) $(sample_keys)

CLEANFILES = prepared.stamp x y yy z out err  $(data_files) \
	     plain-1 plain-2 plain-3 trustdb.gpg *.lock .\#lk* \
	     *.test.log gpg_dearmor gpg.conf gpg-agent.conf S.gpg-agent \
	     pubring.gpg secring.gpg pubring.pkr secring.skr \
	     gnupg-test.stop pubring.gpg~ random_seed gpg-agent.log

clean-local:
	-rm -rf private-keys-v1.d openpgp-revocs.d


# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms)
