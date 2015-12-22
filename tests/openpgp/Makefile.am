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

if SQLITE3
sqlite3_dependent_tests = tofu.test
else
sqlite3_dependent_tests =
endif

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
	import.test ecc.test 4gb-packet.test \
	$(sqlite3_dependent_tests) \
	gpgtar.test use-exact-key.test default-key.test \
	finish.test


TEST_FILES = pubring.asc secring.asc plain-1o.asc plain-2o.asc plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc plain-1-pgp.asc \
	     pubring.pkr.asc secring.skr.asc secdemo.asc pubdemo.asc \
             gpg.conf.tmpl gpg-agent.conf.tmpl \
	     bug537-test.data.asc bug894-test.asc \
	     bug1223-good.asc bug1223-bogus.asc 4gb-packet.asc \
	     tofu-keys.asc tofu-keys-secret.asc \
	     tofu-2183839A-1.txt tofu-BC15C85A-1.txt tofu-EE37CF96-1.txt

data_files = data-500 data-9000 data-32000 data-80000 plain-large

priv_keys = privkeys/50B2D4FA4122C212611048BC5FC31BD44393626E.asc \
            privkeys/7E201E28B6FEB2927B321F443205F4724EBE637E.asc \
            privkeys/13FDB8809B17C5547779F9D205C45F47CE0217CE.asc \
            privkeys/343D8AF79796EE107D645A2787A9D9252F924E6F.asc \
            privkeys/8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34.asc \
            privkeys/0D6F6AD4C4C803B25470F9104E9F4E6A4CA64255.asc \
            privkeys/FD692BD59D6640A84C8422573D469F84F3B98E53.asc \
            privkeys/76F7E2B35832976B50A27A282D9B87E44577EB66.asc \
            privkeys/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD.asc \
	    privkeys/0DD40284FF992CD24DC4AAC367037E066FCEE26A.asc \
	    privkeys/2BC997C0B8691D41D29A4EC81CCBCF08454E4961.asc \
	    privkeys/3C9D5ECA70130C2DBB1FC6AC0076BEEEC197716F.asc \
	    privkeys/449E644892C951A37525654730DD32C202079926.asc \
	    privkeys/58FFE844087634E62440224908BDE44BEA7EB730.asc \
	    privkeys/4DF9172D6FF428C97A0E9AA96F03E8BCE3B2F188.asc \
	    privkeys/9D7CD8F53F2F14C3E2177D1E9D1D11F39513A4A4.asc \
	    privkeys/6E6B7ED0BD4425018FFC54F3921D5467A3AE00EB.asc \
	    privkeys/C905D0AB6AE9655C5A35975939997BBF3325D6DD.asc \
	    privkeys/B2BAA7144303DF19BB6FDE23781DD3FDD97918D4.asc \
	    privkeys/CF60965BF51F67CF80DECE853E0D2D343468571D.asc \
	    privkeys/DF00E361D34F80868D06879AC21D7A7D4E4FAD76.asc \
	    privkeys/00FE67F28A52A8AA08FFAED20AF832DA916D1985.asc \
	    privkeys/1DF48228FEFF3EC2481B106E0ACA8C465C662CC5.asc \
	    privkeys/A2832820DC9F40751BDCD375BB0945BA33EC6B4C.asc \
	    privkeys/ADE710D74409777B7729A7653373D820F67892E0.asc \
	    privkeys/CEFC51AF91F68A2904FBFF62C4F075A4785B803F.asc


sample_keys = samplekeys/ecc-sample-1-pub.asc \
              samplekeys/ecc-sample-2-pub.asc \
              samplekeys/ecc-sample-3-pub.asc \
              samplekeys/ecc-sample-1-sec.asc \
              samplekeys/ecc-sample-2-sec.asc \
              samplekeys/ecc-sample-3-sec.asc \
	      samplekeys/eddsa-sample-1-pub.asc \
	      samplekeys/eddsa-sample-1-sec.asc \
	      samplekeys/dda252ebb8ebe1af-1.asc \
	      samplekeys/dda252ebb8ebe1af-2.asc \
	      samplekeys/whats-new-in-2.1.asc \
	      samplekeys/e2e-p256-1-clr.asc \
	      samplekeys/e2e-p256-1-prt.asc \
	      samplekeys/E657FB607BB4F21C90BB6651BC067AF28BC90111.asc

EXTRA_DIST = defs.inc pinentry.sh $(TESTS) $(TEST_FILES) ChangeLog-2011 \
	     mkdemodirs signdemokey $(priv_keys) $(sample_keys)

CLEANFILES = prepared.stamp x y yy z out err  $(data_files) \
	     plain-1 plain-2 plain-3 trustdb.gpg *.lock .\#lk* \
	     *.test.log gpg_dearmor gpg.conf gpg-agent.conf S.gpg-agent \
	     pubring.gpg pubring.gpg~ pubring.kbx pubring.kbx~ \
	     secring.gpg pubring.pkr secring.skr \
	     gnupg-test.stop random_seed gpg-agent.log tofu.db

clean-local:
	-rm -rf private-keys-v1.d openpgp-revocs.d tofu.d gpgtar.d


# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms)
