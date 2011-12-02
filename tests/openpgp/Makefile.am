# Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
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

GPG_IMPORT = ../../g10/gpg2 --homedir . \
              --quiet --yes --no-permission-warning --import

# Programs required before we can run these tests.
required_pgms = ../../g10/gpg2 ../../agent/gpg-agent \
                ../../tools/gpg-connect-agent


TESTS_ENVIRONMENT = GNUPGHOME=$(abs_builddir) GPG_AGENT_INFO= LC_ALL=C \
		    ../../agent/gpg-agent --quiet --daemon sh


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
	import.test


TEST_FILES = pubring.asc secring.asc plain-1o.asc plain-2o.asc plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc plain-1-pgp.asc \
	     pubring.pkr.asc secring.skr.asc secdemo.asc pubdemo.asc \
             gpg.conf.tmpl gpg-agent.conf.tmpl \
             bug537-test.data.asc bug894-test.asc

DATA_FILES = data-500 data-9000 data-32000 data-80000 plain-large

EXTRA_DIST = defs.inc $(TESTS) $(TEST_FILES) ChangeLog-2011 \
	     mkdemodirs signdemokey

# Note that removing S.gpg-agent forces a running gpg-agent to
# terminate after some time.
CLEANFILES = prepared.stamp x y yy z out err  $(DATA_FILES) \
	     plain-1 plain-2 plain-3 trustdb.gpg *.lock .\#lk* \
	     *.test.log gpg_dearmor gpg.conf gpg-agent.conf S.gpg-agent \
	     pubring.gpg secring.gpg pubring.pkr secring.skr

DISTCLEANFILES = pubring.gpg~ random_seed


all-local: prepared.stamp

distclean-local:
	$(srcdir)/mkdemodirs --clean

prepared.stamp: ./pubring.gpg ./secring.gpg ./plain-1 ./plain-2 ./plain-3 \
		./pubring.pkr ./secring.skr ./gpg_dearmor $(DATA_FILES)
	 $(GPG_IMPORT) $(srcdir)/pubdemo.asc
	 cat $(srcdir)/gpg-agent.conf.tmpl > gpg-agent.conf
	 echo timestamp >./prepared.stamp


# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
./gpg_dearmor: $(required_pgms)
	echo '#!/bin/sh' >./gpg_dearmor
	echo "../../g10/gpg2 --no-options --no-greeting \
             --no-secmem-warning --batch --dearmor" >>./gpg_dearmor
	chmod 755 ./gpg_dearmor

./pubring.gpg: $(srcdir)/pubring.asc $(srcdir)/pubdemo.asc ./gpg_dearmor
	./gpg_dearmor > ./pubring.gpg < $(srcdir)/pubring.asc

./secring.gpg: $(srcdir)/secring.asc ./gpg_dearmor
	./gpg_dearmor > ./secring.gpg < $(srcdir)/secring.asc

./pubring.pkr: $(srcdir)/pubring.pkr.asc ./gpg_dearmor
	./gpg_dearmor > ./pubring.pkr < $(srcdir)/pubring.pkr.asc

./secring.skr: $(srcdir)/secring.skr.asc ./gpg_dearmor
	./gpg_dearmor > ./secring.skr < $(srcdir)/secring.skr.asc

./plain-1: $(srcdir)/plain-1o.asc ./gpg_dearmor
	./gpg_dearmor > ./plain-1 < $(srcdir)/plain-1o.asc

./plain-2: $(srcdir)/plain-2o.asc ./gpg_dearmor
	./gpg_dearmor > ./plain-2 < $(srcdir)/plain-2o.asc

./plain-3: $(srcdir)/plain-3o.asc ./gpg_dearmor
	./gpg_dearmor > ./plain-3 < $(srcdir)/plain-3o.asc


data-500:
	../../tools/mk-tdata   500  >data-500
data-9000:
	../../tools/mk-tdata  9000  >data-9000
data-32000:
	../../tools/mk-tdata 32000  >data-32000
data-80000:
	../../tools/mk-tdata 80000  >data-80000
plain-large:
	cat $(srcdir)/../../doc/HACKING \
	    $(srcdir)/../../doc/DETAILS \
	    $(srcdir)/../../doc/gpg.texi >plain-large

# To speed up key generation we create a dummy random seed file
random_seed:
	../../tools/mk-tdata 600

