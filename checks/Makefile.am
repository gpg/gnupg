# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to create Makefile.in

GPG_DEARMOR = ../g10/gpg --no-options --no-greeting --batch --quiet --yes --dearmor
GPG_IMPORT  = ../g10/gpg --homedir . --quiet --yes --import

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
	multisig.test


TEST_FILES = pubring.asc secring.asc plain-1o.asc plain-2o.asc plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc plain-1-pgp.asc \
	     pubring.pkr.asc secring.skr.asc secdemo.asc pubdemo.asc options.in

DATA_FILES = data-500 data-9000 data-32000 data-80000 plain-large

EXTRA_DIST = defs.inc run-gpg run-gpg.patterns $(TESTS) $(TEST_FILES) \
	     mkdemodirs signdemokey
CLEANFILES = prepared.stamp x y yy z out err  $(DATA_FILES) \
	     plain-1 plain-2 plain-3 options trustdb.gpg *.lock .\#lk* \
	     pubring.gpg secring.gpg pubring.pkr secring.skr options
DISTCLEANFILES = pubring.gpg~


all-local: prepared.stamp

distclean-local:
	./mkdemodirs --clean

prepared.stamp: ./pubring.gpg ./secring.gpg ./plain-1 ./plain-2 ./plain-3 \
		./pubring.pkr ./secring.skr ./options $(DATA_FILES)
	 $(GPG_IMPORT) $(srcdir)/pubdemo.asc	 
	 echo timestamp >./prepared.stamp

./options: $(srcdir)/options.in
	cat $(srcdir)/options.in >./options

./pubring.gpg: $(srcdir)/pubring.asc $(srcdir)/pubdemo.asc
	 $(GPG_DEARMOR) -o ./pubring.gpg $(srcdir)/pubring.asc

./secring.gpg: $(srcdir)/secring.asc
	 $(GPG_DEARMOR) -o ./secring.gpg $(srcdir)/secring.asc

./pubring.pkr: $(srcdir)/pubring.pkr.asc
	 $(GPG_DEARMOR) -o ./pubring.pkr $(srcdir)/pubring.pkr.asc

./secring.skr: $(srcdir)/secring.skr.asc
	 $(GPG_DEARMOR) -o ./secring.skr $(srcdir)/secring.skr.asc

./plain-1: $(srcdir)/plain-1o.asc
	 $(GPG_DEARMOR) -o ./plain-1 $(srcdir)/plain-1o.asc

./plain-2: $(srcdir)/plain-2o.asc
	 $(GPG_DEARMOR) -o ./plain-2 $(srcdir)/plain-2o.asc

./plain-3: $(srcdir)/plain-3o.asc
	 $(GPG_DEARMOR) -o ./plain-3 $(srcdir)/plain-3o.asc



data-500:
	../tools/mk-tdata   500  >data-500
data-9000:
	../tools/mk-tdata  9000  >data-9000
data-32000:
	../tools/mk-tdata 32000  >data-32000
data-80000:
	../tools/mk-tdata 80000  >data-80000
plain-large:
	cat $(srcdir)/../doc/HACKING \
	    $(srcdir)/../doc/DETAILS \
	    $(srcdir)/../doc/FAQ	 >plain-large

