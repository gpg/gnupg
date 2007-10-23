# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
#               2005 Free Software Foundation, Inc.
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

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/intl @LIBUSB_CPPFLAGS@

# it seems that we can't use this with automake 1.5
#OMIT_DEPENDENCIES = zlib.h zconf.h

if ! HAVE_DOSISH_SYSTEM
AM_CPPFLAGS += -DLOCALEDIR="\"$(localedir)\""
AM_CPPFLAGS += -DGNUPG_LIBEXECDIR="\"$(libexecdir)/@PACKAGE@\""
AM_CPPFLAGS += -DGNUPG_DATADIR="\"$(pkgdatadir)\""
AM_CPPFLAGS += -DGNUPG_LIBDIR="\"$(libdir)/@PACKAGE@\""
endif

needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a
other_libs = $(LIBICONV) $(DNSLIBS) $(LIBINTL) $(CAPLIBS)

bin_PROGRAMS = gpg gpgv
dist_pkgdata_DATA = options.skel

if ENABLE_BZIP2_SUPPORT
bzip2_source = compress-bz2.c
else
bzip2_source =
endif

common_source =  \
	      global.h          \
	      build-packet.c	\
	      compress.c	\
	      $(bzip2_source)   \
	      filter.h		\
	      free-packet.c	\
	      getkey.c		\
	      keydb.c keydb.h    \
	      keyring.c keyring.h \
	      seskey.c		\
	      kbnode.c		\
	      main.h		\
	      mainproc.c	\
	      armor.c		\
	      mdfilter.c	\
	      textfilter.c	\
	      progress.c	\
	      misc.c		\
	      options.h 	\
	      openfile.c	\
	      keyid.c		\
	      packet.h		\
	      parse-packet.c	\
	      status.c		\
	      status.h		\
	      plaintext.c	\
	      sig-check.c	\
	      keylist.c 	\
	      signal.c

if ENABLE_CARD_SUPPORT
card_support_source_gpg = card-util.c 
card_support_source_scd = \
	app-common.h \
	app-openpgp.c \
	iso7816.c iso7816.h \
	apdu.c apdu.h \
	ccid-driver.c ccid-driver.h
card_support_source_local = cardglue.c cardglue.h tlv.c tlv.h
else
card_support_source_gpg =
card_support_source_scd = 
card_support_source_local =
endif

card_support_source = $(card_support_source_local) $(card_support_source_gpg) $(card_support_source_scd)

gpg_SOURCES  = gpg.c		\
	      $(common_source)	\
	      $(card_support_source) \
	      pkclist.c 	\
	      skclist.c 	\
	      pubkey-enc.c	\
	      passphrase.c	\
	      seckey-cert.c	\
	      encr-data.c	\
	      cipher.c		\
	      encode.c		\
	      sign.c		\
	      verify.c		\
	      revoke.c		\
	      decrypt.c 	\
	      keyedit.c 	\
	      dearmor.c 	\
	      import.c		\
	      export.c		\
	      trustdb.c 	\
	      trustdb.h 	\
	      tdbdump.c 	\
	      tdbio.c		\
	      tdbio.h		\
	      delkey.c		\
	      keygen.c          \
	      pipemode.c        \
	      helptext.c        \
	      keyserver.c       \
	      keyserver-internal.h \
	      photoid.c photoid.h \
	      exec.c exec.h

gpgv_SOURCES = gpgv.c           \
	      $(common_source)  \
	      verify.c          

LDADD =  $(needed_libs) $(other_libs) @ZLIBS@ @W32LIBS@ @LIBREADLINE@
gpg_LDADD = $(LDADD) @DLLIBS@ @NETLIBS@ @LIBUSB@

$(PROGRAMS): $(needed_libs)

install-exec-hook:
	@set -e;\
	 if test -f $(DESTDIR)$(bindir)/gpgm ; then \
	   echo "removing obsolete gpgm binary" ;   \
	   rm $(DESTDIR)$(bindir)/gpgm ;	    \
	 fi

# Helper to update some source files.
update-source-from-gnupg-2:
	@set -e; \
	 if test -d ../../gnupg-1.9/scd; then dir="../../gnupg-1.9"; \
	 elif test -d ../../gnupg/scd; then dir="../../gnupg"; \
	 else exit 1; \
	 fi; \
	 for i in $(card_support_source_scd); do \
           cp $$dir/scd/$$i $$i; echo $$i; \
	 done ;\
	 for i in $(card_support_source_gpg); do \
           cp $$dir/g10/$$i $$i; echo $$i; \
	 done ; \
	 echo "Please remember to update the ChangeLog accordingly!"
