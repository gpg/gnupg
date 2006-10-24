# Copyright (C) 1998, 1999, 2000, 2001, 2002,
#               2003, 2006  Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

## Process this file with automake to produce Makefile.in

EXTRA_DIST = options.skel

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/common \
              -I$(top_srcdir)/include -I$(top_srcdir)/intl 

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)

needed_libs = ../gl/libgnu.a ../common/libcommon.a ../jnlib/libjnlib.a

bin_PROGRAMS = gpg2 gpgv2

if ENABLE_BZIP2_SUPPORT
bzip2_source = compress-bz2.c
else
bzip2_source =
endif


common_source =  \
	      gpg.h             \
	      build-packet.c	\
	      compress.c	\
	      $(bzip2_source)	\
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
	      pkglue.c pkglue.h 

gpg2_SOURCES  = gpg.c		\
	      $(common_source)	\
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
	      helptext.c        \
	      keyserver.c       \
	      keyserver-internal.h \
	      photoid.c photoid.h \
	      call-agent.c call-agent.h \
	      card-util.c \
	      exec.c exec.h

gpgv2_SOURCES = gpgv.c           \
	      $(common_source)  \
	      verify.c          

#gpgd_SOURCES = gpgd.c \
#	       ks-proto.h \
#	       ks-proto.c \
#	       ks-db.c \
#	       ks-db.h \
#	       $(common_source)

LDADD =  $(needed_libs) ../common/libgpgrl.a \
         $(ZLIBS) $(DNSLIBS) $(LIBREADLINE) \
         $(LIBINTL) $(CAPLIBS) $(NETLIBS)
gpg2_LDADD = $(LIBGCRYPT_LIBS) $(LDADD) $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS)
gpgv2_LDADD = $(LIBGCRYPT_LIBS) $(LDADD) $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS)

$(PROGRAMS): $(needed_libs) ../common/libgpgrl.a

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/options.skel \
				$(DESTDIR)$(pkgdatadir)/gpg-conf.skel

