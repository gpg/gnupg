# Copyright (C) 1998, 1999, 2000, 2001, 2002,
#               2003  Free Software Foundation, Inc.
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

## Process this file with automake to produce Makefile.in

localedir = $(datadir)/locale
INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/include -I$(top_srcdir)/intl -DLOCALEDIR=\"$(localedir)\"

EXTRA_DIST = options.skel
# it seems that we can't use this with automake 1.5
#OMIT_DEPENDENCIES = zlib.h zconf.h
libexecdir = @libexecdir@/@PACKAGE@
if ! HAVE_DOSISH_SYSTEM
AM_CFLAGS = -DGNUPG_LIBEXECDIR="\"$(libexecdir)\""
endif
needed_libs = ../common/libcommon.a ../jnlib/libjnlib.a

#noinst_PROGRAMS = gpgd
bin_PROGRAMS = gpg gpgv

common_source =  \
	      global.h gpg.h    \
	      build-packet.c	\
	      compress.c	\
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
	      comment.c 	\
	      status.c		\
	      status.h		\
	      plaintext.c	\
	      sig-check.c	\
	      keylist.c 	\
	      pkglue.c pkglue.h 

gpg_SOURCES  = g10.c		\
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
	      pipemode.c        \
	      helptext.c        \
	      keyserver.c       \
	      keyserver-internal.h \
	      photoid.c photoid.h \
	      call-agent.c call-agent.h \
	      card-util.c \
	      exec.c exec.h

gpgv_SOURCES = gpgv.c           \
	      $(common_source)  \
	      verify.c          

#gpgd_SOURCES = gpgd.c \
#	       ks-proto.h \
#	       ks-proto.c \
#	       ks-db.c \
#	       ks-db.h \
#	       $(common_source)

LDADD =  $(needed_libs) @INTLLIBS@ @CAPLIBS@ @ZLIBS@ 
gpg_LDADD = $(LIBGCRYPT_LIBS) $(LDADD) -lassuan -lgpg-error
gpgv_LDADD = $(LIBGCRYPT_LIBS) $(LDADD) -lassuan -lgpg-error

$(PROGRAMS): $(needed_libs)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/options.skel \
				$(DESTDIR)$(pkgdatadir)/options.skel
	@set -e;\
	 if test -f $(DESTDIR)$(bindir)/gpgm ; then \
	   echo "removing obsolete gpgm binary" ;   \
	   rm $(DESTDIR)$(bindir)/gpgm ;	    \
	 fi
