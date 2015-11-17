# Copyright (C) 1998, 1999, 2000, 2001, 2002,
#               2003, 2006, 2010  Free Software Foundation, Inc.
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

EXTRA_DIST = options.skel dirmngr-conf.skel distsigkey.gpg \
	     ChangeLog-2011 gpg-w32info.rc \
	     gpg.w32-manifest.in test.c t-keydb-keyring.kbx \
	     t-keydb-get-keyblock.gpg

AM_CPPFLAGS = -I$(top_srcdir)/common

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(SQLITE3_CFLAGS) $(LIBGCRYPT_CFLAGS) \
            $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)

needed_libs = ../kbx/libkeybox.a $(libcommon)

bin_PROGRAMS = gpg2
if !HAVE_W32CE_SYSTEM
bin_PROGRAMS += gpgv2
endif
noinst_PROGRAMS = $(module_tests)
TESTS = $(module_tests)

if ENABLE_BZIP2_SUPPORT
bzip2_source = compress-bz2.c
else
bzip2_source =
endif

if ENABLE_CARD_SUPPORT
card_source = card-util.c
else
card_source =
endif

if NO_TRUST_MODELS
trust_source =
else
trust_source = trustdb.c trustdb.h tdbdump.c tdbio.c tdbio.h
endif

if USE_TOFU
tofu_source = tofu.h tofu.c sqlite.c sqlite.h
else
tofu_source =
endif


if HAVE_W32_SYSTEM
resource_objs += gpg-w32info.o

gpg-w32info.o : gpg.w32-manifest

endif

common_source =  \
	      gpg.h             \
	      dek.h             \
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
              rmd160.c rmd160.h \
	      options.h 	\
	      openfile.c	\
	      keyid.c		\
	      packet.h		\
	      parse-packet.c	\
	      cpr.c		\
	      plaintext.c	\
	      sig-check.c	\
	      keylist.c 	\
	      pkglue.c pkglue.h \
	      ecdh.c

gpg2_SOURCES  = gpg.c		\
	      server.c          \
	      $(common_source)	\
	      pkclist.c 	\
	      skclist.c 	\
	      pubkey-enc.c	\
	      passphrase.c	\
	      decrypt.c 	\
	      decrypt-data.c	\
	      cipher.c		\
	      encrypt.c		\
	      sign.c		\
	      verify.c		\
	      revoke.c		\
	      keyedit.c 	\
	      dearmor.c 	\
	      import.c		\
	      export.c		\
	      migrate.c         \
	      delkey.c		\
	      keygen.c          \
	      helptext.c        \
	      keyserver.c       \
	      keyserver-internal.h \
	      call-dirmngr.c call-dirmngr.h \
	      photoid.c photoid.h \
	      call-agent.c call-agent.h \
	      trust.c $(trust_source) $(tofu_source) \
	      $(card_source) \
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
         $(ZLIBS) $(LIBINTL) $(CAPLIBS) $(NETLIBS)
gpg2_LDADD = $(LDADD) $(SQLITE3_LIBS) $(LIBGCRYPT_LIBS) $(LIBREADLINE) \
             $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) \
	     $(LIBICONV) $(resource_objs) $(extra_sys_libs)
gpg2_LDFLAGS = $(extra_bin_ldflags)
gpgv2_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
              $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(resource_objs) $(extra_sys_libs)
gpgv2_LDFLAGS = $(extra_bin_ldflags)

t_common_ldadd =
module_tests = t-rmd160 t-keydb t-keydb-get-keyblock
t_rmd160_SOURCES = t-rmd160.c rmd160.c
t_rmd160_LDADD = $(t_common_ldadd)
t_keydb_SOURCES = t-keydb.c test-stubs.c $(common_source)
t_keydb_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(t_common_ldadd)
t_keydb_get_keyblock_SOURCES = t-keydb-get-keyblock.c test-stubs.c \
	      $(common_source)
t_keydb_get_keyblock_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(t_common_ldadd)


$(PROGRAMS): $(needed_libs) ../common/libgpgrl.a

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/options.skel \
				$(DESTDIR)$(pkgdatadir)/gpg-conf.skel
	$(INSTALL_DATA) $(srcdir)/dirmngr-conf.skel \
				$(DESTDIR)$(pkgdatadir)/dirmngr-conf.skel
	$(INSTALL_DATA) $(srcdir)/distsigkey.gpg \
				$(DESTDIR)$(pkgdatadir)/distsigkey.gpg

uninstall-local:
	-@rm $(DESTDIR)$(pkgdatadir)/gpg-conf.skel
	-@rm $(DESTDIR)$(pkgdatadir)/dirmngr-conf.skel
	-@rm $(DESTDIR)$(pkgdatadir)/distsigkey.gpg


# There has never been a gpg for WindowsCE, thus we don't need a gpg2 here
if HAVE_W32CE_SYSTEM
install-exec-hook:
	mv -f $(DESTDIR)$(bindir)/gpg2$(EXEEXT) \
              $(DESTDIR)$(bindir)/gpg$(EXEEXT)
endif
