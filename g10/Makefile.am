# Makefile.am - g10
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
# along with this program; if not, see <https://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

EXTRA_DIST = distsigkey.gpg \
             gpg-w32info.rc  gpg.w32-manifest.in \
	     gpgv-w32info.rc gpgv.w32-manifest.in \
	     ChangeLog-2011 test.c t-keydb-keyring.kbx \
	     t-keydb-get-keyblock.gpg t-stutter-data.asc \
	     all-tests.scm

AM_CPPFLAGS = -DREGEXP_PREFIX=gnupg_

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(SQLITE3_CFLAGS) $(LIBGCRYPT_CFLAGS) \
            $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) $(GPG_ERROR_CFLAGS)

needed_libs = ../kbx/libkeybox.a $(libcommonpth) ../regexp/libregexp.a


bin_PROGRAMS = gpg gpgv

noinst_PROGRAMS = $(module_tests)
if DISABLE_TESTS
TESTS =
else
TESTS = $(module_tests)
endif
TESTS_ENVIRONMENT = \
	abs_top_srcdir=$(abs_top_srcdir)

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
tofu_source = tofu.h tofu.c gpgsql.c gpgsql.h
else
tofu_source =
endif


if HAVE_W32_SYSTEM
gpg_rc_objs = gpg-w32info.o
gpgv_rc_objs = gpgv-w32info.o

gpg-w32info.o  : gpg.w32-manifest   ../common/w32info-rc.h
gpgv-w32info.o : gpgv.w32-manifest  ../common/w32info-rc.h
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
	      expand-group.c	\
	      keydb.h           \
	      keydb-private.h   \
              call-keyboxd.c    \
	      keydb.c           \
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
	      objcache.c objcache.h \
	      ecdh.c

gpg_sources = server.c          \
	      $(common_source)	\
	      pkclist.c 	\
	      skclist.c 	\
	      pubkey-enc.c	\
	      passphrase.c	\
	      decrypt.c 	\
	      decrypt-data.c	\
	      cipher-cfb.c	\
	      cipher-aead.c     \
	      encrypt.c		\
	      sign.c		\
	      verify.c		\
	      revoke.c		\
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
	      exec.c exec.h \
              key-clean.c key-clean.h \
	      key-check.c key-check.h

gpg_SOURCES  = gpg.c \
	keyedit.c keyedit.h	\
	$(gpg_sources)

gpgv_SOURCES = gpgv.c           \
	      $(common_source)  \
	      verify.c

LDADD =  $(needed_libs) ../common/libgpgrl.a \
         $(ZLIBS) $(LIBINTL) $(CAPLIBS)
gpg_LDADD = $(LDADD) $(SQLITE3_LIBS) $(LIBGCRYPT_LIBS) $(LIBREADLINE) \
             $(LIBASSUAN_LIBS) $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	     $(LIBICONV) $(gpg_rc_objs)
gpg_LDFLAGS =
gpgv_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
	      $(LIBASSUAN_LIBS) $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	      $(LIBICONV) $(gpgv_rc_objs)
gpgv_LDFLAGS =


t_common_ldadd =
module_tests = t-rmd160 t-keydb t-keydb-get-keyblock t-stutter t-keyid
t_rmd160_SOURCES = t-rmd160.c rmd160.c
t_rmd160_LDADD = $(t_common_ldadd)
t_keydb_SOURCES = t-keydb.c test-stubs.c $(common_source)
t_keydb_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
              $(LIBASSUAN_LIBS) $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	      $(LIBICONV) $(t_common_ldadd)
t_keydb_get_keyblock_SOURCES = t-keydb-get-keyblock.c test-stubs.c \
	      $(common_source)
t_keydb_get_keyblock_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
              $(LIBASSUAN_LIBS) $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	      $(LIBICONV) $(t_common_ldadd)
t_stutter_SOURCES = t-stutter.c test-stubs.c \
	      $(common_source)
t_stutter_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
	      $(LIBASSUAN_LIBS) $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	      $(LIBICONV) $(t_common_ldadd)
t_keyid_SOURCES = t-keyid.c test-stubs.c $(common_source)
t_keyid_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
              $(LIBASSUAN_LIBS) $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	      $(LIBICONV) $(t_common_ldadd)


$(PROGRAMS): $(needed_libs) ../common/libgpgrl.a


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/distsigkey.gpg \
				$(DESTDIR)$(pkgdatadir)/distsigkey.gpg

uninstall-local:
	-@rm $(DESTDIR)$(pkgdatadir)/distsigkey.gpg
