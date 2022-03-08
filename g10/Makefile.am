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
	     ChangeLog-2011 \
             gpg-w32info.rc gpg.w32-manifest.in \
             gpgv-w32info.rc gpgv.w32-manifest.in \
	     test.c t-keydb-keyring.kbx \
	     t-keydb-get-keyblock.gpg t-stutter-data.asc \
	     all-tests.scm

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(SQLITE3_CFLAGS) \
            $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)

needed_libs = ../kbx/libkeybox.a $(libcommon) ../regexp/libregexp.a

# Because there are no program specific transform macros we need to
# work around that to allow installing gpg as gpg2.
gpg2_hack_list = gpg gpgv
if USE_GPG2_HACK
gpg2_hack_uninst = gpg2 gpgv2
use_gpg2_hack = yes
else
gpg2_hack_uninst = $(gpg2_hack_list)
use_gpg2_hack = no
endif

# NB: We use noinst_ for gpg and gpgv so that we can install them with
# the install-hook target under the name gpg2/gpgv2.
noinst_PROGRAMS = gpg
if !HAVE_W32CE_SYSTEM
noinst_PROGRAMS += gpgv
endif
if MAINTAINER_MODE
noinst_PROGRAMS += gpgcompose
endif
noinst_PROGRAMS += $(module_tests)
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
gpg_robjs = $(resource_objs) gpg-w32info.o
gpgv_robjs = $(resource_objs) gpgv-w32info.o
gpg-w32info.o : gpg.w32-manifest
gpgv-w32info.o : gpgv.w32-manifest
else
gpg_robjs =
gpgv_robjs =
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

gpg_sources = server.c          \
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

gpgcompose_SOURCES  = gpgcompose.c  $(gpg_sources)
gpgv_SOURCES = gpgv.c           \
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
gpg_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) $(SQLITE3_LIBS) $(LIBREADLINE) \
             $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) \
	     $(LIBICONV) $(gpg_robjs) $(extra_sys_libs)
gpg_LDFLAGS = $(extra_bin_ldflags)
gpgv_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) \
              $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(gpgv_robjs) $(extra_sys_libs)
gpgv_LDFLAGS = $(extra_bin_ldflags)

gpgcompose_LDADD = $(LDADD) $(SQLITE3_LIBS) $(LIBGCRYPT_LIBS) $(LIBREADLINE) \
             $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) \
	     $(LIBICONV) $(extra_sys_libs)
gpgcompose_LDFLAGS = $(extra_bin_ldflags)

t_common_ldadd =
module_tests = t-rmd160 t-keydb t-keydb-get-keyblock t-stutter
t_rmd160_SOURCES = t-rmd160.c rmd160.c
t_rmd160_LDADD = $(t_common_ldadd)
t_keydb_SOURCES = t-keydb.c test-stubs.c $(common_source)
t_keydb_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(t_common_ldadd)
t_keydb_get_keyblock_SOURCES = t-keydb-get-keyblock.c test-stubs.c \
	      $(common_source)
t_keydb_get_keyblock_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(t_common_ldadd)
t_stutter_SOURCES = t-stutter.c test-stubs.c \
	      $(common_source)
t_stutter_LDADD = $(LDADD) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	      $(LIBICONV) $(t_common_ldadd)


$(PROGRAMS): $(needed_libs) ../common/libgpgrl.a

# NB: To install gpg and gpgv we use this -hook.  This code has to
# duplicate most of the automake generated install-binPROGRAMS target
# so that directories are created and the transform feature works.
install-exec-hook:
	@echo "running install-exec-hook"; \
        echo " $(MKDIR_P) '$(DESTDIR)$(bindir)'"; \
        $(MKDIR_P) "$(DESTDIR)$(bindir)"; \
	for p in $(gpg2_hack_list); do \
          echo "$$p$(EXEEXT) $$p$(EXEEXT)"; done | \
	sed 's/$(EXEEXT)$$//' | \
	while read p p1; do if test -f $$p \
	  ; then echo "$$p"; echo "$$p"; else :; fi; \
	done | \
	sed -e 'p;s,.*/,,;n;h' \
	    -e 's|.*|.|' \
	    -e 'p;x;s,.*/,,;s/$(EXEEXT)$$//;$(transform);s/$$/$(EXEEXT)/' | \
	sed 'N;N;N;s,\n, ,g' | \
	$(AWK) 'BEGIN { files["."] = ""; dirs["."] = 1 } \
	  { d=$$3; if (dirs[d] != 1) { print "d", d; dirs[d] = 1 } \
	    if ($$2 == $$4) files[d] = files[d] " " $$1; \
	    else { print "f", $$3 "/" $$4, $$1; } } \
	  END { for (d in files) print "f", d, files[d] }' | \
	while read type dir files; do \
	    for f in $$files; do \
	       if test $(use_gpg2_hack) = yes ; \
		 then f2=`echo "$${f}" | sed 's/$(EXEEXT)$$//'`2$(EXEEXT); \
	         else f2="$${f}" ;\
	       fi ; \
	       echo "$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) \
                     $${f} '$(DESTDIR)$(bindir)/$${f2}'"; \
	       $(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) \
                     $${f} "$(DESTDIR)$(bindir)/$${f2}"; \
	    done; \
	done


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/distsigkey.gpg \
				$(DESTDIR)$(pkgdatadir)/distsigkey.gpg

# NB: For uninstalling gpg and gpgv we use -local because there is
# no need for a specific order the targets need to be run.
uninstall-local:
	-@rm $(DESTDIR)$(pkgdatadir)/distsigkey.gpg
	-@files=`for p in $(gpg2_hack_uninst); do echo "$$p"; done | \
	  sed -e 'h;s,^.*/,,;s/$(EXEEXT)$$//;$(transform)' \
	      -e 's/$$/$(EXEEXT)/' \
	`; \
	echo " ( cd '$(DESTDIR)$(bindir)' && rm -f" $$files ")"; \
	cd "$(DESTDIR)$(bindir)" && rm -f $$files
