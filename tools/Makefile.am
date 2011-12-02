# Makefile.am - Tools directory
#     	Copyright (C) 2003, 2007 Free Software Foundation, Inc.
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

EXTRA_DIST = \
	Manifest watchgnupg.c ChangeLog-2011 \
	addgnupghome applygnupgdefaults gpgsm-gencert.sh \
	lspgpot mail-signed-keys convert-from-106 sockprox.c \
	ccidmon.c


AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl -I$(top_srcdir)/common
include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS) $(LIBASSUAN_CFLAGS)

sbin_SCRIPTS = addgnupghome applygnupgdefaults

bin_SCRIPTS = gpgsm-gencert.sh
if HAVE_USTAR
# bin_SCRIPTS += gpg-zip
noinst_SCRIPTS = gpg-zip
endif

if BUILD_SYMCRYPTRUN
  symcryptrun = symcryptrun
else
  symcryptrun =
endif

if BUILD_GPGTAR
  gpgtar = gpgtar
else
  gpgtar =
endif


bin_PROGRAMS = gpgconf gpg-connect-agent gpgkey2ssh ${symcryptrun} ${gpgtar}
if !HAVE_W32_SYSTEM
bin_PROGRAMS += watchgnupg gpgparsemail
endif

if !DISABLE_REGEX
libexec_PROGRAMS = gpg-check-pattern
endif

noinst_PROGRAMS = clean-sat mk-tdata make-dns-cert gpgsplit

common_libs = $(libcommon) ../jnlib/libjnlib.a ../gl/libgnu.a
pwquery_libs = ../common/libsimple-pwquery.a

gpgsplit_LDADD = $(common_libs) \
	         $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
		 $(ZLIBS) $(LIBINTL) $(LIBICONV)

gpgconf_SOURCES = gpgconf.c gpgconf.h gpgconf-comp.c no-libgcrypt.c

# jnlib/common sucks in gpg-error, will they, nil they (some compilers
# do not eliminate the supposed-to-be-unused-inline-functions).
gpgconf_LDADD = $(common_libs) \
                $(LIBINTL) $(GPG_ERROR_LIBS) $(LIBICONV) $(W32SOCKLIBS)

gpgparsemail_SOURCES = gpgparsemail.c rfc822parse.c rfc822parse.h
gpgparsemail_LDADD =

symcryptrun_SOURCES = symcryptrun.c
symcryptrun_LDADD = $(LIBUTIL_LIBS) $(common_libs) $(pwquery_libs) \
                    $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) \
                    $(LIBICONV) $(W32SOCKLIBS)

watchgnupg_SOURCES = watchgnupg.c
watchgnupg_LDADD = $(NETLIBS)

gpg_connect_agent_SOURCES = gpg-connect-agent.c no-libgcrypt.c
# FIXME: remove PTH_LIBS (why do we need them at all?)
gpg_connect_agent_LDADD = ../common/libgpgrl.a $(common_libs) \
	                  $(LIBASSUAN_LIBS) $(PTH_LIBS) $(GPG_ERROR_LIBS) \
                          $(LIBREADLINE) $(LIBINTL) $(NETLIBS) $(LIBICONV)

gpgkey2ssh_SOURCES = gpgkey2ssh.c
gpgkey2ssh_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)
# common sucks in jnlib, via use of BUG() in an inline function, which
# some compilers do not eliminate.
gpgkey2ssh_LDADD = $(common_libs) \
                   $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)


if !DISABLE_REGEX
gpg_check_pattern_SOURCES = gpg-check-pattern.c
gpg_check_pattern_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)
gpg_check_pattern_LDADD = $(common_libs) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
                          $(LIBINTL) $(LIBICONV) $(W32SOCKLIBS)
endif

gpgtar_SOURCES = \
	gpgtar.c gpgtar.h \
	gpgtar-create.c \
	gpgtar-extract.c \
	gpgtar-list.c \
	no-libgcrypt.c
gpgtar_CFLAGS = $(GPG_ERROR_CFLAGS) $(PTH_CFLAGS)
gpgtar_LDADD = $(common_libs) $(GPG_ERROR_LIBS) $(NETLIBS) $(W32SOCKLIBS)

# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs) $(pwquery_libs) ../common/libgpgrl.a

