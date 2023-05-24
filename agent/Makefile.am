# Makefile.am - agent
# Copyright (C) 2001, 2003, 2004, 2005 Free Software Foundation, Inc.
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

bin_PROGRAMS = gpg-agent
libexec_PROGRAMS = gpg-protect-tool
# fixme: Do no use simple-pwquery for preset-passphrase.
libexec_PROGRAMS += gpg-preset-passphrase
noinst_PROGRAMS = $(TESTS)

EXTRA_DIST = ChangeLog-2011 all-tests.scm \
             gpg-agent-w32info.rc gpg-agent.w32-manifest.in

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
resource_objs += gpg-agent-w32info.o

gpg-agent-w32info.o : gpg-agent.w32-manifest ../common/w32info-rc.h
endif

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

if HAVE_LIBTSS
tpm2_sources =  divert-tpm2.c call-tpm2d.c
else
tpm2_sources =
endif

gpg_agent_SOURCES = \
	gpg-agent.c agent.h \
	command.c command-ssh.c \
	call-pinentry.c \
	cache.c \
	trans.c \
	findkey.c \
	sexp-secret.c \
	pksign.c \
	pkdecrypt.c \
	genkey.c \
	protect.c \
	trustlist.c \
	divert-scd.c \
	cvt-openpgp.c cvt-openpgp.h \
	call-scd.c \
	call-daemon.c \
	$(tpm2_sources) \
	learncard.c

common_libs = $(libcommon)
commonpth_libs = $(libcommonpth)
pwquery_libs = ../common/libsimple-pwquery.a


gpg_agent_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) \
		$(INCICONV)
gpg_agent_LDADD = $(commonpth_libs) \
                $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	        $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV) \
		$(resource_objs)
gpg_agent_LDFLAGS =
gpg_agent_DEPENDENCIES = $(resource_objs)

gpg_protect_tool_SOURCES = \
	protect-tool.c \
	sexp-secret.c \
	protect.c cvt-openpgp.c

gpg_protect_tool_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) \
	$(INCICONV)
gpg_protect_tool_LDADD = $(common_libs) $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) \
         $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)

gpg_preset_passphrase_SOURCES = \
	preset-passphrase.c
gpg_preset_passphrase_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS)

# Needs $(NETLIBS) for libsimple-pwquery.la.
gpg_preset_passphrase_LDADD = \
         $(pwquery_libs) $(common_libs) $(LIBASSUAN_LIBS) \
	 $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)


# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs) $(commonpth_libs) $(pwquery_libs)



#
# Module tests
#
module_tests = t-protect

if DISABLE_TESTS
TESTS =
else
TESTS = $(module_tests)
endif

t_common_ldadd = $(common_libs)  $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	          $(LIBINTL) $(LIBICONV) $(NETLIBS)

t_protect_SOURCES = t-protect.c protect.c
t_protect_LDADD = $(t_common_ldadd)
t_protect_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS)
