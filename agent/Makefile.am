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
if !HAVE_W32CE_SYSTEM
# fixme: Do no use simple-pwquery for preset-passphrase.
libexec_PROGRAMS += gpg-preset-passphrase
endif
noinst_PROGRAMS = $(TESTS)

EXTRA_DIST = ChangeLog-2011 gpg-agent-w32info.rc all-tests.scm


AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
resource_objs += gpg-agent-w32info.o
endif

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

gpg_agent_SOURCES = \
	gpg-agent.c agent.h \
	command.c command-ssh.c \
	call-pinentry.c \
	cache.c \
	trans.c \
	findkey.c \
	pksign.c \
	pkdecrypt.c \
	genkey.c \
	protect.c \
	trustlist.c \
	divert-scd.c \
	cvt-openpgp.c cvt-openpgp.h \
	call-scd.c \
	learncard.c

common_libs = $(libcommon)
commonpth_libs = $(libcommonpth)
if HAVE_W32CE_SYSTEM
pwquery_libs =
else
pwquery_libs = ../common/libsimple-pwquery.a
endif


gpg_agent_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) \
		$(INCICONV)
gpg_agent_LDADD = $(commonpth_libs) \
                $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	        $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV) \
		$(resource_objs)
gpg_agent_LDFLAGS = $(extra_bin_ldflags)
gpg_agent_DEPENDENCIES = $(resource_objs)

gpg_protect_tool_SOURCES = \
	protect-tool.c \
	protect.c cvt-openpgp.c

gpg_protect_tool_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) \
	$(INCICONV)
gpg_protect_tool_LDADD = $(common_libs) $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) \
         $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)

gpg_preset_passphrase_SOURCES = \
	preset-passphrase.c

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
TESTS = t-protect

t_common_ldadd = $(common_libs)  $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
	          $(LIBINTL) $(LIBICONV) $(NETLIBS)

t_protect_SOURCES = t-protect.c protect.c
t_protect_LDADD = $(t_common_ldadd)
