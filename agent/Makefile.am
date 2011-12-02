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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

bin_PROGRAMS = gpg-agent
libexec_PROGRAMS = gpg-protect-tool gpg-preset-passphrase
noinst_PROGRAMS = $(TESTS)

# EXTRA_DIST = gpg-agent.ico gpg-agent-resource.rc
EXTRA_DIST = ChangeLog-2011

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/common -I$(top_srcdir)/intl

include $(top_srcdir)/am/cmacros.am

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
	call-scd.c \
	learncard.c

common_libs = $(libcommon) ../jnlib/libjnlib.a ../gl/libgnu.a
commonpth_libs = $(libcommonpth) ../jnlib/libjnlib.a ../gl/libgnu.a
pwquery_libs = ../common/libsimple-pwquery.a

#if HAVE_W32_SYSTEM
#.rc.o:
#	$(WINDRES) `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) | \
#	 sed -e 's/-I/--include-dir /g;s/-D/--define /g'` -i $< -o $@
#
#gpg_agent_res_ldflags = -Wl,gpg-agent-resource.o -Wl,--subsystem,windows
#gpg_agent_res_deps = gpg-agent-resource.o
#else
gpg_agent_res_ldflags =
gpg_agent_res_deps =
#endif


gpg_agent_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)
gpg_agent_LDADD = $(commonpth_libs) \
                $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(PTH_LIBS) \
	        $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)
gpg_agent_LDFLAGS = $(gpg_agent_res_ldflags)
gpg_agent_DEPENDENCIES = $(gpg_agent_res_deps)

gpg_protect_tool_SOURCES = \
	protect-tool.c \
	protect.c \
	minip12.c minip12.h

gpg_protect_tool_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS)
gpg_protect_tool_LDADD = $(common_libs) $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) \
         $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)

gpg_preset_passphrase_SOURCES = \
	preset-passphrase.c

# Needs $(NETLIBS) for libsimple-pwquery.la.
gpg_preset_passphrase_LDADD = \
         $(pwquery_libs) $(common_libs) \
	 $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)


# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs) $(commonpth_libs) $(pwquery_libs)



#
# Module tests
#
TESTS = t-protect

t_common_ldadd = $(common_libs) \
                 $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)

t_protect_SOURCES = t-protect.c protect.c
t_protect_LDADD = $(t_common_ldadd)




