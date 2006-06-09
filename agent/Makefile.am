# Copyright (C) 2001, 2003, 2004, 2005 Free Software Foundation, Inc.
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

bin_PROGRAMS = gpg-agent
libexec_PROGRAMS = gpg-protect-tool gpg-preset-passphrase
noinst_PROGRAMS = $(TESTS)

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/common -I$(top_srcdir)/intl

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)

gpg_agent_SOURCES = \
	gpg-agent.c agent.h \
	command.c command-ssh.c \
	query.c \
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


gpg_agent_LDADD = ../jnlib/libjnlib.a ../common/libcommon.a ../gl/libgnu.a \
                $(LIBGCRYPT_LIBS) $(PTH_LIBS) $(LIBASSUAN_LIBS) \
	         -lgpg-error @LIBINTL@ $(NETLIBS)

gpg_protect_tool_SOURCES = \
	protect-tool.c \
	protect.c \
	minip12.c minip12.h 

gpg_protect_tool_LDADD = ../common/libsimple-pwquery.a \
	../jnlib/libjnlib.a  ../common/libcommon.a ../gl/libgnu.a \
	 $(LIBGCRYPT_LIBS) -lgpg-error @LIBINTL@
if HAVE_W32_SYSTEM
gpg_protect_tool_LDADD += -lwsock32
endif

gpg_preset_passphrase_SOURCES = \
	preset-passphrase.c

gpg_preset_passphrase_LDADD = ../common/libsimple-pwquery.a \
	../jnlib/libjnlib.a ../common/libcommon.a ../gl/libgnu.a \
	 $(LIBGCRYPT_LIBS) -lgpg-error @LIBINTL@
if HAVE_W32_SYSTEM
gpg_preset_passphrase_LDADD += -lwsock32
endif

#
# Module tests
#
TESTS = t-protect

t_common_ldadd = ../jnlib/libjnlib.a ../common/libcommon.a ../gl/libgnu.a \
                 $(LIBGCRYPT_LIBS) -lgpg-error @LIBINTL@

t_protect_SOURCES = t-protect.c protect.c 
t_protect_LDADD = $(t_common_ldadd)




