# Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
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
libexec_PROGRAMS = gpg-protect-tool

AM_CPPFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/intl

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)

gpg_agent_SOURCES = \
	gpg-agent.c agent.h \
	estream.c estream.h \
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


gpg_agent_LDADD = ../jnlib/libjnlib.a ../common/libcommon.a \
                $(LIBGCRYPT_LIBS) $(PTH_LIBS) $(LIBASSUAN_LIBS) \
	         -lgpg-error @INTLLIBS@

gpg_protect_tool_SOURCES = \
	protect-tool.c \
	protect.c \
	minip12.c minip12.h 

gpg_protect_tool_LDADD = ../jnlib/libjnlib.a \
        ../common/libcommon.a ../common/libsimple-pwquery.a \
	 $(LIBGCRYPT_LIBS) -lgpg-error @INTLLIBS@


