# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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


bin_PROGRAMS = gpgsm

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(KSBA_CFLAGS)

AM_CPPFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/intl 
include $(top_srcdir)/am/cmacros.am


gpgsm_SOURCES = \
	gpgsm.c	gpgsm.h \
	misc.c \
	keydb.c keydb.h \
	server.c \
	call-agent.c \
	call-dirmngr.c \
	fingerprint.c \
	base64.c \
	certlist.c \
	certdump.c \
	certcheck.c \
	certchain.c \
	keylist.c \
	verify.c \
	sign.c \
	encrypt.c \
	decrypt.c \
	import.c \
	export.c \
	delete.c \
	certreqgen.c 


gpgsm_LDADD = ../jnlib/libjnlib.a ../kbx/libkeybox.a ../common/libcommon.a \
               $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(KSBA_LIBS) -lgpg-error \
	       $(INTLLIBS)
