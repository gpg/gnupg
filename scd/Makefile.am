# Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

bin_PROGRAMS = scdaemon sc-investigate

AM_CPPFLAGS = -I$(top_srcdir)/common $(OPENSC_CFLAGS) $(LIBGCRYPT_CFLAGS) \
	      $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS)

scdaemon_SOURCES = \
	scdaemon.c scdaemon.h \
	command.c card.c \
	card-common.h \
	card-p15.c card-dinsig.c \
	apdu.c apdu.h \
	iso7816.c iso7816.h \
	app-openpgp.c

scdaemon_LDADD = ../jnlib/libjnlib.a ../common/libcommon.a \
	  $(OPENSC_LIBS) $(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) -lgpg-error -ldl

sc_investigate_SOURCES = \
	sc-investigate.c scdaemon.h \
	apdu.c apdu.h \
	iso7816.c iso7816.h \
	app-openpgp.c \
	atr.c atr.h 

sc_investigate_LDADD = ../jnlib/libjnlib.a ../common/libcommon.a \
		$(LIBGCRYPT_LIBS) -lgpg-error -ldl









