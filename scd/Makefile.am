# Copyright (C) 2002 Free Software Foundation, Inc.
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

bin_PROGRAMS = scdaemon

AM_CPPFLAGS = -I$(top_srcdir)/common $(LIBOPENSC_CFLAGS) $(LIBGCRYPT_CFLAGS) \
	      $(LIBKSBA_CFLAGS)
LDFLAGS = @LDFLAGS@ 

scdaemon_SOURCES = \
	scdaemon.c scdaemon.h \
	command.c card.c \
	card-common.h \
	card-p15.c card-dinsig.c

# fixme: We added -lpcslite because the opensc config script can't cope with 
# a static only libopensc.
scdaemon_LDADD = ../jnlib/libjnlib.a ../assuan/libassuan.a  \
		../common/libcommon.a \
		$(LIBOPENSC_LIBS) $(LIBGCRYPT_LIBS) $(LIBKSBA_LIBS) \
	        -lpcsclite -lpthread




