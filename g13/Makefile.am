# g13/Makefile.am
# Copyright (C) 2009 Free Software Foundation, Inc.
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

bin_PROGRAMS = g13 

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl -I$(top_srcdir)/common

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS)  $(LIBASSUAN_PTH_CFLAGS) $(PTH_CFLAGS)

g13_SOURCES = \
	g13.c g13.h \
	keyblob.h \
	utils.c utils.h \
	create.c create.h \
	mount.c mount.h \
	call-gpg.c call-gpg.h \
	runner.c runner.h \
	backend.c backend.h \
	be-encfs.c be-encfs.h \
	be-truecrypt.c be-truecrypt.h

g13_LDADD = $(libcommonpth) ../jnlib/libjnlib.a ../gl/libgnu.a \
	$(LIBGCRYPT_LIBS) $(LIBASSUAN_PTH_LIBS) $(PTH_LIBS) \
	$(GPG_ERROR_LIBS) $(LIBINTL)

