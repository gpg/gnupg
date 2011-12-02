# Keybox Makefile
# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

EXTRA_DIST = mkerrors ChangeLog-2011
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/common -I$(top_srcdir)/intl \
	       $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

noinst_LIBRARIES = libkeybox.a
bin_PROGRAMS = kbxutil

common_sources = \
	keybox.h keybox-defs.h keybox-search-desc.h \
	keybox-util.c \
	keybox-init.c \
	keybox-blob.c \
	keybox-file.c \
	keybox-search.c \
	keybox-update.c \
	keybox-openpgp.c \
	keybox-dump.c


libkeybox_a_SOURCES = $(common_sources)

# We need W32SOCKLIBS because the init subsystem code in libcommon
# requires it - although we don't actually need it.  It is easier
# to do it this way.
kbxutil_SOURCES = kbxutil.c $(common_sources)
kbxutil_LDADD   = ../common/libcommon.a ../jnlib/libjnlib.a ../gl/libgnu.a \
                  $(KSBA_LIBS) $(LIBGCRYPT_LIBS) \
                  $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV) $(W32SOCKLIBS)

$(PROGRAMS) : ../common/libcommon.a ../jnlib/libjnlib.a ../gl/libgnu.a
