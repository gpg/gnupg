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
# along with this program; if not, see <https://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

EXTRA_DIST = mkerrors

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

noinst_LIBRARIES = libkeybox.a libkeybox509.a
bin_PROGRAMS = kbxutil

if HAVE_W32CE_SYSTEM
extra_libs =  $(LIBASSUAN_LIBS)
else
extra_libs =
endif

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
libkeybox509_a_SOURCES = $(common_sources)

libkeybox_a_CFLAGS    = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS)
libkeybox509_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) \
                          -DKEYBOX_WITH_X509=1

# We need W32SOCKLIBS because the init subsystem code in libcommon
# requires it - although we don't actually need it.  It is easier
# to do it this way.
kbxutil_SOURCES = kbxutil.c $(common_sources)
kbxutil_CFLAGS = $(AM_CFLAGS) -DKEYBOX_WITH_X509=1
kbxutil_LDADD   = ../common/libcommon.a \
                  $(KSBA_LIBS) $(LIBGCRYPT_LIBS) $(extra_libs) \
                  $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV) $(W32SOCKLIBS) \
		  $(NETLIBS)

$(PROGRAMS) : ../common/libcommon.a
