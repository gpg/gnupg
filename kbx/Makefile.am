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

EXTRA_DIST = mkerrors keyboxd-w32info.rc keyboxd.w32-manifest.in

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
resource_objs += keyboxd-w32info.o

keyboxd-w32info.o : keyboxd.w32-manifest ../common/w32info-rc.h
endif

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

bin_PROGRAMS = kbxutil
noinst_LIBRARIES = libkeybox.a libkeybox509.a
if BUILD_KEYBOXD
libexec_PROGRAMS = keyboxd
else
libexec_PROGRAMS =
endif

common_libs = $(libcommon)
commonpth_libs = $(libcommonpth)

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

client_sources = \
        kbx-client-util.h \
        kbx-client-util.c


libkeybox_a_SOURCES = $(common_sources) $(client_sources)
libkeybox509_a_SOURCES = $(common_sources) $(client_sources)

libkeybox_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS)
libkeybox509_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) -DKEYBOX_WITH_X509=1


# We need W32SOCKLIBS because the init subsystem code in libcommon
# requires it - although we don't actually need it.  It is easier
# to do it this way.
kbxutil_SOURCES = kbxutil.c $(common_sources)
kbxutil_CFLAGS = $(AM_CFLAGS) -DKEYBOX_WITH_X509=1
kbxutil_LDADD   = $(common_libs) \
                  $(KSBA_LIBS) $(LIBGCRYPT_LIBS) \
                  $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV) $(W32SOCKLIBS) \
		  $(NETLIBS)


keyboxd_SOURCES = \
	keyboxd.c keyboxd.h   \
	kbxserver.c           \
	frontend.c frontend.h \
	backend.h backend-support.c \
	backend-cache.c \
	backend-kbx.c \
	backend-sqlite.c \
	$(common_sources)

keyboxd_CFLAGS = $(AM_CFLAGS) -DKEYBOX_WITH_X509=1 \
                 $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) $(SQLITE3_CFLAGS) \
                 $(INCICONV)
keyboxd_LDADD = $(commonpth_libs) \
                $(KSBA_LIBS) $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	        $(SQLITE3_LIBS) $(GPG_ERROR_LIBS) \
                $(LIBINTL) $(NETLIBS) $(LIBICONV) \
		$(resource_objs)
keyboxd_LDFLAGS =
keyboxd_DEPENDENCIES = $(resource_objs)


# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs) $(commonpth_libs)
