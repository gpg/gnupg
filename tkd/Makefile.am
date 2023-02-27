# Copyright (C) 2002, 2003, 2005 Free Software Foundation, Inc.
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
# SPDX-License-Identifier: GPL-3.0-or-later

EXTRA_DIST =

libexec_PROGRAMS = tkdaemon

AM_CPPFLAGS =

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) \
	     $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS)

include $(top_srcdir)/am/cmacros.am

tkdaemon_SOURCES = \
	tkdaemon.c tkdaemon.h \
	command.c pkcs11.c

tkdaemon_LDADD = $(libcommonpth) \
	$(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	$(GPG_ERROR_LIBS) \
        $(LIBINTL) $(DL_LIBS) $(NETLIBS) $(LIBICONV)

pksign_LDADD = $(libcommonpth) \
	$(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	$(GPG_ERROR_LIBS) \
        $(LIBINTL) $(DL_LIBS) $(NETLIBS) $(LIBICONV)
