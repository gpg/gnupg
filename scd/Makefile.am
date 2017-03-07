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

## Process this file with automake to produce Makefile.in

EXTRA_DIST = ChangeLog-2011 scdaemon-w32info.rc

libexec_PROGRAMS = scdaemon

AM_CPPFLAGS = $(LIBUSB_CPPFLAGS)

include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
resource_objs += scdaemon-w32info.o
endif

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) \
	     $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS)


card_apps = app-openpgp.c app-nks.c app-dinsig.c app-p15.c app-geldkarte.c app-sc-hsm.c

scdaemon_SOURCES = \
	scdaemon.c scdaemon.h \
	command.c \
	atr.c atr.h \
	apdu.c apdu.h \
	ccid-driver.c ccid-driver.h \
	iso7816.c iso7816.h \
	app.c app-common.h app-help.c $(card_apps)


scdaemon_LDADD = $(libcommonpth) \
	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	$(LIBUSB_LIBS) $(GPG_ERROR_LIBS) \
        $(LIBINTL) $(DL_LIBS) $(NETLIBS) $(LIBICONV) $(resource_objs)
