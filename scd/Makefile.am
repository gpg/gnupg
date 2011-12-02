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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

bin_PROGRAMS = scdaemon
if ! HAVE_W32_SYSTEM
libexec_PROGRAMS = gnupg-pcsc-wrapper
endif

EXTRA_DIST = ChangeLog-2011

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl -I$(top_srcdir)/common

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) \
	     $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)


card_apps = app-openpgp.c app-nks.c app-dinsig.c app-p15.c app-geldkarte.c

scdaemon_SOURCES = \
	scdaemon.c scdaemon.h \
	command.c \
	apdu.c apdu.h \
	ccid-driver.c ccid-driver.h \
	iso7816.c iso7816.h \
	app.c app-common.h app-help.c $(card_apps)


scdaemon_LDADD = $(libcommonpth) ../jnlib/libjnlib.a ../gl/libgnu.a \
	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) $(PTH_LIBS) \
	$(LIBUSB_LIBS) $(GPG_ERROR_LIBS) \
        $(LIBINTL) $(DL_LIBS) $(NETLIBS) $(LIBICONV)

# Removed for now: We need to decide whether it makes sense to
# continue it at all, given that gpg has now all required
# functionality.
#sc_copykeys_SOURCES = \
#	sc-copykeys.c scdaemon.h \
#	apdu.c apdu.h \
#	ccid-driver.c ccid-driver.h \
#	iso7816.c iso7816.h \
#	atr.c atr.h \
#	app.c app-common.h app-help.c $(card_apps)
#
#sc_copykeys_LDADD = \
#	../jnlib/libjnlib.a ../common/libcommon.a \
#	../common/libsimple-pwquery.a \
#	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) $(PTH_LIBS) \
#	 $(LIBUSB_LIBS) \
#        -lgpg-error @LIBINTL@ @DL_LIBS@
#
gnupg_pcsc_wrapper_SOURCES = pcsc-wrapper.c
gnupg_pcsc_wrapper_LDADD = $(DL_LIBS)
gnupg_pcsc_wrapper_CFLAGS =
