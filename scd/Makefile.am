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

bin_PROGRAMS = scdaemon sc-copykeys
if HAVE_W32_SYSTEM
pkglib_PROGRAMS = pcsc-wrapper
endif

AM_CPPFLAGS = -I$(top_srcdir)/intl -I$(top_srcdir)/common

include $(top_srcdir)/am/cmacros.am

# avoid linking against Pth if we are using OpenSC.
if HAVE_OPENSC
pth_libs = 
else
pth_libs = $(PTH_LIBS)
endif

AM_CFLAGS =  $(OPENSC_CFLAGS) $(LIBGCRYPT_CFLAGS) \
	      $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)


card_apps = app-openpgp.c app-nks.c app-dinsig.c

scdaemon_SOURCES = \
	scdaemon.c scdaemon.h \
	command.c card.c \
	card-common.h \
	card-p15.c  \
	apdu.c apdu.h \
	ccid-driver.c ccid-driver.h \
	iso7816.c iso7816.h \
	tlv.c tlv.h \
	app.c app-common.h app-help.c $(card_apps)


scdaemon_LDADD = ../jnlib/libjnlib.a ../common/libcommon.a \
	   $(LIBGCRYPT_LIBS) $(pth_libs) \
          $(KSBA_LIBS) $(LIBASSUAN_LIBS) \
	  $(LIBUSB_LIBS) $(OPENSC_LIBS) -lgpg-error @LIBINTL@ \
	  @DL_LIBS@

sc_copykeys_SOURCES = \
	sc-copykeys.c scdaemon.h \
	apdu.c apdu.h \
	ccid-driver.c ccid-driver.h \
	iso7816.c iso7816.h \
	tlv.c tlv.h \
	atr.c atr.h \
	app.c app-common.h app-help.c $(card_apps)

sc_copykeys_LDADD = \
	../jnlib/libjnlib.a ../common/libcommon.a \
	../common/libsimple-pwquery.a \
	$(LIBGCRYPT_LIBS) $(pth_libs) \
	$(KSBA_LIBS) $(LIBUSB_LIBS) $(OPENSC_LIBS) \
        -lgpg-error @LIBINTL@ @DL_LIBS@

pcsc_wrapper_SOURCES = pcsc-wrapper.c
pcsc_wrapper_LDADD = @DL_LIBS@
pcsc_wrapper_CFLAGS = 
