# Makfile.am - Makefile for tpm2d
# Copyright (C) 2021 James Bottomley <James.Bottomley@HansenPartnership.com>
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

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

libexec_PROGRAMS = tpm2daemon

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) \
	     $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) $(LIBTSS_CFLAGS)

tpm2daemon_SOURCES = \
        command.c \
        tpm2daemon.c \
        tpm2.c tpm2.h \
        tpm2daemon.h ibm-tss.h intel-tss.h

tpm2daemon_LDADD = $(libcommonpth) \
	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	$(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV) $(LIBTSS_LIBS)
