# Makefile for common gnupg modules
# Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libcommon.a libcommonpth.a libsimple-pwquery.a libgpgrl.a
noinst_PROGRAMS = $(module_tests)
TESTS = $(module_tests)

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

include $(top_srcdir)/am/cmacros.am

common_sources = \
	common-defs.h \
	util.h i18n.c i18n.h \
	errors.h \
	openpgpdefs.h \
	keyserver.h \
	sexp-parse.h \
	sexputil.c \
	sysutils.c sysutils.h \
	homedir.c \
	gettime.c \
	yesno.c \
	b64enc.c \
	convert.c \
	miscellaneous.c \
	xasprintf.c \
	xreadline.c \
	membuf.c membuf.h \
	iobuf.c iobuf.h \
	ttyio.c ttyio.h \
	asshelp.c asshelp.h \
	exechelp.c exechelp.h \
	signal.c \
	estream.c estream.h estream-printf.c estream-printf.h \
	srv.h \
	dns-cert.c dns-cert.h \
	pka.c pka.h \
	http.c http.h 

libcommon_a_SOURCES = $(common_sources)
if USE_DNS_SRV
libcommon_a_SOURCES += srv.c
endif
libcommon_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) -DWITHOUT_GNU_PTH=1

libcommonpth_a_SOURCES = $(common_sources)
if USE_DNS_SRV
libcommonpth_a_SOURCES += srv.c
endif
libcommonpth_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_PTH_CFLAGS) $(PTH_CFLAGS)

libsimple_pwquery_a_SOURCES = \
	simple-pwquery.c simple-pwquery.h asshelp.c asshelp.h
libsimple_pwquery_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS)

libgpgrl_a_SOURCES = \
        gpgrlhelp.c

#
# Module tests
#
module_tests = t-convert

t_common_ldadd = ../jnlib/libjnlib.a ../common/libcommon.a ../gl/libgnu.a \
                 $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)

t_convert_DEPENDENCIES = convert.c libcommon.a
t_convert_LDADD = $(t_common_ldadd)

