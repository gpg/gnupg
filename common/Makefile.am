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

AM_CPPFLAGS = -I$(top_srcdir)/gl

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

common_sources = \
	common-defs.h \
	util.h i18n.h \
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
	simple-gettext.c \
	w32reg.c \
	signal.c \
	dynload.h \
	estream.c estream.h \
	srv.c srv.h \
	dns-cert.c dns-cert.h \
	pka.c pka.h \
	http.c http.h 

libcommon_a_SOURCES = $(common_sources)
libcommon_a_CFLAGS = $(AM_CFLAGS) -DWITHOUT_GNU_PTH=1

libcommonpth_a_SOURCES = $(common_sources)
libcommonpth_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_PTH_CFLAGS) $(PTH_CFLAGS)

libsimple_pwquery_a_SOURCES = \
	simple-pwquery.c simple-pwquery.h asshelp.c asshelp.h

libgpgrl_a_SOURCES = \
        gpgrlhelp.c

#
# Module tests
#
module_tests = t-convert

t_common_ldadd = ../jnlib/libjnlib.a ../common/libcommon.a ../gl/libgnu.a \
                 $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS)

t_convert_DEPENDENCIES = convert.c
t_convert_LDADD = $(t_common_ldadd)

