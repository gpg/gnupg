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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

EXTRA_DIST = mkerrors mkerrtok

noinst_LIBRARIES = libcommon.a libsimple-pwquery.a

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

libcommon_a_SOURCES = \
	util.h i18n.h \
	errors.h \
	sexp-parse.h \
	maperror.c \
	sysutils.c sysutils.h \
	gettime.c \
	yesno.c \
	b64enc.c \
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
	dynload.h


libcommon_a_LIBADD = @LIBOBJS@

libsimple_pwquery_a_SOURCES = \
	simple-pwquery.c simple-pwquery.h asshelp.c asshelp.h

libsimple_pwquery_a_LIBADD = @LIBOBJS@









