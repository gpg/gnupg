# Makefile for common gnupg modules
# Copyright (C) 2001 Free Software Foundation, Inc.
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
#INCLUDES = 
BUILT_SOURCES = errors.c 

noinst_LIBRARIES = libcommon.a

AM_CPPFLAGS =  $(LIBGCRYPT_CFLAGS) $(LIBKSBA_CFLAGS)

libcommon_a_SOURCES = \
	util.h i18n.h \
	errors.c errors.h \
	maperror.c \
	sysutils.c sysutils.h \
	cryptmiss.c \
	gettime.c 

libcommon_a_LIBADD = @LIBOBJS@

errors.c : errors.h mkerrors mkerrtok
	$(srcdir)/mkerrors < $(srcdir)/errors.h > errors.c
	$(srcdir)/mkerrtok < $(srcdir)/errors.h >> errors.c








