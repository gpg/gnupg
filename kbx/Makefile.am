# Keybox Makefile 
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

EXTRA_DIST = mkerrors
INCLUDES = -I.. -I$(top_srcdir)/include
BUILT_SOURCES = keybox-errors.c

noinst_LIBRARIES = libkeybox.a
bin_PROGRAMS = kbxutil

common_sources = \
	keybox.h keybox-defs.h keybox-search-desc.h \
	keybox-util.c \
	keybox-errors.c \
	keybox-init.c \
	keybox-blob.c \
	keybox-file.c \
	keybox-search.c \
	keybox-update.c \
	keybox-dump.c 


libkeybox_a_SOURCES = $(common_sources)

kbxutil_SOURCES = kbxutil.c $(common_sources)
kbxutil_LDADD   = ../jnlib/libjnlib.a  \
		  ../../libksba/src/.libs/libksba.a \
                  ../../libgcrypt/src/.libs/libgcrypt.so.1 

keybox-errors.c : keybox.h mkerrors
	$(srcdir)/mkerrors < $(srcdir)/keybox.h > keybox-errors.c



