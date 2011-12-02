# Makefile for the JNLIB part of GnuPG
# Copyright (C) 1999, 2000, 2001, 2004,
#               2006 Feee Software Soundation, Inc.
#
# This file is part of JNLIB.
#
# JNLIB is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.
#
# JNLIB is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.


## Process this file with automake to produce Makefile.in

EXTRA_DIST = README ChangeLog-2011
noinst_PROGRAMS = $(module_tests)
TESTS = $(module_tests)

AM_CPPFLAGS = -I$(top_srcdir)/intl

# We need libgcrypt because libjnlib-config includes gcrypt.h
AM_CFLAGS = -DJNLIB_IN_JNLIB $(LIBGCRYPT_CFLAGS)

noinst_LIBRARIES = libjnlib.a


#libjnlib_a_LDFLAGS =
libjnlib_a_SOURCES = \
	libjnlib-config.h \
	stringhelp.c stringhelp.h \
	strlist.c strlist.h \
	utf8conv.c utf8conv.h \
	argparse.c argparse.h \
	logging.c logging.h  \
	dotlock.c dotlock.h  \
	types.h mischelp.c mischelp.h dynload.h w32help.h

if HAVE_W32_SYSTEM
libjnlib_a_SOURCES += w32-reg.c w32-afunix.c w32-afunix.h w32-gettext.c
endif


# For GnuPG we don't need the xmalloc stuff.
#       xmalloc.c xmalloc.h


#
# Module tests.
#
# These tests should only be used at the canonical location of jnlib
# which is the GnuPG package.  The reason for this is that t-support.c
# defines replacements for the actual used memory allocation functions
# so that there is no dependency on libgcrypt.
#
module_tests = t-stringhelp

t_jnlib_src = t-support.c t-support.h
t_jnlib_ldadd = libjnlib.a $(LIBINTL) $(LIBICONV)

t_stringhelp_SOURCES = t-stringhelp.c $(t_jnlib_src)
t_stringhelp_LDADD = $(t_jnlib_ldadd)

