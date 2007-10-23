# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2005,
#               2007 Free Software Foundation, Inc.
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

AM_CPPFLAGS = -I.. -I$(top_srcdir)/include -I$(top_srcdir)/intl

if ! HAVE_DOSISH_SYSTEM
AM_CPPFLAGS += -DGNUPG_LIBDIR="\"$(libdir)/@PACKAGE@\""
endif


noinst_LIBRARIES = libcipher.a

libcipher_a_SOURCES = cipher.c	\
		 pubkey.c	\
		 md.c		\
		 dynload.c	\
		 bithelp.h	\
		 des.c		\
		 twofish.c	\
		 blowfish.c	\
		 cast5.c	\
		 rijndael.c     \
		 camellia.c camellia.h camellia-glue.c \
		 elgamal.c	\
		 elgamal.h	\
		 rsa.c rsa.h    \
		 primegen.c	\
		 random.h	\
		 random.c	\
		 rand-internal.h \
		 rmd.h		\
		 dsa.h		\
		 dsa.c		\
		 smallprime.c	\
		 algorithms.h   \
		 md5.c     	\
		 rmd160.c  	\
		 sha1.c         \
		 sha256.c

if USE_RNDLINUX
libcipher_a_SOURCES+=rndlinux.c
endif

if USE_RNDUNIX
libcipher_a_SOURCES+=rndunix.c
endif

if USE_RNDEGD
libcipher_a_SOURCES+=rndegd.c
endif

if USE_RNDW32
libcipher_a_SOURCES+=rndw32.c
endif

if USE_SHA512
libcipher_a_SOURCES+=sha512.c
endif

EXTRA_libcipher_a_SOURCES=idea-stub.c
libcipher_a_DEPENDENCIES=@IDEA_O@
libcipher_a_LIBADD=@IDEA_O@
