# Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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

INCLUDES = -I.. -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LIBRARIES = libcipher.a

libcipher_a_SOURCES = cipher.c	\
		 pubkey.c	\
		 md.c		\
		 dynload.c	\
		 bithelp.h	\
		 des.c		\
		 des.h		\
		 twofish.c	\
		 blowfish.c	\
		 blowfish.h	\
		 cast5.c	\
		 cast5.h	\
		 rijndael.c     \
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
		 g10c.c 	\
		 smallprime.c	\
		 algorithms.h   \
		 rndlinux.c	\
		 rndunix.c 	\
		 rndegd.c  	\
		 rndw32.c  	\
		 md5.c     	\
		 rmd160.c  	\
		 sha1.c    	\
		 tiger.c        

EXTRA_libcipher_a_SOURCES = idea-stub.c

libcipher_a_DEPENDENCIES = @IDEA_O@
libcipher_a_LIBADD = @IDEA_O@

tiger.o: $(srcdir)/tiger.c
	`echo $(COMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `


