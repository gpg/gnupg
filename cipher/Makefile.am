# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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


INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LIBRARIES = libcipher.a

# The configure script greps the module names from the EXTRA_PROGRAMS line
EXTRA_PROGRAMS = rndlinux rndunix rndegd rndw32 sha1 rmd160 md5 tiger

EXTRA_rndlinux_SOURCES = rndlinux.c
EXTRA_rndunix_SOURCES = rndunix.c
EXTRA_rndegd_SOURCES = rndegd.c
EXTRA_rndw32_SOURCES = rndw32.c
EXTRA_md5_SOURCES = md5.c
EXTRA_rmd160_SOURCES = rmd160.c
EXTRA_sha1_SOURCES = sha1.c
EXTRA_tiger_SOURCES = tiger.c


if ENABLE_GNUPG_EXTENSIONS
pkglib_PROGRAMS  = @DYNAMIC_CIPHER_MODS@
else
pkglib_PROGRAMS  =
endif


DYNLINK_MOD_CFLAGS = -DIS_MODULE @DYNLINK_MOD_CFLAGS@

#libcipher_a_LDFLAGS =
libcipher_a_SOURCES = cipher.c	\
		 pubkey.c	\
		 md.c		\
		 dynload.c	\
		 dynload.h	\
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
		 construct.c

# configure creates the constructor file
BUILT_SOURCES = construct.c


libcipher_a_DEPENDENCIES = @STATIC_CIPHER_OBJS@
libcipher_a_LIBADD =	   @STATIC_CIPHER_OBJS@


# If I remember it correct, automake 1.4 has a feature to set
# fooFLAGS depending on the program.  So we should check it out.

tiger: $(srcdir)/tiger.c
	`echo $(COMPILE) $(DYNLINK_MOD_CFLAGS) -o tiger $(srcdir)/tiger.c | \
	    sed -e 's/-O[2-9s]*/-O/g' `

tiger.o: $(srcdir)/tiger.c
	`echo $(COMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `

#twofish: $(srcdir)/twofish.c
#	 `echo $(COMPILE) $(DYNLINK_MOD_CFLAGS) -o twofish $(srcdir)/twofish.c | \
#	     sed -e 's/-O[0-9s]*/  /g' `

twofish: $(srcdir)/twofish.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o twofish $(srcdir)/twofish.c

#twofish.o: $(srcdir)/twofish.c
#	 `echo $(COMPILE) -c $(srcdir)/twofish.c | sed -e 's/-O[0-9s]*/  /g' `


rndunix: $(srcdir)/rndunix.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndunix $(srcdir)/rndunix.c

rndlinux: $(srcdir)/rndlinux.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndlinux $(srcdir)/rndlinux.c

rndegd: $(srcdir)/rndegd.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndegd $(srcdir)/rndegd.c

