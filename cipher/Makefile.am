## Process this file with automake to produce Makefile.in

INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl -I../intl
EXTRA_DIST = @CIPHER_EXTRA_DIST@

noinst_LIBRARIES = libcipher.a


libcipher_a_SOURCES = cipher.c	\
		 blowfish.c	\
		 blowfish.h	\
		 cast5.c	\
		 cast5.h	\
		 elgamal.c	\
		 elgamal.h	\
		 md5.c		\
		 md5.h		\
		 primegen.c	\
		 random.h	\
		 random.c	\
		 rand-internal.h \
		 rand-unix.c	\
		 rand-w32.c	\
		 rand-dummy.c	\
		 rmd.h		\
		 rmd160.c	\
		 tiger.h	\
		 tiger.c	\
		 sha1.h 	\
		 sha1.c 	\
		 dsa.h		\
		 dsa.c		\
		 md.c		\
		 md.h		\
		 misc.c 	\
		 smallprime.c

libcipher_a_DEPENDENCIES = @CIPHER_EXTRA_OBJS@
libcipher_a_LIBADD = @CIPHER_EXTRA_OBJS@


