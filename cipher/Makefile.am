## Process this file with automake to produce Makefile.in

INCLUDES =  -I$(top_srcdir)/include
EXTRA_DIST = @CIPHER_EXTRA_DIST@

noinst_LIBRARIES = libcipher.a


libcipher_a_SOURCES = blowfish.c     \
		 blowfish.h	\
		 elgamal.c	\
		 elgamal.h	\
		 gost.c 	\
		 gost.h 	\
		 md5.c		\
		 md5.h		\
		 primegen.c	\
		 random.c	\
		 rmd.h		\
		 rmd160.c	\
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


