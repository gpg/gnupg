## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include
EXTRA_DIST = @CIPHER_EXTRA_DIST@

noinst_LIBRARIES = cipher


cipher_SOURCES = blowfish.c	\
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
		 misc.c 	\
		 smallprime.c

cipher_LIBADD = @CIPHER_EXTRA_OBJS@


