## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include

noinst_LIBRARIES = cipher


# please add "rsa.c" and "rsa.h" manually in Makefile.am
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
		 smallprime.c

cipher_LIBADD = rsa.o


