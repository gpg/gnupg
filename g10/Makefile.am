## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = g10

g10_SOURCES = g10.c		\
	      build-packet.c	\
	      compressed.c	\
	      encode.c		\
	      encr-data.c	\
	      filter.h		\
	      free-packet.c	\
	      getkey.c		\
	      keydb.h		\
	      keygen.c		\
	      main.h		\
	      mainproc.c	\
	      mdfilter.c	\
	      options.h 	\
	      overwrite.c	\
	      packet.h		\
	      parse-packet.c	\
	      passphrase.c	\
	      plaintext.c	\
	      pubkey-enc.c	\
	      seckey-cert.c	\
	      seskey.c		\
	      sig-check.c


LDADD = -L ../cipher -L ../mpi -L ../util -lcipher -lmpi -lutil


$(PROGRAMS): ../cipher/libcipher.a ../mpi/libmpi.a

