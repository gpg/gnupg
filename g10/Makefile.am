## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = g10

g10_SOURCES = g10.c		\
	      build-packet.c	\
	      compress.c	\
	      encode.c		\
	      encr-data.c	\
	      filter.h		\
	      free-packet.c	\
	      getkey.c		\
	      keydb.h		\
	      ringedit.c	\
	      kbnode.c		\
	      keygen.c		\
	      main.h		\
	      mainproc.c	\
	      armor.c		\
	      mdfilter.c	\
	      cipher.c		\
	      options.h 	\
	      openfile.c	\
	      keyid.c		\
	      packet.h		\
	      parse-packet.c	\
	      passphrase.c	\
	      plaintext.c	\
	      pubkey-enc.c	\
	      seckey-cert.c	\
	      seskey.c		\
	      sign.c		\
	      comment.c 	\
	      sig-check.c


LDADD = -L ../cipher -L ../mpi -L ../util -lcipher -lmpi -lutil


$(PROGRAMS): ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

