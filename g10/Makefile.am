## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include
EXTRA_DIST = OPTIONS

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
	      pkclist.c 	\
	      skclist.c 	\
	      ringedit.c	\
	      kbnode.c		\
	      keygen.c		\
	      main.h		\
	      mainproc.c	\
	      armor.c		\
	      mdfilter.c	\
	      textfilter.c	\
	      cipher.c		\
	      elg.c		\
	      rsa.c		\
	      options.h 	\
	      openfile.c	\
	      keyid.c		\
	      trustdb.c 	\
	      trustdb.h 	\
	      packet.h		\
	      parse-packet.c	\
	      passphrase.c	\
	      plaintext.c	\
	      pubkey-enc.c	\
	      seckey-cert.c	\
	      seskey.c		\
	      sign.c		\
	      import.c		\
	      export.c		\
	      comment.c 	\
	      sig-check.c


LDADD = -L ../cipher -L ../mpi -L ../util \
	-lcipher -lmpi -lutil


$(PROGRAMS): ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

