## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include
EXTRA_DIST = OPTIONS  pubring.g10
needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

bin_PROGRAMS = g10 g10maint

common_source =  \
	      build-packet.c	\
	      compress.c	\
	      filter.h		\
	      free-packet.c	\
	      getkey.c		\
	      keydb.h		\
	      pkclist.c 	\
	      skclist.c 	\
	      ringedit.c	\
	      kbnode.c		\
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
	      pubkey-enc.c	\
	      seckey-cert.c	\
	      seskey.c		\
	      import.c		\
	      export.c		\
	      comment.c 	\
	      status.c		\
	      status.h		\
	      sign.c		\
	      plaintext.c	\
	      encr-data.c	\
	      encode.c		\
	      revoke.c		\
	      sig-check.c

g10_SOURCES  = g10.c		\
	      $(common_source)	\
	      keygen.c


g10maint_SOURCES = g10maint.c	\
	      dearmor.c 	\
	      $(common_source)

LDADD = @INTLLIBS@ $(needed_libs) @ZLIBS@

$(PROGRAMS): $(needed_libs)

