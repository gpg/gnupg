## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl -I../intl
EXTRA_DIST = OPTIONS  pubring.asc
OMIT_DEPENDENCIES = zlib.h zconf.h
LDFLAGS = -rdynamic
needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

noinst_PROGRAMS = gpgd
bin_PROGRAMS = gpg gpgm

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
	      dsa.c		\
	      rsa.c		\
	      misc.c		\
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
	      keyedit.c 	\
	      plaintext.c	\
	      encr-data.c	\
	      encode.c		\
	      revoke.c		\
	      keylist.c 	\
	      sig-check.c	\
	      signal.c

gpg_SOURCES  = g10.c		\
	      $(common_source)	\
	      verify.c		\
	      decrypt.c 	\
	      keygen.c


gpgm_SOURCES = dearmor.c     \
	      $(common_source)

gpgd_SOURCES = gpgd.c \
	      ks-proto.h \
	      ks-proto.c \
	      $(common_source)


LDADD = @INTLLIBS@ $(needed_libs) @ZLIBS@

gpgm_LDADD = g10maint.o $(LDADD)

g10maint.o: g10.c
	$(COMPILE) -DIS_G10MAINT  -o g10maint.o -c g10.c


$(PROGRAMS): $(needed_libs)

