## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
EXTRA_DIST = OPTIONS  pubring.asc  options.skel
OMIT_DEPENDENCIES = zlib.h zconf.h
LDFLAGS = @LDFLAGS@ @DYNLINK_LDFLAGS@
needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

#noinst_PROGRAMS = gpgd
bin_PROGRAMS = gpg gpgm

common_source =  \
	      build-packet.c	\
	      compress.c	\
	      filter.h		\
	      free-packet.c	\
	      getkey.c		\
	      keydb.h		\
	      delkey.c		\
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
	      misc.c		\
	      options.h 	\
	      openfile.c	\
	      keyid.c		\
	      trustdb.c 	\
	      trustdb.h 	\
	      tdbio.c		\
	      tdbio.h		\
	      pref.h		\
	      pref.c		\
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
	      keylist.c 	\
	      sig-check.c	\
	      signal.c

gpg_SOURCES  = g10.c		\
	      $(common_source)	\
	      verify.c		\
	      decrypt.c 	\
	      keyedit.c 	\
	      keygen.c


gpgm_SOURCES = dearmor.c     \
	      $(common_source)

#gpgd_SOURCES = gpgd.c \
#	       ks-proto.h \
#	       ks-proto.c \
#	       ks-db.c \
#	       ks-db.h \
#	       $(common_source)


LDADD =  $(needed_libs) @ZLIBS@ @INTLLIBS@

gpgm_LDADD = g10maint.o $(LDADD)

g10maint.o: $(srcdir)/g10.c
	$(COMPILE) -DIS_G10MAINT  -o g10maint.o -c $(srcdir)/g10.c


$(PROGRAMS): $(needed_libs)


install-data-local:
	$(mkinstalldirs) $(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/options.skel $(pkgdatadir)/options.skel



