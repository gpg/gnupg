## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
EXTRA_DIST = OPTIONS  pubring.asc  options.skel
OMIT_DEPENDENCIES = zlib.h zconf.h
LDFLAGS = @LDFLAGS@ @DYNLINK_LDFLAGS@
needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

#noinst_PROGRAMS = gpgd
bin_PROGRAMS = gpg

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
	      tdbdump.c 	\
	      tdbio.c		\
	      tdbio.h		\
	      hkp.h		\
	      hkp.c		\
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
	      signal.c		\
	      helptext.c

gpg_SOURCES  = g10.c		\
	      $(common_source)	\
	      verify.c		\
	      decrypt.c 	\
	      keyedit.c 	\
	      dearmor.c 	\
	      keygen.c

#gpgd_SOURCES = gpgd.c \
#	       ks-proto.h \
#	       ks-proto.c \
#	       ks-db.c \
#	       ks-db.h \
#	       $(common_source)


LDADD =  $(needed_libs) @ZLIBS@ @INTLLIBS@


$(PROGRAMS): $(needed_libs)


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)
	$(INSTALL_DATA) $(srcdir)/options.skel \
				$(DESTDIR)$(pkgdatadir)/options.skel
	@set -e;\
	 if test -f $(DESTDIR)$(bindir)/gpgm ; then \
	   echo "removing obsolete gpgm binary" ;   \
	   rm $(DESTDIR)$(bindir)/gpgm ;	    \
	 fi

