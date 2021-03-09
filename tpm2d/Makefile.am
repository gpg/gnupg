AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

libexec_PROGRAMS = tpm2daemon

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) \
	     $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS) $(LIBTSS_CFLAGS)

tpm2daemon_SOURCES = \
        command.c \
        tpm2daemon.c \
        tpm2.c tpm2.h \
        tpm2daemon.h ibm-tss.h

tpm2daemon_LDADD = $(libcommonpth) \
	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	$(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV) $(LIBTSS_LIBS)
