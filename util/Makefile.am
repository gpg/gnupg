## Process this file with automake to produce Makefile.in

# Those 2 files are in the CVS but currently not used.
EXTRA_DIST = xmalloc.c xmalloc.h logging.c logging.c

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LTLIBRARIES = libutil.la


libutil_la_LDFLAGS =
libutil_la_SOURCES = logger.c fileutil.c miscutil.c strgutil.c	\
		     ttyio.c  memory.c secmem.c errors.c iobuf.c \
		     dotlock.c http.c simple-gettext.c \
		     libutil-config.h  \
		     mischelp.h \
		     stringhelp.h stringhelp.c \
		     argparse.h argparse.c


http-test:  http.c
	gcc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) -g -Wall -DTEST \
	    -o http-test http.c libutil.a ../mpi/libmpi.a @INTLLIBS@





