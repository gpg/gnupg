## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
EXTRA_DIST = README

noinst_LIBRARIES = libutil.a

libutil_a_SOURCES = logger.c fileutil.c miscutil.c strgutil.c	\
		     ttyio.c  errors.c iobuf.c \
		     http.c simple-gettext.c w32reg.c


http-test:  http.c
	gcc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) -g -Wall -DTEST \
	    -o http-test http.c libutil.a ../mpi/libmpi.a @INTLLIBS@





