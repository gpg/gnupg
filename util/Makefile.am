## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LTLIBRARIES = libutil.la


libutil_la_LDFLAGS =
libutil_la_SOURCES = g10u.c logger.c fileutil.c miscutil.c strgutil.c  \
		     ttyio.c  argparse.c memory.c secmem.c errors.c iobuf.c \
		     dotlock.c http.c


http-test:  http.c
	gcc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) -g -Wall -DTEST \
	    -o http-test http.c libutil.a ../mpi/libmpi.a @INTLLIBS@



