## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LIBRARIES = libutil.a


#libutil_a_LDFLAGS =
libutil_a_SOURCES = g10u.c logger.c fileutil.c miscutil.c strgutil.c  \
		     ttyio.c  argparse.c memory.c secmem.c errors.c iobuf.c \
		     dotlock.c http.c simple-gettext.c w32reg.c


http-test:  http.c
	gcc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) -g -Wall -DTEST \
	    -o http-test http.c libutil.a ../mpi/libmpi.a @INTLLIBS@



