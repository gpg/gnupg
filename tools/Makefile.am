## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = mpicalc

mpicalc_SOURCES = mpicalc.c


LDADD = -L ../cipher -L ../mpi -L ../util  -lmpi -lutil

$(PROGRAMS): ../mpi/libmpi.a

