## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include

noinst_PROGRAMS = mpicalc bftest

mpicalc_SOURCES = mpicalc.c

bftest_SOURCES = bftest.c


LDADD = -L ../cipher -L ../mpi -L ../util -L ../cipher	\
	-lmpi -lutil -lmpi -lutil -lcipher

$(PROGRAMS): ../mpi/libmpi.a ../cipher/libcipher.a

