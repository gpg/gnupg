## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include
needed_libs = ../cipher/libcipher.a  ../util/libutil.a ../mpi/libmpi.a ../util/libutil.a

noinst_PROGRAMS = mpicalc bftest

mpicalc_SOURCES = mpicalc.c

bftest_SOURCES = bftest.c


LDADD = @INTLLIBS@  $(needed_libs)

$(PROGRAMS): $(needed_libs)

