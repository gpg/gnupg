## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include
needed_libs = ../cipher/libcipher.a  ../util/libutil.a ../mpi/libmpi.a ../util/libutil.a

noinst_PROGRAMS = mpicalc bftest clean-sat

mpicalc_SOURCES = mpicalc.c

bftest_SOURCES = bftest.c

clean_sat_SOURCES  = clean-sat.c


mpicalc_LDADD = @INTLLIBS@  $(needed_libs)
bftest_LDADD = @INTLLIBS@  $(needed_libs)

mpicalc bftest: $(needed_libs)

