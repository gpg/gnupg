## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl -I../intl
needed_libs = ../cipher/libcipher.a  ../util/libutil.a \
	      ../mpi/libmpi.a ../util/libutil.a

noinst_PROGRAMS = mpicalc bftest cast5test clean-sat

mpicalc_SOURCES = mpicalc.c

bftest_SOURCES = bftest.c

cast5test_SOURCES = cast5test.c

clean_sat_SOURCES  = clean-sat.c


mpicalc_LDADD = @INTLLIBS@  $(needed_libs)
bftest_LDADD = @INTLLIBS@  $(needed_libs)
cast5test_LDADD = @INTLLIBS@  $(needed_libs)

mpicalc bftest cast5test: $(needed_libs)

