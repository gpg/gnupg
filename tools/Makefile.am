## Process this file with automake to produce Makefile.in

EXTRA_DIST = lspgpot ring-a-party mail-signed-keys
INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
needed_libs = ../cipher/libcipher.a  \
	      ../mpi/libmpi.a ../util/libutil.a @INTLLIBS@

noinst_PROGRAMS = mpicalc bftest clean-sat mk-tdata shmtest

mpicalc_SOURCES = mpicalc.c

bftest_SOURCES = bftest.c

clean_sat_SOURCES  = clean-sat.c
mk_tdata_SOURCES = mk-tdata.c
shmtest_SOURCES = shmtest.c


mpicalc_LDADD =  $(needed_libs)
bftest_LDADD =	$(needed_libs)

shmtest_LDADD =  $(needed_libs)

mpicalc bftest shmtest: $(needed_libs)

