## Process this file with automake to produce Makefile.in

EXTRA_DIST = lspgpot mail-signed-keys ring-a-party
INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
# we need to add libutil.la a second time because we have to resolve
# gpg_log_ in some libjnlib modules. - very ugly - should be removed soon.
needed_libs = ../util/libutil.la ../gcrypt/libgcrypt.la \
	      ../jnlib/libjnlib.la ../util/libutil.la @INTLLIBS@


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

