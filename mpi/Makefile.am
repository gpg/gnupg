## Process this file with automake to produce Makefile.in

INCLUDES =  -I$(top_srcdir)/include
CFLAGS = @CFLAGS@ @MPI_OPT_FLAGS@
SFLAGS = @MPI_SFLAGS@

EXTRA_DIST = config.links
DISTCLEANFILES = mpih-add1.S mpih-mul1.S mpih-mul2.S mpih-mul3.S  \
		 mpih-lshift.S mpih-rshift.S mpih-sub1.S asm-syntax.h sysdep.h
CLEANFILES = tmp-*.s

noinst_LTLIBRARIES = libmpi.la

libmpi_la_LDFLAGS =
libmpi_la_SOURCES = longlong.h	   \
	      mpi-add.c      \
	      mpi-bit.c      \
	      mpi-cmp.c      \
	      mpi-div.c      \
	      mpi-gcd.c      \
	      mpi-internal.h \
	      mpi-inline.h   \
	      mpi-inline.c   \
	      mpi-inv.c      \
	      mpi-mul.c      \
	      mpi-pow.c      \
	      mpi-mpow.c     \
	      mpi-scan.c     \
	      mpicoder.c     \
	      mpih-cmp.c     \
	      mpih-div.c     \
	      mpih-mul.c     \
	      mpiutil.c      \
	      g10m.c

# Note this objects are actually links, the sourcefiles are
# distributed by special code in dist-hook
common_asm_objects = mpih-mul1.lo    \
		     mpih-mul2.lo    \
		     mpih-mul3.lo    \
		     mpih-add1.lo    \
		     mpih-sub1.lo    \
		     mpih-lshift.lo  \
		     mpih-rshift.lo

libmpi_la_DEPENDENCIES = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@
libmpi_la_LIBADD = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@

SUFFIXES = .S

.S.o:
	$(CPP) $(INCLUDES) $(DEFS) $< | grep -v '^#' >tmp-$*.s
	$(CC) $(CFLAGS) $(SFLAGS) -c tmp-$*.s
	mv tmp-$*.o $@
	rm -f tmp-$*.s

.S.lo:
	$(CPP) $(INCLUDES) $(DEFS) $< | grep -v '^#' >tmp-$*.s
	if test -f tmp-$*.lo; then rm tmp-$*.lo; fi
	if test -f tmp-$*.o ; then rm tmp-$*.o ; fi
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(SFLAGS) -c tmp-$*.s
	if test -f tmp-$*.lo; then mv tmp-$*.lo $*.lo; fi
	if test -f tmp-$*.o ; then mv tmp-$*.o	$*.o ; fi
	rm -f tmp-$*.s

