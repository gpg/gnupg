## Process this file with automake to produce Makefile.in

INCLUDES =  -I$(top_srcdir)/include
CFLAGS += -O2

SUFFIXES = .S .s

EXTRA_DIST = config.links


noinst_LIBRARIES = mpi
# noinst_HEADERS   =

mpi_SOURCES = longlong.h     \
	      mpi-add.c      \
	      mpi-bit.c      \
	      mpi-cmp.c      \
	      mpi-div.c      \
	      mpi-gcd.c      \
	      mpi-internal.h \
	      mpi-inline.h   \
	      mpi-inv.c      \
	      mpi-mul.c      \
	      mpi-pow.c      \
	      mpi-scan.c     \
	      mpicoder.c     \
	      mpih-cmp.c     \
	      mpih-add.c     \
	      mpih-sub.c     \
	      mpih-div.c     \
	      mpih-mul.c     \
	      mpiutil.c

mpi_LIBADD =  mpih-mul1.o    \
	      mpih-mul2.o    \
	      mpih-mul3.o    \
	      mpih-add1.o    \
	      mpih-sub1.o    \
	      mpih-shift.o  @MPI_EXTRA_ASM_OBJS@


