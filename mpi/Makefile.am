## Process this file with automake to produce Makefile.in

INCLUDES =  -I$(top_srcdir)/include
CFLAGS += -O2

SUFFIXES = .S .s

EXTRA_DIST = config.links
DISTCLEANFILES = mpih-add1.S mpih-mul1.S mpih-mul2.S mpih-mul3.S  \
		 mpih-lshift.S mpih-rshift.S mpih-sub1.S asm-syntax.h sysdep.h


noinst_LIBRARIES = libmpi.a
# noinst_HEADERS   =



libmpi_a_SOURCES = longlong.h	  \
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
	      mpi-mpow.c     \
	      mpi-scan.c     \
	      mpicoder.c     \
	      mpih-cmp.c     \
	      mpih-add.c     \
	      mpih-sub.c     \
	      mpih-div.c     \
	      mpih-mul.c     \
	      mpiutil.c      \
	      g10m.c

# Note this objects are actually links, the sourcefiles are
# distributed by special code in dist-hook
common_asm_objects = mpih-mul1.o    \
		     mpih-mul2.o    \
		     mpih-mul3.o    \
		     mpih-add1.o    \
		     mpih-sub1.o    \
		     mpih-lshift.o  \
		     mpih-rshift.o

libmpi_a_DEPENDENCIES = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@
libmpi_a_LIBADD = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@

