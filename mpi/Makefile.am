## Process this file with automake to produce Makefile.in

INCLUDES =  -I$(top_srcdir)/include
CFLAGS += -O2

SUFFIXES = .S .s

SUBDIRS = generic i386
EXTRA_DIST = config.links


noinst_LIBRARIES = mpi
noinst_HEADERS	 = sysdep.h

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
	      mpih-shift.o

#mpi_DEPENDENCIES = mpih-mul1.S    \
#		    mpih-mul2.S    \
#		    mpih-mul3.S    \
#		    mpih-add1.S    \
#		    mpih-sub1.S    \
#		    mpih-shift.S
#

##DISTCLEANFILES = @MPI_DISTCLEANFILES@


