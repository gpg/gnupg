# Process this file with automake to produce Makefile.in
# Copyright (C) 1995-1996 Jean-loup Gailly.
# For conditions of distribution and use, see copyright notice in zlib.h
# This is used if a systems lacks support of zlib

EXTRA_DIST = README algorithm.doc ChangeLog

# I found no other easy way to use this only if zlib is neede
# doing this with SUBDIR = @xxx@  in the top Makefile.am does not
# work because automake doesn't scan this Makefile.am here.
if ENABLE_LOCAL_ZLIB
noinst_LIBRARIES = libzlib.a
endif


libzlib_a_SOURCES = adler32.c compress.c crc32.c \
		    uncompr.c deflate.c trees.c zutil.c \
		    inflate.c infblock.c inftrees.c \
		    infcodes.c infutil.c inffast.c \
		    deflate.h infblock.h infcodes.h inffast.h \
		    inffixed.h inftrees.h infutil.h trees.h \
		    zconf.h zlib.h zutil.h


CLEANFILES = foo.gz



