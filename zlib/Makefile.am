# Process this file with automake to produce Makefile.in
# Copyright (C) 1995-1996 Jean-loup Gailly.
# For conditions of distribution and use, see copyright notice in zlib.h
# This is used if a systems lacks support of zlib

CFLAGS = -O -Wall

EXTRA_DIST = README algorithm.doc ChangeLog example.c
noinst_LIBRARIES = libzlib.a


libzlib_a_SOURCES = adler32.c compress.c crc32.c gzio.c \
		    uncompr.c deflate.c trees.c zutil.c \
		    inflate.c infblock.c inftrees.c \
		    infcodes.c infutil.c inffast.c \
		    zlib.h zconf.h deflate.h infblock.h  \
		    infcodes.h inffast.h inftrees.h infutil.h zutil.h


CLEANFILES = example foo.gz


