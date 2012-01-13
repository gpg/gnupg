# ------------------------------------------------------------------
# This file is part of bzip2/libbzip2, a program and library for
# lossless, block-sorting data compression.
#
# bzip2/libbzip2 version 1.0.6 of 6 September 2010
# Copyright (C) 1996-2010 Julian Seward <jseward@bzip.org>
#
# Please read the WARNING, DISCLAIMER and PATENTS sections in the
# README file.
#
# This program is released under the terms of the license contained
# in the file LICENSE.
# ------------------------------------------------------------------
#
# Modified by g10 Code on 2010-09-23.
# Changed to automake by g10 Code on 2012-01-13.

EXTRA_DIST = README README.1st CHANGES LICENSE

noinst_LIBRARIES = libbz2.a

libbz2_a_SOURCES = blocksort.c huffman.c crctable.c randtable.c \
                   compress.c decompress.c bzlib.c bzlib.h bzlib_private.h
