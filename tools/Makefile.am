# Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

EXTRA_DIST = lspgpot ring-a-party mail-signed-keys convert-from-106
INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

bin_PROGRAMS    = gpgsplit
noinst_PROGRAMS = mpicalc bftest clean-sat mk-tdata shmtest

gpgsplit_LDADD  = $(needed_libs) @INTLLIBS@ @CAPLIBS@ @ZLIBS@
mpicalc_LDADD   = $(needed_libs) @INTLLIBS@ @CAPLIBS@
bftest_LDADD    = $(needed_libs) @INTLLIBS@ @CAPLIBS@ @DLLIBS@ @EGDLIBS@
shmtest_LDADD   = $(needed_libs) @INTLLIBS@ @CAPLIBS@

gpgsplit mpicalc bftest shmtest: $(needed_libs)
