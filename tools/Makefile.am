# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

