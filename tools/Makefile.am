# Copyright (C) 1998, 1999, 2000, 2001, 2003,
#               2004  Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
## Process this file with automake to produce Makefile.in

EXTRA_DIST = lspgpot ring-a-party mail-signed-keys convert-from-106

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/intl

if ! HAVE_DOSISH_SYSTEM
AM_CPPFLAGS += -DLOCALEDIR="\"$(localedir)\""
endif

needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a 
other_libs = $(LIBICONV) $(LIBINTL) $(CAPLIBS)

bin_PROGRAMS    = gpgsplit
noinst_PROGRAMS = mpicalc bftest clean-sat mk-tdata shmtest make-dns-cert

if HAVE_USTAR
bin_SCRIPTS = gpg-zip
endif

if HAVE_SHM
noinst_PROGRAMS += shmtest
endif

gpgsplit_LDADD  = $(needed_libs) $(other_libs) @ZLIBS@
mpicalc_LDADD   = $(needed_libs) $(other_libs) @W32LIBS@
bftest_LDADD    = $(needed_libs) $(other_libs) @W32LIBS@ @DLLIBS@ @NETLIBS@ @LIBREADLINE@
shmtest_LDADD   = $(needed_libs) $(other_libs) @LIBREADLINE@

gpgsplit mpicalc bftest shmtest: $(needed_libs)
