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

INCLUDES = -I.. -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LIBRARIES = libutil.a

EXTRA_libutil_a_SOURCES = regcomp.c regex.c regexec.c regex_internal.c regex_internal.h

#libutil_a_LDFLAGS =
libutil_a_SOURCES = g10u.c logger.c fileutil.c miscutil.c strgutil.c  \
		     ttyio.c  argparse.c memory.c secmem.c errors.c iobuf.c \
		     dotlock.c http.c srv.h srv.c simple-gettext.c w32reg.c

libutil_a_DEPENDENCIES = @REGEX_O@
libutil_a_LIBADD = @REGEX_O@

http-test:  http.c
	gcc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) $(LDFLAGS) -g -Wall \
	    -DTEST -o http-test http.c libutil.a @INTLLIBS@ @SRVLIBS@ @CAPLIBS@

srv-test:  srv.c
	gcc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) $(LDFLAGS) -g -Wall \
	    -DTEST -o srv-test srv.c libutil.a @INTLLIBS@ @SRVLIBS@ @CAPLIBS@
