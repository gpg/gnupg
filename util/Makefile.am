# Copyright (C) 1998, 1999, 2000, 2001, 2005 Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

## Process this file with automake to produce Makefile.in

INCLUDES = -I.. -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LIBRARIES = libutil.a

libutil_a_SOURCES = logger.c fileutil.c miscutil.c strgutil.c \
		    ttyio.c argparse.c memory.c secmem.c errors.c iobuf.c \
		    dotlock.c http.c pka.c membuf.c

if USE_SIMPLE_GETTEXT
libutil_a_SOURCES+=simple-gettext.c
endif

if HAVE_W32_SYSTEM
libutil_a_SOURCES+=w32reg.c
endif

if ENABLE_AGENT_SUPPORT
libutil_a_SOURCES+=assuan-buffer.c assuan-client.c assuan-defs.h \
                   assuan-errors.c assuan-logging.c assuan-socket-connect.c \
		   assuan-connect.c assuan-socket.c assuan-util.c
endif

if USE_INTERNAL_REGEX
libutil_a_SOURCES+=regex.c
endif

if USE_DNS_SRV
libutil_a_SOURCES+=srv.c srv.h
endif

# The internal regex code #includes these.
EXTRA_libutil_a_SOURCES = regcomp.c regexec.c regex_internal.c \
	                  regex_internal.h

# LIBOBJS is for the replacement functions
libutil_a_DEPENDENCIES = @LIBOBJS@
libutil_a_LIBADD = @LIBOBJS@

http-test:  http.c
	cc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) $(LDFLAGS) -g -Wall \
	    -DTEST -o http-test http.c libutil.a @LIBINTL@ @SRVLIBS@ @CAPLIBS@

srv-test:  srv.c
	cc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) $(LDFLAGS) -g -Wall \
	    -DTEST -o srv-test srv.c libutil.a @LIBINTL@ @SRVLIBS@ @CAPLIBS@

pka-test:  pka.c
	cc -DHAVE_CONFIG_H -I. -I. -I.. $(INCLUDES) $(LDFLAGS) -g -Wall \
	   -DTEST -o pka-test pka.c libutil.a @LIBINTL@ @SRVLIBS@ @CAPLIBS@
