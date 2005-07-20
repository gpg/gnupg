# Copyright (C) 2001, 2002, 2004, 2005 Free Software Foundation, Inc.
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

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl
EXTRA_PROGRAMS = gpgkeys_ldap gpgkeys_hkp gpgkeys_http gpgkeys_finger gpgkeys_curl
EXTRA_SCRIPTS = gpgkeys_mailto

gpglibexecdir = $(libexecdir)/@PACKAGE@

gpglibexec_PROGRAMS = @GPGKEYS_LDAP@ @GPGKEYS_HKP@ @GPGKEYS_FINGER@ @GPGKEYS_HTTP@ @GPGKEYS_CURL@
gpglibexec_SCRIPTS = @GPGKEYS_MAILTO@
noinst_SCRIPTS = gpgkeys_test

gpgkeys_ldap_SOURCES = gpgkeys_ldap.c ksutil.c ksutil.h
gpgkeys_hkp_SOURCES = ksutil.c ksutil.h
gpgkeys_http_SOURCES = gpgkeys_http.c ksutil.c ksutil.h
gpgkeys_finger_SOURCES = gpgkeys_finger.c ksutil.c ksutil.h
gpgkeys_curl_SOURCES = gpgkeys_curl.c ksutil.c ksutil.h

other_libs = $(LIBICONV) $(LIBINTL) $(CAPLIBS)

gpgkeys_ldap_LDADD = ../util/libutil.a @LDAPLIBS@ @NETLIBS@ $(other_libs) @GETOPT@ @W32LIBS@
gpgkeys_http_LDADD = ../util/libutil.a @NETLIBS@ @SRVLIBS@ $(other_libs) @GETOPT@ @W32LIBS@
gpgkeys_finger_LDADD = ../util/libutil.a @NETLIBS@ $(other_libs) @GETOPT@ @W32LIBS@

if WITH_CURL
gpgkeys_hkp_SOURCES += gpgkeys_hkp.c
if FAKE_CURL
gpgkeys_curl_SOURCES += curl-shim.c curl-shim.h
gpgkeys_curl_LDADD = ../util/libutil.a @NETLIBS@ @SRVLIBS@ $(other_libs) @GETOPT@ @W32LIBS@
gpgkeys_hkp_SOURCES += curl-shim.c curl-shim.h
gpgkeys_hkp_LDADD = ../util/libutil.a @NETLIBS@ @SRVLIBS@ $(other_libs) @GETOPT@ @W32LIBS@
else
gpgkeys_curl_CPPFLAGS = @LIBCURL_CPPFLAGS@
gpgkeys_curl_LDADD = @LIBCURL@ @GETOPT@
gpgkeys_hkp_CPPFLAGS = @LIBCURL_CPPFLAGS@
gpgkeys_hkp_LDADD = @LIBCURL@ @GETOPT@
endif
else
gpgkeys_hkp_SOURCES += gpgkeys_oldhkp.c
gpgkeys_hkp_LDADD = ../util/libutil.a @NETLIBS@ @SRVLIBS@ $(other_libs) @GETOPT@ @W32LIBS@
endif
