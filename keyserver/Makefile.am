# Copyright (C) 2001, 2002, 2004, 2005, 2006 Free Software Foundation, Inc.
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

EXTRA_PROGRAMS = gpg2keys_ldap gpg2keys_hkp gpg2keys_finger gpg2keys_curl
EXTRA_SCRIPTS = gpg2keys_mailto

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/common -I$(top_srcdir)/intl 

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

include $(top_srcdir)/am/cmacros.am

libexec_PROGRAMS = $(GPGKEYS_LDAP) $(GPGKEYS_HKP) $(GPGKEYS_FINGER) \
                   $(GPGKEYS_CURL)
libexec_SCRIPTS = $(GPGKEYS_MAILTO)
noinst_SCRIPTS = gpgkeys_test

common_libs = ../gl/libgnu.a ../common/libcommon.a ../jnlib/libjnlib.a
other_libs = $(LIBICONV) $(LIBINTL) $(CAPLIBS)

gpg2keys_ldap_SOURCES = gpgkeys_ldap.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_hkp_SOURCES = gpgkeys_hkp.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_finger_SOURCES = gpgkeys_finger.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_curl_SOURCES = gpgkeys_curl.c ksutil.c ksutil.h no-libgcrypt.c


gpg2keys_ldap_CPPFLAGS = $(LDAP_CPPFLAGS) $(AM_CPPFLAGS)
gpg2keys_ldap_LDADD = $(common_libs) $(LDAPLIBS) $(NETLIBS) \
                      $(other_libs) $(W32LIBS)

gpg2keys_finger_LDADD = $(common_libs) $(LIBGCRYPT_LIBS) \
                        $(NETLIBS) $(other_libs) $(W32LIBS)

if FAKE_CURL
gpg2keys_curl_SOURCES += curl-shim.c curl-shim.h
gpg2keys_curl_LDADD = $(common_libs) $(NETLIBS) $(DNSLIBS) \
	              $(other_libs) $(W32LIBS)
gpg2keys_hkp_SOURCES += curl-shim.c curl-shim.h
gpg2keys_hkp_LDADD = $(common_libs) $(NETLIBS) $(DNSLIBS) \
	             $(other_libs) $(W32LIBS)
else
gpg2keys_curl_CPPFLAGS = $(LIBCURL_CPPFLAGS) $(AM_CPPFLAGS)
gpg2keys_curl_LDADD = $(LIBCURL) $(GETOPT)
gpg2keys_hkp_CPPFLAGS = $(LIBCURL_CPPFLAGS) $(AM_CPPFLAGS)
gpg2keys_hkp_LDADD = $(LIBCURL) $(GETOPT)
endif

# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs)


