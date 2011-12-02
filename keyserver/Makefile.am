# Makefile.am - Makefile for keyservers
# Copyright (C) 2001, 2002, 2004, 2005, 2006,
#               2009 Free Software Foundation, Inc.
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

# Note that we have renamed the resulting binaries to from gpgkeys_foo
# to gpg2keys_foo to allow for a non-conflicting installation of
# gnupg1 and gnupg2.  Having the same names for the helpers would
# otherwise lead to trouble when to uninstall one of them.
EXTRA_PROGRAMS = gpg2keys_ldap gpg2keys_hkp gpg2keys_finger gpg2keys_curl \
		 gpg2keys_kdns
EXTRA_SCRIPTS = gpg2keys_mailto

EXTRA_DIST = ChangeLog-2011

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/common -I$(top_srcdir)/intl

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

include $(top_srcdir)/am/cmacros.am

libexec_PROGRAMS = $(GPGKEYS_LDAP) $(GPGKEYS_HKP) $(GPGKEYS_FINGER) \
                   $(GPGKEYS_CURL) $(GPGKEYS_KDNS)
libexec_SCRIPTS = $(GPGKEYS_MAILTO)
noinst_SCRIPTS = gpg2keys_test

common_libs = ../gl/libgnu.a  ../common/libcommon.a ../jnlib/libjnlib.a
other_libs = $(LIBICONV) $(LIBINTL) $(CAPLIBS)

gpg2keys_ldap_SOURCES = gpgkeys_ldap.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_ldap_CPPFLAGS = $(LDAP_CPPFLAGS) $(AM_CPPFLAGS)
gpg2keys_ldap_LDADD = ../jnlib/libjnlib.a $(LDAPLIBS) $(GPG_ERROR_LIBS) \
                      $(NETLIBS) $(other_libs)

gpg2keys_finger_SOURCES = gpgkeys_finger.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_finger_CPPFLAGS = $(AM_CPPFLAGS)
gpg2keys_finger_LDADD = $(common_libs) $(GPG_ERROR_LIBS) \
                        $(NETLIBS) $(other_libs)

gpg2keys_kdns_SOURCES = gpgkeys_kdns.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_kdns_CPPFLAGS = $(AM_CPPFLAGS)
gpg2keys_kdns_LDADD = $(common_libs) $(GPG_ERROR_LIBS) \
                      $(ADNSLIBS) $(NETLIBS) $(other_libs)


gpg2keys_curl_SOURCES = gpgkeys_curl.c ksutil.c ksutil.h no-libgcrypt.c
gpg2keys_hkp_SOURCES  = gpgkeys_hkp.c ksutil.c ksutil.h no-libgcrypt.c
if FAKE_CURL
gpg2keys_curl_SOURCES += curl-shim.c curl-shim.h
gpg2keys_curl_CPPFLAGS = $(AM_CPPFLAGS)
gpg2keys_curl_LDADD = $(common_libs) $(GPG_ERROR_LIBS) $(NETLIBS) $(DNSLIBS) \
	              $(other_libs)
gpg2keys_hkp_SOURCES += curl-shim.c curl-shim.h
gpg2keys_hkp_CPPFLAGS = $(AM_CPPFLAGS)
gpg2keys_hkp_LDADD = $(common_libs) $(GPG_ERROR_LIBS) $(NETLIBS) $(DNSLIBS) \
	             $(other_libs)
else
# Note that we need to include all other libs here as well because
# some compilers don't care about inline functions and insert
# references to symbols used in unused inline functions.
gpg2keys_curl_CPPFLAGS = $(LIBCURL_CPPFLAGS) $(AM_CPPFLAGS)
gpg2keys_curl_LDADD = $(common_libs) $(GPG_ERROR_LIBS) $(NETLIBS) $(DNSLIBS) \
                      $(other_libs) $(LIBCURL) $(GETOPT)
gpg2keys_hkp_CPPFLAGS = $(LIBCURL_CPPFLAGS) $(AM_CPPFLAGS)
gpg2keys_hkp_LDADD =  $(common_libs) $(GPG_ERROR_LIBS) $(NETLIBS) $(DNSLIBS) \
                      $(other_libs) $(LIBCURL) $(GETOPT)
endif

# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs)
