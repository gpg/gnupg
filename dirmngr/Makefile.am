# Makefile.am - dirmngr
# Copyright (C) 2002 Klarälvdalens Datakonsult AB
# Copyright (C) 2004, 2007, 2010 g10 Code GmbH
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
# along with this program; if not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0+

## Process this file with automake to produce Makefile.in

EXTRA_DIST = OAUTHORS ONEWS ChangeLog-2011 tls-ca.pem \
             dirmngr-w32info.rc dirmngr.w32-manifest.in


dist_pkgdata_DATA = sks-keyservers.netCA.pem

bin_PROGRAMS = dirmngr dirmngr-client

if USE_LDAPWRAPPER
libexec_PROGRAMS = dirmngr_ldap
endif

noinst_PROGRAMS = $(module_tests) $(module_net_tests) $(module_maint_tests)
if DISABLE_TESTS
TESTS =
else
TESTS = $(module_tests) $(module_net_tests)
endif

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(USE_C99_CFLAGS) \
            $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS)	\
            $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(NTBTLS_CFLAGS)		\
            $(LIBGNUTLS_CFLAGS)


if HAVE_W32_SYSTEM
ldap_url = ldap-url.h ldap-url.c
else
ldap_url =
endif

if USE_LDAPWRAPPER
extraldap_src = ldap-wrapper.c
else
extraldap_src = ldap-wrapper-ce.c  dirmngr_ldap.c
endif

noinst_HEADERS = dirmngr.h crlcache.h crlfetch.h misc.h

dirmngr_SOURCES = dirmngr.c dirmngr.h server.c crlcache.c crlfetch.c	\
	certcache.c certcache.h \
	domaininfo.c \
	workqueue.c \
	loadswdb.c \
	cdb.h cdblib.c misc.c dirmngr-err.h dirmngr-status.h \
	ocsp.c ocsp.h validate.c validate.h  \
	dns-stuff.c dns-stuff.h \
	http.c http.h http-common.c http-common.h http-ntbtls.c \
	ks-action.c ks-action.h ks-engine.h \
	ks-engine-hkp.c ks-engine-http.c ks-engine-finger.c ks-engine-kdns.c

if USE_LIBDNS
dirmngr_SOURCES += dns.c dns.h
endif

if USE_LDAP
dirmngr_SOURCES += ldapserver.h ldapserver.c ldap.c w32-ldap-help.h \
                   ldap-wrapper.h ldap-parse-uri.c ldap-parse-uri.h \
                   ks-engine-ldap.c $(ldap_url) $(extraldap_src)
ldaplibs = $(LDAPLIBS)
else
ldaplibs =
endif

if HAVE_W32_SYSTEM
dirmngr_robjs = $(resource_objs) dirmngr-w32info.o
dirmngr-w32info.o : dirmngr.w32-manifest
else
dirmngr_robjs =
endif


dirmngr_LDADD = $(libcommonpth) \
        $(DNSLIBS) $(LIBASSUAN_LIBS) \
	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(NPTH_LIBS) \
	$(NTBTLS_LIBS) $(LIBGNUTLS_LIBS) $(LIBINTL) $(LIBICONV) $(NETLIBS) \
        $(dirmngr_robj)
if USE_LDAP
dirmngr_LDADD += $(ldaplibs)
endif
if !USE_LDAPWRAPPER
dirmngr_LDADD += $(ldaplibs)
endif
dirmngr_LDFLAGS = $(extra_bin_ldflags)

if USE_LDAPWRAPPER
dirmngr_ldap_SOURCES = dirmngr_ldap.c $(ldap_url)
dirmngr_ldap_CFLAGS = $(GPG_ERROR_CFLAGS) $(LIBGCRYPT_CFLAGS)
dirmngr_ldap_LDFLAGS =
dirmngr_ldap_LDADD = $(libcommon) \
		     $(GPG_ERROR_LIBS) $(LIBGCRYPT_LIBS) $(LDAPLIBS) \
		     $(LBER_LIBS) $(LIBINTL) $(LIBICONV) $(NETLIBS)
endif

dirmngr_client_SOURCES = dirmngr-client.c
dirmngr_client_LDADD = $(libcommon) \
                       $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) \
                       $(LIBGCRYPT_LIBS) $(NETLIBS) $(LIBINTL) $(LIBICONV)
dirmngr_client_LDFLAGS = $(extra_bin_ldflags)


t_common_src = t-support.h t-support.c
if USE_LIBDNS
t_common_src += dns.c dns.h
endif
t_common_ldadd = $(libcommon) $(LIBASSUAN_LIBS) $(LIBGCRYPT_LIBS) \
                 $(GPG_ERROR_LIBS) $(NETLIBS) \
                 $(NTBTLS_LIBS) $(LIBGNUTLS_LIBS) \
                 $(DNSLIBS) $(LIBINTL) $(LIBICONV)

module_tests = t-http-basic

if USE_LDAP
module_tests += t-ldap-parse-uri
endif

# Test which need a network connections are only used in maintainer mode.
if MAINTAINER_MODE
module_net_tests = t-dns-stuff
else
module_net_tests =
endif

# Tests which are only for manually testing are only build in maintainer-mode.
if MAINTAINER_MODE
module_maint_tests = t-http
else
module_maint_tests =
endif


# http tests
# We need to add the KSBA flags in case we are building against GNUTLS.
# In that case NTBTLS flags are empty, but we need ksba anyway.
t_http_SOURCES = $(t_common_src) t-http.c http.c dns-stuff.c http-common.c
t_http_CFLAGS  = -DWITHOUT_NPTH=1  $(USE_C99_CFLAGS) \
	         $(LIBGCRYPT_CFLAGS) $(NTBTLS_CFLAGS) $(LIBGNUTLS_CFLAGS) \
                 $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS) $(KSBA_CFLAGS)
t_http_LDADD   = $(t_common_ldadd) \
	         $(NTBTLS_LIBS) $(KSBA_LIBS) $(LIBGNUTLS_LIBS) $(DNSLIBS)

t_http_basic_SOURCES = $(t_common_src) t-http-basic.c http.c \
	               dns-stuff.c http-common.c
t_http_basic_CFLAGS  = -DWITHOUT_NPTH=1  $(USE_C99_CFLAGS) \
	         $(LIBGCRYPT_CFLAGS) $(NTBTLS_CFLAGS) $(LIBGNUTLS_CFLAGS) \
                 $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS) $(KSBA_CFLAGS)
t_http_basic_LDADD   = $(t_common_ldadd) \
	         $(NTBTLS_LIBS) $(KSBA_LIBS) $(LIBGNUTLS_LIBS) $(DNSLIBS)


t_ldap_parse_uri_SOURCES = \
	t-ldap-parse-uri.c ldap-parse-uri.c ldap-parse-uri.h \
        http.c http-common.c dns-stuff.c \
        $(ldap_url) $(t_common_src)
t_ldap_parse_uri_CFLAGS = -DWITHOUT_NPTH=1  $(USE_C99_CFLAGS) \
			  $(LIBGCRYPT_CFLAGS) \
                          $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)
t_ldap_parse_uri_LDADD = $(ldaplibs) $(t_common_ldadd) $(DNSLIBS)

t_dns_stuff_CFLAGS = -DWITHOUT_NPTH=1  $(USE_C99_CFLAGS) \
		     $(LIBGCRYPT_CFLAGS) \
	             $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)
t_dns_stuff_SOURCES = $(t_common_src) t-dns-stuff.c dns-stuff.c
t_dns_stuff_LDADD   = $(t_common_ldadd) $(DNSLIBS)

$(PROGRAMS) : $(libcommon) $(libcommonpth)
