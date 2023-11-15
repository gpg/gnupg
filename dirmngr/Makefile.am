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
             dirmngr-w32info.rc dirmngr.w32-manifest.in \
             dirmngr_ldap-w32info.rc dirmngr_ldap.w32-manifest.in \
             dirmngr-client-w32info.rc dirmngr-client.w32-manifest.in


dist_pkgdata_DATA = sks-keyservers.netCA.pem

bin_PROGRAMS = dirmngr dirmngr-client

if USE_LDAP
libexec_PROGRAMS = dirmngr_ldap
else
libexec_PROGRAMS =
endif

noinst_PROGRAMS = $(module_tests) $(module_net_tests) $(module_maint_tests)
if DISABLE_TESTS
TESTS =
else
TESTS = $(module_tests) $(module_net_tests)
endif

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
dirmngr_rc_objs        = dirmngr-w32info.o
dirmngr_ldap_rc_objs   = dirmngr_ldap-w32info.o
dirmngr_client_rc_objs = dirmngr-client-w32info.o

dirmngr-w32info.o        : dirmngr.w32-manifest        ../common/w32info-rc.h
dirmngr_ldap-w32info.o   : dirmngr_ldap.w32-manifest   ../common/w32info-rc.h
dirmngr-client-w32info.o : dirmngr-client.w32-manifest ../common/w32info-rc.h
endif

AM_CFLAGS = $(USE_C99_CFLAGS) \
            $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS)	\
            $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(NTBTLS_CFLAGS)		\
            $(LIBGNUTLS_CFLAGS)


if HAVE_W32_SYSTEM
ldap_url = ldap-url.h ldap-url.c
NETLIBS += -lwinhttp -lsecurity
else
ldap_url =
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
                   ldap-misc.c ldap-misc.h \
                   ks-engine-ldap.c $(ldap_url) ldap-wrapper.c
ldaplibs = $(LDAPLIBS)
else
ldaplibs =
endif


dirmngr_LDADD = $(libcommonpth) \
        $(DNSLIBS) $(LIBASSUAN_LIBS) \
	$(KSBA_LIBS) $(NPTH_LIBS) $(NTBTLS_LIBS) $(LIBGNUTLS_LIBS) \
        $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV) \
        $(NETLIBS) $(dirmngr_rc_objs)
if USE_LDAP
dirmngr_LDADD += $(ldaplibs) $(LBER_LIBS)
endif
dirmngr_LDFLAGS = $(extra_bin_ldflags)
dirmngr_DEPENDENCIES = $(dirmngr_rc_objs)

if USE_LDAP
dirmngr_ldap_SOURCES = dirmngr_ldap.c ldap-misc.c ldap-misc.h $(ldap_url)
dirmngr_ldap_CFLAGS = $(GPG_ERROR_CFLAGS) $(LIBGCRYPT_CFLAGS)
dirmngr_ldap_LDFLAGS =
dirmngr_ldap_LDADD = $(libcommon) \
		     $(GPG_ERROR_LIBS) $(LIBGCRYPT_LIBS) $(LDAPLIBS) \
		     $(LBER_LIBS) $(LIBINTL) $(LIBICONV) $(NETLIBS)  \
                     $(dirmngr_ldap_rc_objs)
dirmngr_ldap_DEPENDENCIES = $(dirmngr_ldap_rc_objs)
endif

dirmngr_client_SOURCES = dirmngr-client.c
dirmngr_client_LDADD = $(libcommon) \
                       $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) \
                       $(LIBGCRYPT_LIBS) $(NETLIBS) $(LIBINTL) $(LIBICONV) \
                       $(dirmngr_client_rc_objs)
dirmngr_client_LDFLAGS =
dirmngr_client_DEPENDENCIES = $(dirmngr_client_rc_objs)

t_common_src = t-support.h t-support.c
if USE_LIBDNS
t_common_src += dns.c dns.h
endif
t_common_ldadd = $(libcommon) $(LIBASSUAN_LIBS) \
                 $(NTBTLS_LIBS) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
                 $(LIBGNUTLS_LIBS) \
                 $(NETLIBS) $(DNSLIBS) $(LIBINTL) $(LIBICONV)

module_tests = t-http-basic

if USE_LDAP
module_tests += t-ldap-parse-uri t-ldap-misc
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
	               $(NTBTLS_LIBS) $(KSBA_LIBS) $(LIBGCRYPT_LIBS) \
                       $(GPG_ERROR_LIBS) \
                       $(LIBGNUTLS_LIBS) $(DNSLIBS)

t_ldap_parse_uri_SOURCES = \
	t-ldap-parse-uri.c ldap-parse-uri.c ldap-parse-uri.h \
        http.c http-common.c dns-stuff.c ldap-misc.c \
        $(ldap_url) $(t_common_src)
t_ldap_parse_uri_CFLAGS = -DWITHOUT_NPTH=1  $(USE_C99_CFLAGS) \
			  $(LIBGCRYPT_CFLAGS) $(NTBTLS_CFLAGS) \
                          $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS) $(KSBA_CFLAGS)
t_ldap_parse_uri_LDADD = $(ldaplibs) $(t_common_ldadd) $(KSBA_LIBS) $(DNSLIBS)

t_ldap_misc_SOURCES = t-ldap-misc.c ldap-misc.c ldap-misc.h $(ldap_url)
t_ldap_misc_CFLAGS = -DWITHOUT_NPTH=1 $(GPG_ERROR_CFLAGS) $(LIBGCRYPT_CFLAGS) \
                     $(NTBTLS_CFLAGS)
t_ldap_misc_LDFLAGS =
t_ldap_misc_LDADD = $(libcommon) $(NTBTLS_LIBS) $(LIBGCRYPT_LIBS) \
                    $(LDAPLIBS) $(LBER_LIBS) $(LIBINTL) \
                    $(KSBA_LIBS) $(GPG_ERROR_LIBS) $(LIBICONV) $(NETLIBS)


t_dns_stuff_CFLAGS = -DWITHOUT_NPTH=1  $(USE_C99_CFLAGS) \
		     $(LIBGCRYPT_CFLAGS) $(NTBTLS_CFLAGS) \
	             $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)
t_dns_stuff_SOURCES = $(t_common_src) t-dns-stuff.c dns-stuff.c
t_dns_stuff_LDADD   = $(t_common_ldadd) $(DNSLIBS)

$(PROGRAMS) : $(libcommon) $(libcommonpth)
