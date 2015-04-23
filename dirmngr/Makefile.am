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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

EXTRA_DIST = OAUTHORS ONEWS ChangeLog-2011

bin_PROGRAMS = dirmngr dirmngr-client

if USE_LDAPWRAPPER
libexec_PROGRAMS = dirmngr_ldap
endif

noinst_PROGRAMS = $(module_tests)
TESTS = $(module_tests)

AM_CPPFLAGS = -I$(top_srcdir)/common

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS)	\
            $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(NTBTLS_CFLAGS)		\
            $(LIBGNUTLS_CFLAGS)


BUILT_SOURCES = no-libgcrypt.c

CLEANFILES = no-libgcrypt.c

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
	cdb.h cdblib.c misc.c dirmngr-err.h  \
	ocsp.c ocsp.h validate.c validate.h  \
	dns-cert.c dns-cert.h \
	ks-action.c ks-action.h ks-engine.h \
	ks-engine-hkp.c ks-engine-http.c ks-engine-finger.c ks-engine-kdns.c

if USE_LDAP
dirmngr_SOURCES += ldapserver.h ldapserver.c ldap.c w32-ldap-help.h \
                   ldap-wrapper.h ldap-parse-uri.c ldap-parse-uri.h \
                   ks-engine-ldap.c $(ldap_url) $(extraldap_src)
ldaplibs = $(LDAPLIBS)
else
ldaplibs =
endif


dirmngr_LDADD = $(libcommontlsnpth) $(libcommonpth) \
        $(DNSLIBS) $(LIBASSUAN_LIBS) \
	$(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(NPTH_LIBS) \
	$(NTBTLS_LIBS) $(LIBGNUTLS_LIBS) $(LIBINTL) $(LIBICONV)
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
dirmngr_ldap_LDADD = $(libcommon) no-libgcrypt.o \
		     $(GPG_ERROR_LIBS) $(LDAPLIBS) $(LBER_LIBS) $(LIBINTL) \
		     $(LIBICONV)
endif

dirmngr_client_SOURCES = dirmngr-client.c
dirmngr_client_LDADD = $(libcommon) no-libgcrypt.o \
	                $(LIBASSUAN_LIBS) \
	               $(GPG_ERROR_LIBS) $(NETLIBS) $(LIBINTL) $(LIBICONV)
dirmngr_client_LDFLAGS = $(extra_bin_ldflags)


no-libgcrypt.c : $(top_srcdir)/tools/no-libgcrypt.c
	cat $(top_srcdir)/tools/no-libgcrypt.c > no-libgcrypt.c


t_common_src = t-support.h
# We need libcommontls, because we use the http functions.
t_common_ldadd = $(libcommontls) $(libcommon) no-libgcrypt.o \
                 $(GPG_ERROR_LIBS) $(NETLIBS) \
                 $(NTBTLS_LIBS) $(LIBGNUTLS_LIBS) \
                 $(DNSLIBS) $(LIBINTL) $(LIBICONV)

module_tests = t-dns-cert

if USE_LDAP
module_tests += t-ldap-parse-uri
endif

t_ldap_parse_uri_SOURCES = \
	t-ldap-parse-uri.c ldap-parse-uri.c ldap-parse-uri.h \
        $(ldap_url) $(t_common_src)
t_ldap_parse_uri_LDADD = $(ldaplibs) $(t_common_ldadd)

t_dns_cert_SOURCES = t-dns-cert.c dns-cert.c
t_dns_cert_LDADD   = $(t_common_ldadd)

$(PROGRAMS) : $(libcommon) $(libcommonpth) $(libcommontls) $(libcommontlsnpth)
