# Makefile for common gnupg modules
# Copyright (C) 2001, 2003, 2007, 2010 Free Software Foundation, Inc.
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

EXTRA_DIST = mkstrtable.awk exaudit.awk exstatus.awk ChangeLog-2011 \
             audit-events.h status-codes.h ChangeLog.jnlib \
	     ChangeLog-2011.include w32info-rc.h.in gnupg.ico tls-ca.pem

noinst_LIBRARIES = libcommon.a libcommonpth.a libgpgrl.a \
                   libcommontls.a libcommontlsnpth.a
if !HAVE_W32CE_SYSTEM
noinst_LIBRARIES += libsimple-pwquery.a
endif
noinst_PROGRAMS = $(module_tests) $(module_maint_tests)
TESTS = $(module_tests)

BUILT_SOURCES = audit-events.h status-codes.h

MAINTAINERCLEANFILES = audit-events.h status-codes.h

AM_CPPFLAGS =

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(KSBA_CFLAGS)

include $(top_srcdir)/am/cmacros.am


common_sources = \
	common-defs.h \
	util.h i18n.c i18n.h \
	types.h host2net.h dynload.h w32help.h \
	mapstrings.c stringhelp.c stringhelp.h \
	strlist.c strlist.h \
	utf8conv.c utf8conv.h \
	argparse.c argparse.h \
	logging.c logging.h  \
	dotlock.c dotlock.h  \
        mischelp.c mischelp.h \
	status.c status.h\
	shareddefs.h \
	openpgpdefs.h \
	gc-opt-flags.h \
	keyserver.h \
	sexp-parse.h \
	tlv.c tlv.h \
	init.c init.h \
	sexputil.c \
	sysutils.c sysutils.h \
	homedir.c \
	gettime.c gettime.h \
	yesno.c \
	b64enc.c b64dec.c zb32.c \
	convert.c \
	percent.c \
	mbox-util.c mbox-util.h \
	miscellaneous.c \
	xasprintf.c \
	xreadline.c \
	membuf.c membuf.h \
	iobuf.c iobuf.h \
	ttyio.c ttyio.h \
	asshelp.c asshelp2.c asshelp.h \
	exechelp.h \
	signal.c \
	audit.c audit.h \
	srv.h \
	localename.c \
	session-env.c session-env.h \
	userids.c userids.h \
	openpgp-oid.c \
	ssh-utils.c ssh-utils.h \
	agent-opt.c \
	helpfile.c

if HAVE_W32_SYSTEM
common_sources += w32-reg.c w32-afunix.c w32-afunix.h
endif

# Sources possible requiring a TLS library are put into a separate
# conveince library.
tls_sources = \
	http.c http.h


# To make the code easier to read we have split home some code into
# separate source files.
if HAVE_W32_SYSTEM
if HAVE_W32CE_SYSTEM
common_sources += exechelp-w32ce.c
else
common_sources += exechelp-w32.c
endif
else
common_sources += exechelp-posix.c
endif

# Sources only useful without NPTH.
without_npth_sources = \
        get-passphrase.c get-passphrase.h


libcommon_a_SOURCES = $(common_sources) $(without_npth_sources)
if USE_DNS_SRV
libcommon_a_SOURCES += srv.c
endif
libcommon_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) -DWITHOUT_NPTH=1

libcommonpth_a_SOURCES = $(common_sources)
if USE_DNS_SRV
libcommonpth_a_SOURCES += srv.c
endif
libcommonpth_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS)

libcommontls_a_SOURCES = $(tls_sources)
libcommontls_a_CFLAGS = $(AM_CFLAGS) $(LIBGNUTLS_CFLAGS) -DWITHOUT_NPTH=1

libcommontlsnpth_a_SOURCES = $(tls_sources)
libcommontlsnpth_a_CFLAGS = $(AM_CFLAGS) $(LIBGNUTLS_CFLAGS) $(NPTH_CFLAGS)

if !HAVE_W32CE_SYSTEM
libsimple_pwquery_a_SOURCES = \
	simple-pwquery.c simple-pwquery.h asshelp.c asshelp.h
libsimple_pwquery_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS)
endif

libgpgrl_a_SOURCES = \
        gpgrlhelp.c

if MAINTAINER_MODE
# Note: Due to the dependency on Makefile, the file will always be
# rebuilt, so we allow this only in maintainer mode.

# Create the audit-events.h include file from audit.h
# Note: We create the target file in the source directory because it
# is a distributed built source.  If we would not do that we may end
# up with two files and then it is not clear which version of the
# files will be picked up.
audit-events.h: Makefile.am mkstrtable.awk exaudit.awk audit.h
	$(AWK) -f $(srcdir)/exaudit.awk $(srcdir)/audit.h \
	  | $(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=3 -v nogettext=1 \
		   -v namespace=eventstr_  > $(srcdir)/audit-events.h

# Create the status-codes.h include file from status.h
status-codes.h: Makefile.am mkstrtable.awk exstatus.awk status.h
	$(AWK) -f $(srcdir)/exstatus.awk $(srcdir)/status.h \
	  | $(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=3 -v nogettext=1 \
		   -v namespace=statusstr_  > $(srcdir)/status-codes.h
endif

#
# Module tests
#
module_tests = t-stringhelp t-timestuff \
               t-convert t-percent t-gettime t-sysutils t-sexputil \
	       t-session-env t-openpgp-oid t-ssh-utils \
	       t-mapstrings t-zb32 t-mbox-util
if !HAVE_W32CE_SYSTEM
module_tests += t-exechelp
endif
if HAVE_W32_SYSTEM
module_tests += t-w32-reg
endif

if MAINTAINER_MODE
module_maint_tests = t-helpfile t-b64 t-http
else
module_maint_tests =
endif

t_extra_src = t-support.h

t_common_cflags = $(KSBA_CFLAGS) $(LIBGCRYPT_CFLAGS) \
                  $(LIBASSUAN_CFLAGS) $(GPG_ERROR_CFLAGS)
t_common_ldadd = libcommon.a \
                 $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) \
	         $(LIBINTL) $(LIBICONV)


# Common tests
t_stringhelp_SOURCES = t-stringhelp.c $(t_extra_src)
t_stringhelp_LDADD = $(t_common_ldadd)

t_timestuff_SOURCES = t-timestuff.c $(t_extra_src)
t_timestuff_LDADD = $(t_common_ldadd)

t_convert_LDADD = $(t_common_ldadd)
t_percent_LDADD = $(t_common_ldadd)
t_gettime_LDADD = $(t_common_ldadd)
t_sysutils_LDADD = $(t_common_ldadd)
t_helpfile_LDADD = $(t_common_ldadd)
t_sexputil_LDADD = $(t_common_ldadd)
t_b64_LDADD = $(t_common_ldadd)
t_exechelp_LDADD = $(t_common_ldadd)
t_session_env_LDADD = $(t_common_ldadd)
t_openpgp_oid_LDADD = $(t_common_ldadd)
t_ssh_utils_LDADD = $(t_common_ldadd)
t_mapstrings_LDADD = $(t_common_ldadd)
t_zb32_LDADD = $(t_common_ldadd)
t_mbox_util_LDADD = $(t_common_ldadd)

# System specific test
if HAVE_W32_SYSTEM
t_w32_reg_SOURCES = t-w32-reg.c $(t_extra_src)
t_w32_reg_LDADD   = $(t_common_ldadd)
endif

# http tests
t_http_SOURCES = t-http.c
t_http_CFLAGS  = $(t_common_cflags) $(NTBTLS_CFLAGS) $(LIBGNUTLS_CFLAGS)
t_http_LDADD   = libcommontls.a $(t_common_ldadd) \
	         $(NTBTLS_LIBS) $(LIBGNUTLS_LIBS) $(DNSLIBS)

# All programs should depend on the created libs.
$(PROGRAMS) : libcommon.a libcommonpth.a libcommontls.a libcommontlsnpth.a
