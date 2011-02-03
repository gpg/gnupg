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

EXTRA_DIST = mkstrtable.awk exaudit.awk exstatus.awk \
             audit-events.h status-codes.h README.jnlib ChangeLog.jnlib

noinst_LIBRARIES = libcommon.a libcommonpth.a libgpgrl.a
if !HAVE_W32CE_SYSTEM
noinst_LIBRARIES += libsimple-pwquery.a
endif
noinst_PROGRAMS = $(jnlib_tests) $(module_tests) $(module_maint_tests)
TESTS = $(jnlib_tests) $(module_tests)

BUILT_SOURCES = audit-events.h status-codes.h

CLEANFILES = audit-events.h status-codes.h

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(KSBA_CFLAGS)

include $(top_srcdir)/am/cmacros.am

jnlib_sources = \
	libjnlib-config.h \
	types.h dynload.h w32help.h \
	stringhelp.c stringhelp.h \
	strlist.c strlist.h \
	utf8conv.c utf8conv.h \
	argparse.c argparse.h \
	logging.c logging.h  \
	dotlock.c dotlock.h  \
        mischelp.c mischelp.h

if HAVE_W32_SYSTEM
jnlib_sources += w32-reg.c w32-afunix.c w32-afunix.h
endif


common_sources = \
	common-defs.h \
	util.h i18n.c i18n.h \
	estream.c estream.h estream-printf.c estream-printf.h \
	status.c status.h\
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
	b64enc.c b64dec.c \
	convert.c \
	percent.c \
	miscellaneous.c \
	xasprintf.c \
	xreadline.c \
	membuf.c membuf.h \
	iobuf.c iobuf.h \
	ttyio.c ttyio.h \
	asshelp.c asshelp.h \
	exechelp.h \
	signal.c \
	audit.c audit.h \
	srv.h \
	dns-cert.c dns-cert.h \
	pka.c pka.h \
	http.c http.h \
	localename.c \
	session-env.c session-env.h \
	userids.c userids.h \
	openpgp-oid.c \
	helpfile.c

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

# Sources only useful without PTH.
without_pth_sources = \
        get-passphrase.c get-passphrase.h


libcommon_a_SOURCES = $(jnlib_sources) $(common_sources) $(without_pth_sources)
if USE_DNS_SRV
libcommon_a_SOURCES += srv.c
endif
libcommon_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) -DWITHOUT_GNU_PTH=1

libcommonpth_a_SOURCES = $(jnlib_sources) $(common_sources)
if USE_DNS_SRV
libcommonpth_a_SOURCES += srv.c
endif
libcommonpth_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)

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
t_jnlib_src = t-support.c t-support.h 
jnlib_tests = t-stringhelp t-timestuff
if HAVE_W32_SYSTEM
jnlib_tests += t-w32-reg
endif
module_tests = t-convert t-percent t-gettime t-sysutils t-sexputil \
	       t-session-env t-openpgp-oid
if !HAVE_W32CE_SYSTEM
module_tests += t-exechelp
endif
module_maint_tests = t-helpfile t-b64


t_common_ldadd = libcommon.a ../gl/libgnu.a \
                 $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)

# jnlib tests
t_stringhelp_SOURCES = t-stringhelp.c $(t_jnlib_src)
t_stringhelp_LDADD = $(t_common_ldadd)

t_timestuff_SOURCES = t-timestuff.c $(t_jnlib_src)
t_timestuff_LDADD = $(t_common_ldadd)

if HAVE_W32_SYSTEM
t_w32_reg_SOURCES = t-w32-reg.c $(t_jnlib_src)
t_w32_reg_LDADD   = $(t_common_ldadd)
endif

# common tests
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




