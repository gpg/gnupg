# Makefile for common gnupg modules
# Copyright (C) 2001, 2003, 2007 Free Software Foundation, Inc.
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
             audit-events.h status-codes.h ChangeLog-2011 \
	     w32info-rc.h.in gnupg.ico

noinst_LIBRARIES = libcommon.a libcommonpth.a libsimple-pwquery.a libgpgrl.a
noinst_PROGRAMS = $(module_tests) $(module_maint_tests)
TESTS = $(module_tests)

BUILT_SOURCES = audit-events.h status-codes.h

MAINTAINERCLEANFILES = audit-events.h status-codes.h

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS)

include $(top_srcdir)/am/cmacros.am

common_sources = \
	common-defs.h \
	util.h i18n.c i18n.h \
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
	gettime.c \
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
	exechelp.c exechelp.h \
	signal.c \
	estream.c estream.h estream-printf.c estream-printf.h \
	audit.c audit.h \
	srv.h \
	dns-cert.c dns-cert.h \
	pka.c pka.h \
	http.c http.h \
	localename.c \
	session-env.c session-env.h \
	ssh-utils.c ssh-utils.h \
	helpfile.c

# Sources only useful without PTH.
without_pth_sources = \
        get-passphrase.c get-passphrase.h


libcommon_a_SOURCES = $(common_sources) $(without_pth_sources)
if USE_DNS_SRV
libcommon_a_SOURCES += srv.c
endif
libcommon_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) -DWITHOUT_GNU_PTH=1

libcommonpth_a_SOURCES = $(common_sources)
if USE_DNS_SRV
libcommonpth_a_SOURCES += srv.c
endif
libcommonpth_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS) $(PTH_CFLAGS)

libsimple_pwquery_a_SOURCES = \
	simple-pwquery.c simple-pwquery.h asshelp.c asshelp.h
libsimple_pwquery_a_CFLAGS = $(AM_CFLAGS) $(LIBASSUAN_CFLAGS)

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
audit-events.h: Makefile mkstrtable.awk exaudit.awk audit.h
	$(AWK) -f $(srcdir)/exaudit.awk $(srcdir)/audit.h \
	  | $(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=3 -v nogettext=1 \
		   -v namespace=eventstr_  > $(srcdir)/audit-events.h

# Create the status-codes.h include file from status.h
status-codes.h: Makefile mkstrtable.awk exstatus.awk status.h
	$(AWK) -f $(srcdir)/exstatus.awk $(srcdir)/status.h \
	  | $(AWK) -f $(srcdir)/mkstrtable.awk -v textidx=3 -v nogettext=1 \
		   -v namespace=statusstr_  > $(srcdir)/status-codes.h

endif


#
# Module tests
#
module_tests = t-convert t-percent t-gettime t-sysutils t-sexputil t-exechelp \
	       t-session-env t-ssh-utils
module_maint_tests = t-helpfile t-b64

t_common_ldadd = libcommon.a ../jnlib/libjnlib.a ../gl/libgnu.a \
                 $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)

t_convert_LDADD = $(t_common_ldadd)
t_percent_LDADD = $(t_common_ldadd)
t_gettime_LDADD = $(t_common_ldadd)
t_sysutils_LDADD = $(t_common_ldadd)
t_helpfile_LDADD = $(t_common_ldadd)
t_sexputil_LDADD = $(t_common_ldadd)
t_b64_LDADD = $(t_common_ldadd)
t_exechelp_LDADD = $(t_common_ldadd)
t_session_env_LDADD = $(t_common_ldadd)
t_ssh_utils_LDADD = $(t_common_ldadd)
