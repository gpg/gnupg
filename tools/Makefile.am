# Makefile.am - Tools directory
#     	Copyright (C) 2003, 2007 Free Software Foundation, Inc.
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

EXTRA_DIST = \
	Manifest watchgnupg.c no-libgcrypt.c \
	addgnupghome applygnupgdefaults \
	lspgpot mail-signed-keys convert-from-106 sockprox.c \
	ccidmon.c ChangeLog-2011 \
	gpgconf-w32info.rc           gpgconf.w32-manifest.in \
	gpgtar-w32info.rc            gpgtar.w32-manifest.in \
        gpg-connect-agent-w32info.rc gpg-connect-agent.w32-manifest.in \
	gpg-check-pattern-w32info.rc gpg-check-pattern.w32-manifest.in \
	gpg-wks-client-w32info.rc    gpg-wks-client.w32-manifest.in


AM_CPPFLAGS =
include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
gpgconf_rc_objs =           $(resource_objs) gpgconf-w32info.o
gpgtar_rc_objs =            $(resource_objs) gpgtar-w32info.o
gpg_connect_agent_rc_objs = $(resource_objs) gpg-connect-agent-w32info.o
gpg_check_pattern_rc_objs = $(resource_objs) gpg-check-pattern-w32info.o
gpg_wks_client_rc_objs =    $(resource_objs) gpg-wks-client-w32info.o

gpg-connect-agent-w32info.o  : gpg-connect-agent.w32-manifest \
                                                     ../common/w32info-rc.h
gpgconf-w32info.o            : gpgconf.w32-manifest  ../common/w32info-rc.h
gpgtar-w32info.o             : gpgtar.w32-manifest   ../common/w32info-rc.h
gpg-check-pattern-w32info.o  : gpg-check-pattern.w32-manifest \
                                                     ../common/w32info-rc.h
gpg-wks-client-w32info.o     : gpg-wks-client.w32-manifest \
                                                     ../common/w32info-rc.h
endif

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS) $(LIBASSUAN_CFLAGS)

sbin_SCRIPTS = addgnupghome applygnupgdefaults

if HAVE_USTAR
# bin_SCRIPTS += gpg-zip
noinst_SCRIPTS = gpg-zip
endif

if BUILD_WKS_TOOLS
  gpg_wks_server = gpg-wks-server
else
  gpg_wks_server =
endif

libexec_PROGRAMS = gpg-wks-client

bin_PROGRAMS = gpgconf gpg-connect-agent
if !HAVE_W32_SYSTEM
bin_PROGRAMS += watchgnupg gpgparsemail ${gpg_wks_server} gpgsplit
else
bin_PROGRAMS += gpgconf-w32
endif

libexec_PROGRAMS += gpg-check-pattern

if !HAVE_W32CE_SYSTEM
noinst_PROGRAMS = clean-sat make-dns-cert
endif

if !HAVE_W32CE_SYSTEM
if BUILD_GPGTAR
  bin_PROGRAMS += gpgtar
else
  noinst_PROGRAMS += gpgtar
endif
endif

common_libs = $(libcommon)
commonpth_libs = $(libcommonpth)

# Some modules require PTH under W32CE.
if HAVE_W32CE_SYSTEM
maybe_commonpth_libs = $(commonpth_libs)
else
maybe_commonpth_libs = $(common_libs)
endif

if HAVE_W32CE_SYSTEM
pwquery_libs =
else
pwquery_libs = ../common/libsimple-pwquery.a
endif

if HAVE_W32CE_SYSTEM
opt_libassuan_libs = $(LIBASSUAN_LIBS)
endif

regexp_libs = ../regexp/libregexp.a


gpgsplit_LDADD = $(common_libs) \
	         $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
		 $(ZLIBS) $(LIBINTL) $(NETLIBS) $(LIBICONV)

gpgconf_SOURCES = gpgconf.c gpgconf.h gpgconf-comp.c

# common sucks in gpg-error, will they, nil they (some compilers
# do not eliminate the supposed-to-be-unused-inline-functions).
gpgconf_LDADD = $(maybe_commonpth_libs) $(opt_libassuan_libs) \
                $(LIBINTL) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) $(NETLIBS) \
	        $(LIBICONV) $(W32SOCKLIBS) \
	        $(gpgconf_rc_objs)
gpgconf_LDFLAGS = $(extra_bin_ldflags)

gpgconf_w32_SOURCES = $(gpgconf_SOURCES)
gpgconf_w32_LDADD = $(gpgconf_LDADD)
gpgconf_w32_LDFLAGS = $(gpgconf_LDFLAGS) -Wl,-subsystem,windows

gpgparsemail_SOURCES = gpgparsemail.c rfc822parse.c rfc822parse.h
gpgparsemail_LDADD =

watchgnupg_SOURCES = watchgnupg.c
watchgnupg_LDADD = $(NETLIBS)

gpg_connect_agent_SOURCES = gpg-connect-agent.c
gpg_connect_agent_LDADD = ../common/libgpgrl.a $(common_libs) \
	                  $(LIBASSUAN_LIBS) $(LIBGCRYPT_LIBS) \
                          $(GPG_ERROR_LIBS) \
                          $(LIBREADLINE) $(LIBINTL) $(NETLIBS) $(LIBICONV) \
                          $(gpg_connect_agent_rc_objs)

gpg_check_pattern_SOURCES = gpg-check-pattern.c
gpg_check_pattern_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS) $(INCICONV)
gpg_check_pattern_LDADD = $(common_libs) $(regexp_libs) $(LIBGCRYPT_LIBS) \
			  $(GPG_ERROR_LIBS) \
			  $(LIBINTL) $(NETLIBS) $(LIBICONV) $(W32SOCKLIBS) \
			  $(LIBICONV) $(gpg_check_pattern_rc_objs)

gpgtar_SOURCES = \
	gpgtar.c gpgtar.h \
	gpgtar-create.c \
	gpgtar-extract.c \
	gpgtar-list.c
gpgtar_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)
gpgtar_LDADD = $(libcommon) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
               $(LIBINTL) $(NETLIBS) $(LIBICONV) $(W32SOCKLIBS) \
	       $(gpgtar_rc_objs)

gpg_wks_server_SOURCES = \
	gpg-wks-server.c \
	gpg-wks.h \
	wks-util.c \
	wks-receive.c \
	rfc822parse.c rfc822parse.h \
	mime-parser.c mime-parser.h \
	mime-maker.c  mime-maker.h  \
	send-mail.c   send-mail.h

gpg_wks_server_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS) $(INCICONV)
gpg_wks_server_LDADD = $(libcommon) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
		       $(LIBINTL) $(LIBICONV)

gpg_wks_client_SOURCES = \
	gpg-wks-client.c \
	gpg-wks.h  \
	wks-util.c \
	wks-receive.c \
	rfc822parse.c rfc822parse.h \
	mime-parser.c mime-parser.h \
	mime-maker.h  mime-maker.c  \
	send-mail.c   send-mail.h   \
	call-dirmngr.c call-dirmngr.h

gpg_wks_client_CFLAGS = $(LIBASSUAN_CFLAGS) $(LIBGCRYPT_CFLAGS) \
			$(GPG_ERROR_CFLAGS) $(INCICONV)
gpg_wks_client_LDADD = $(libcommon) \
		       $(LIBASSUAN_LIBS) $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) \
		       $(LIBINTL) $(LIBICONV) $(NETLIBS) \
		       $(gpg_wks_client_rc_objs)


# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs) $(pwquery_libs) ../common/libgpgrl.a
