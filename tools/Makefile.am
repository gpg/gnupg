# Makefile.am - Tools directory
#     	Copyright (C) 2003 Free Software Foundation, Inc.
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

EXTRA_DIST = Manifest watchgnupg.c \
             rfc822parse.c rfc822parse.h gpgparsemail.c \
	     addgnupghome gpgsm-gencert.sh

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/intl -I$(top_srcdir)/common
include $(top_srcdir)/am/cmacros.am

AM_CFLAGS = $(GPG_ERROR_CFLAGS) $(LIBASSUAN_CFLAGS)

sbin_SCRIPTS = addgnupghome

bin_SCRIPTS = gpgsm-gencert.sh

if BUILD_SYMCRYPTRUN
  symcryptrun = symcryptrun
else
  symcryptrun =
endif

bin_PROGRAMS = gpgconf gpg-connect-agent gpgkey2ssh ${symcryptrun}
if !HAVE_W32_SYSTEM
bin_PROGRAMS += watchgnupg
endif

gpgconf_SOURCES = gpgconf.c gpgconf.h gpgconf-comp.c no-libgcrypt.c

gpgconf_LDADD = ../gl/libgnu.a ../jnlib/libjnlib.a \
                ../common/libcommon.a @LIBINTL@

symcryptrun_SOURCES = symcryptrun.c
symcryptrun_LDADD = $(LIBUTIL_LIBS) ../gl/libgnu.a ../jnlib/libjnlib.a \
                    ../common/libcommon.a \
		    ../common/libsimple-pwquery.a $(LIBGCRYPT_LIBS) \
		    $(GPG_ERROR_LIBS) $(LIBINTL)

watchgnupg_SOURCES = watchgnupg.c 

gpg_connect_agent_SOURCES = gpg-connect-agent.c no-libgcrypt.c
gpg_connect_agent_LDADD = ../gl/libgnu.a ../jnlib/libjnlib.a \
                          ../common/libcommon.a \
                          $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) $(LIBINTL)

gpgkey2ssh_SOURCES = gpgkey2ssh.c
gpgkey2ssh_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)
gpgkey2ssh_LDADD = ../gl/libgnu.a ../common/libcommon.a \
                   $(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS)
