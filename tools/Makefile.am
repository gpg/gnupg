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

EXTRA_DIST = Manifest watchgnupg.c addgnupghome

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

# Note, that we require GPG_ERROR_CFLAGS only because some share header files
# require that file.  It is not actually used in gpgconf.
AM_CFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/intl @GPG_ERROR_CFLAGS@

bin_PROGRAMS = gpgconf

gpgconf_SOURCES = gpgconf.c gpgconf.h gpgconf-comp.c no-libgcrypt.c

gpgconf_LDADD = ../jnlib/libjnlib.a ../common/libcommon.a @INTLLIBS@

