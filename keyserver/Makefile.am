# Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_srcdir)/include
EXTRA_PROGRAMS = gpgkeys_ldap gpgkeys_hkp
EXTRA_SCRIPTS = gpgkeys_mailto
libexecdir = @GNUPG_LIBEXECDIR@

# We don't need the libs the regular GPG binaries do
LIBS=

libexec_PROGRAMS = @GPGKEYS_LDAP@ @GPGKEYS_HKP@
libexec_SCRIPTS = @GPGKEYS_MAILTO@
noinst_SCRIPTS = gpgkeys_test

# don't distribute hkp for now
nodist_gpgkeys_hkp_SOURCES = gpgkeys_hkp.c

gpgkeys_ldap_LDADD = @LDAPLIBS@ @NETLIBS@
gpgkeys_hkp_LDADD = @NETLIBS@
