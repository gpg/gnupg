# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
libexecdir = @libexecdir@/@PACKAGE@

libexec_PROGRAMS = @GPGKEYS_LDAP@ @GPGKEYS_HKP@
libexec_SCRIPTS = @GPGKEYS_MAILTO@
noinst_SCRIPTS = gpgkeys_test

gpgkeys_ldap_LDADD = @LDAPLIBS@ @NETLIBS@ @GETOPT@ @W32LIBS@
gpgkeys_hkp_LDADD = ../util/libutil.a @NETLIBS@ @INTLLIBS@ @CAPLIBS@ @GETOPT@ @W32LIBS@
