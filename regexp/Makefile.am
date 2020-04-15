# Makefile for common gnupg modules
# Copyright (C) 2020 g10 Code GmbH
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

## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libregexp.a

AM_CPPFLAGS = -DJIM_REGEXP -DJIM_UTF8 -DUSE_UTF8

AM_CFLAGS =

libregexp_a_SOURCES = jimregexp.h utf8.h jimregexp.c utf8.c
libregexp_a_CFLAGS = $(AM_CFLAGS)

EXTRA_DIST = parse-unidata.awk UnicodeData.txt _unicode_mapping.c

if MAINTAINER_MODE
BUILT_SOURCES = _unicode_mapping.c
MAINTAINERCLEANFILES = _unicode_mapping.c

_unicode_mapping.c: parse-unidata.awk UnicodeData.txt
	$(AWK) $(AWK_HEX_NUMBER_OPTION) -f $(srcdir)/parse-unidata.awk \
	       $(srcdir)/UnicodeData.txt >$@
endif
