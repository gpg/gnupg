# Makefile.am - main makefile for NewPG/GnuPG
#     	Copyright (C) 2001, 2004 Free Software Foundation, Inc.
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

ACLOCAL_AMFLAGS = -I m4 -I gl/m4
AUTOMAKE_OPTIONS = dist-bzip2 no-dist-gzip
DISTCHECK_CONFIGURE_FLAGS = --enable-symcryptrun --enable-mailto --enable-gpgtar

EXTRA_DIST = scripts/config.rpath autogen.sh README.SVN
DISTCLEANFILES = g10defs.h 

if BUILD_GPGSM
kbx = kbx
else
kbx =
endif


if BUILD_GPG
gpg = g10
keyserver = keyserver
else
gpg =
keyserver = 
endif
if BUILD_GPGSM
sm = sm
else
sm =
endif
if BUILD_AGENT
agent = agent
else
agent =
endif
if BUILD_SCDAEMON
scd = scd
else
scd =
endif
if BUILD_TOOLS
tools = tools
else
tools =
endif
if BUILD_DOC
doc = doc
else
doc =
endif

if HAVE_W32_SYSTEM
tests =
else
tests = tests
endif

SUBDIRS = m4 gl include jnlib common ${kbx} \
 ${gpg} ${keyserver} ${sm} ${agent} ${scd} ${tools} po ${doc} ${tests}

dist_doc_DATA = README


dist-hook:
	echo "$(VERSION)" > $(distdir)/VERSION

stowinstall: 
	$(MAKE) $(AM_MAKEFLAGS) install prefix=/usr/local/stow/gnupg


