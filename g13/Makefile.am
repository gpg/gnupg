# g13/Makefile.am
# Copyright (C) 2009 Free Software Foundation, Inc.
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

EXTRA_DIST = ChangeLog-2011 all-tests.scm

bin_PROGRAMS = g13
sbin_PROGRAMS = g13-syshelp

noinst_PROGRAMS = $(module_tests)
if DISABLE_TESTS
TESTS =
else
TESTS = $(module_tests)
endif

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =  $(LIBGCRYPT_CFLAGS) $(LIBASSUAN_CFLAGS) $(NPTH_CFLAGS)

g13_SOURCES = \
	g13.c g13.h \
	g13-common.c g13-common.h \
	keyblob.c keyblob.h \
	g13tuple.c g13tuple.h \
	server.c server.h \
	create.c create.h \
	mount.c mount.h \
	suspend.c suspend.h \
	mountinfo.c mountinfo.h \
	call-syshelp.c call-syshelp.h \
	runner.c runner.h \
	backend.c backend.h \
	be-encfs.c be-encfs.h \
	be-truecrypt.c be-truecrypt.h \
	be-dmcrypt.c be-dmcrypt.h

g13_LDADD = $(libcommonpth) \
	$(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) $(NPTH_LIBS) \
	$(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)


g13_syshelp_SOURCES = \
	g13-syshelp.c g13-syshelp.h \
	g13-common.c g13-common.h \
	keyblob.c keyblob.h \
	g13tuple.c g13tuple.h \
	sh-cmd.c \
	sh-blockdev.c \
	sh-dmcrypt.c

g13_syshelp_LDADD = $(libcommon) \
	$(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) \
	$(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)


module_tests = t-g13tuple
t_common_ldadd = $(libcommon) $(LIBGCRYPT_LIBS) \
	         $(LIBASSUAN_LIBS) $(GPG_ERROR_LIBS) $(LIBICONV)

t_g13tuple_SOURCES = t-g13tuple.c g13tuple.c
t_g13tuple_LDADD = $(t_common_ldadd)


$(PROGRAMS) : $(libcommon) $(libcommonpth)
