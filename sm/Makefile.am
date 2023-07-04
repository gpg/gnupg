# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

EXTRA_DIST = ChangeLog-2011 \
             gpgsm-w32info.rc gpgsm.w32-manifest.in

bin_PROGRAMS = gpgsm
noinst_PROGRAMS = $(module_tests) $(module_maint_tests)

if DISABLE_TESTS
TESTS =
else
TESTS = $(module_tests)
endif

AM_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS) $(LIBASSUAN_CFLAGS) \
            $(NPTH_CFLAGS) $(GPG_ERROR_CFLAGS)

AM_CPPFLAGS = -DKEYBOX_WITH_X509=1
include $(top_srcdir)/am/cmacros.am

if HAVE_W32_SYSTEM
resource_objs += gpgsm-w32info.o
gpgsm-w32info.o : gpgsm.w32-manifest ../common/w32info-rc.h
endif

gpgsm_SOURCES = \
	gpgsm.c	gpgsm.h \
	misc.c \
	keydb.c keydb.h \
	server.c \
	call-agent.c \
	call-dirmngr.c \
	fingerprint.c \
	certlist.c \
	certdump.c \
	certcheck.c \
	certchain.c \
	keylist.c \
	verify.c \
	sign.c \
	encrypt.c \
	decrypt.c \
	import.c \
	export.c \
	delete.c \
	certreqgen.c \
	certreqgen-ui.c \
	minip12.c minip12.h \
	qualified.c \
	passphrase.c passphrase.h


common_libs = ../kbx/libkeybox509.a $(libcommonpth)

gpgsm_LDADD = $(common_libs) ../common/libgpgrl.a \
              $(LIBGCRYPT_LIBS) $(KSBA_LIBS) $(LIBASSUAN_LIBS) \
              $(NPTH_LIBS) $(GPG_ERROR_LIBS) $(LIBREADLINE) $(LIBINTL) \
	      $(LIBICONV) $(resource_objs) $(NETLIBS)
gpgsm_LDFLAGS =
gpgsm_DEPENDENCIES = $(resource_objs)


module_tests = t-minip12
module_maint_tests =

t_common_src =
t_common_ldadd = $(libcommon) $(LIBGCRYPT_LIBS) $(KSBA_LIBS) \
                 $(GPG_ERROR_LIBS) $(LIBINTL) $(LIBICONV)


t_minip12_CFLAGS = -DWITHOUT_NPTH=1 \
	           $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS) $(GPG_ERROR_CFLAGS)
t_minip12_SOURCES = $(t_common_src) t-minip12.c minip12.c
t_minip12_LDADD   = $(t_common_ldadd) $(NETLIBS)



# Make sure that all libs are build before we use them.  This is
# important for things like make -j2.
$(PROGRAMS): $(common_libs)
