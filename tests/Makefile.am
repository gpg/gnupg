# Makefile.am -tests makefile for libxtime
#     	Copyright (C) 2002 Free Software Foundation, Inc.
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

GPGSM = ../sm/gpgsm

TESTS_ENVIRONMENT = GNUPGHOME=`pwd` GPG_AGENT_INFO= LC_ALL=C GPGSM=$(GPGSM) \
		    LD_LIBRARY_PATH=$$(seen=0; \
                           for i in $(LDFLAGS) $(LIBGCRYPT_LIBS) $(PTH_LIBS); \
                           do \
                             if echo "$$i" | egrep '^-L' >/dev/null 2>&1; \
                             then \
                               if test $$seen = 0; \
                               then \
                                 seen=1; \
                               else \
                                 printf ":"; \
                               fi; \
                               printf "%s" "$${i}" | sed 's/^-L//'; \
                             fi; \
                           done; \
                           if test $$seen != 0 \
                              && test x$${LD_LIBRARY_PATH} != x; \
                           then \
                             printf ":"; \
                           fi; \
                           printf "%s" "$${LD_LIBRARY_PATH}") $(srcdir)/runtest

testscripts = sm-sign+verify sm-verify

EXTRA_DIST = runtest inittests $(testscripts) \
	     text-1.txt text-2.txt text-3.txt \
	     text-1.osig.pem text-1.dsig.pem text-1.osig-bad.pem \
	     text-2.osig.pem text-2.osig-bad.pem \
             samplekeys/32100C27173EF6E9C4E9A25D3D69F86D37A4F939.key \
             samplekeys/cert_g10code_pete1.pem \
             samplekeys/cert_g10code_test1.pem \
             samplekeys/cert_g10code_theo1.pem

TESTS = $(testscripts)

CLEANFILES = inittests.stamp x y y z out err 
	     *.lock .\#lk* 

DISTCLEANFILES = pubring.kbx~ random_seed

noinst_PROGRAMS = asschk

asschk_SOURCES = asschk.c


all-local: inittests.stamp

clean-local:
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp

