# Makefile.am - tests using NIST's PKITS
#     	Copyright (C) 2004 Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

## Process this file with automake to produce Makefile.in

GPGSM = ../../sm/gpgsm

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



testscripts = import-all-certs validate-all-certs



EXTRA_DIST = PKITS_data.tar.bz2 inittests runtest $(testscripts) 
	     import-all-certs.data 

TESTS = $(testscripts)

CLEANFILES = inittests.stamp x y y z out err  *.lock .\#lk* *.log

DISTCLEANFILES = pubring.kbx~ random_seed

all-local: inittests.stamp

clean-local:
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests --clean

inittests.stamp: inittests
	srcdir=$(srcdir) $(TESTS_ENVIRONMENT) $(srcdir)/inittests
	echo timestamp >./inittests.stamp

