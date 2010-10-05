# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
## Process this file with automake to create Makefile.in

EXTRA_DIST = DETAILS FAQ \
             HACKING OpenPGP README.W32 samplekeys.asc gnupg.7 \
             TRANSLATE gpg.ru.sgml gpg.ru.1 highlights-1.4.txt \
             gpg.texi gpgv.texi specify-user-id.texi see-also-note.texi \
	     opt-homedir.texi texi.css yat2m.c gpl.texi gpg-zip.1


myman_sources = gpg.texi gpgv.texi
myman_pages   = gpg.1 gpgv.1


sources_from_trunk = $(myman_sources) \
                     opt-homedir.texi specify-user-id.texi see-also-note.texi

info_TEXINFOS = gnupg1.texi

man_MANS = $(myman_pages) gnupg.7 gpg.ru.1 gpg-zip.1

gnupg1_TEXINFOS = gnupg1.texi

# Need this to avoid building of dvis with automake 1.4
DVIS =

pkgdata_DATA = FAQ

# we can't add gpg.texi gpgv.texi here because automake does not like them to
# be built files. 

CLEANFILES = gpg.xml gpgv.xml gpg.ru.xml 
DISTCLEANFILES = yat2m yat2m-stamp.tmp yat2m-stamp $(myman_pages)

AM_MAKEINFOFLAGS = -I $(srcdir) --css-include=$(srcdir)/texi.css -D gpgone

YAT2M_OPTIONS = -I $(srcdir) -D gpgone \
        --release "GnuPG @PACKAGE_VERSION@" --source "GNU Privacy Guard"

yat2m: Makefile yat2m.c
	$(CC_FOR_BUILD) -o $@ $(srcdir)/yat2m.c

yat2m-stamp: $(myman_sources)
	@rm -f yat2m-stamp.tmp
	@touch yat2m-stamp.tmp
	for file in $(myman_sources) ; do \
              ./yat2m $(YAT2M_OPTIONS) --store \
	          `test -f '$$file' || echo '$(srcdir)/'`$$file ; done
	@mv -f yat2m-stamp.tmp $@

yat2m-stamp: yat2m

$(myman_pages) : yat2m-stamp
	@if test -f $@; then :; else \
            trap 'rm -rf yat2m-stamp yat2m-lock' 1 2 13 15; \
               if mkdir yat2m-lock 2>/dev/null; then \
                 rm -f yat2m-stamp; \
                 $(MAKE) $(AM_MAKEFLAGS) yat2m-stamp; \
                 rmdir yat2m-lock; \
               else \
                 while test -d yat2m-lock; do sleep 1; done; \
                 test -f yat2m-stamp; exit $$?; \
               fi; \
             fi


.sgml.1:
if HAVE_DOCBOOK_TO_MAN
	docbook-to-man $<  >$@
else
	: Warning: missing docbook-to-man, cannot make $@
	echo ".TH $< 1"   >$@
	echo "No man page due to missing docbook-to-man" >>$@
endif

dist-hook:
	@if test "`wc -c < gpg.1`" -lt 200; then \
	    echo 'ERROR: dummy man page'; false; fi

# Helper to update some source files.
update-source-from-gnupg-2:
	@set -e; \
	 if test -d ../../gnupg/scd; then dir="../../gnupg"; \
	 else exit 1; \
	 fi; \
	 for i in $(sources_from_trunk); do \
           cp $$dir/doc/$$i $$i; echo $$i; \
	 done ;\
	 echo "Please remember to update the ChangeLog!"
