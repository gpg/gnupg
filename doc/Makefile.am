# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = no-texinfo.tex

EXTRA_DIST = DETAILS gpg.1 gpgv.1 faq.raw FAQ faq.html \
             HACKING OpenPGP README.W32 samplekeys.asc gnupg.7 \
             TRANSLATE gpg.ru.sgml gpg.ru.1 highlights-1.4.txt

noinst_PROGRAMS = yat2m

myman_sources = gpg.texi 
myman_pages   = gpg.1 

info_TEXINFOS = gpg.texi

man_MANS = $(myman_pages) gnupg.7 gpg.ru.1


# Need this to avoid building of dvis with automake 1.4
DVIS =

pkgdata_DATA = FAQ faq.html

BUILT_SOURCES = FAQ faq.html 
# we can't add gpg.texi gpgv.texi here because automake does not like them to
# be built files. 

CLEANFILES = faq.raw.xref gpg.xml gpgv.xml gpg.ru.xml
DISTCLEANFILES = yat2m-stamp.tmp yat2m-stamp $(myman_pages)

YAT2M_OPTIONS = -I $(srcdir) -D gpgone \
        --release "GnuPG @PACKAGE_VERSION@" --source "GNU Privacy Guard"

yat2m_SOURCES = yat2m.c

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


%.1 : %.sgml
if HAVE_DOCBOOK_TO_MAN
	docbook-to-man $<  >$@
else
	: Warning: missing docbook-to-man, cannot make $@
	echo ".TH $< 1"   >$@
	echo "No man page due to missing docbook-to-man" >>$@
endif

FAQ : faq.raw
if WORKING_FAQPROG
	$(FAQPROG) -f $<  $@ || $(FAQPROG) -f $< $@
else
	: Warning: missing faqprog.pl, cannot make $@
	echo "No $@ due to missing faqprog.pl" > $@
	echo "See ftp://ftp.gnupg.org/gcrypt/contrib/faqprog.pl" >> $@
endif

faq.html : faq.raw
if WORKING_FAQPROG
	$(FAQPROG) -h -f $< $@ 2>&1 || $(FAQPROG) -h -f $< $@
else
	: Warning: missing faqprog.pl, cannot make $@
	echo "No $@ due to missing faqprog.pl" > $@
	echo "See ftp://ftp.gnupg.org/gcrypt/contrib/faqprog.pl" >> $@
endif

dist-hook:
	@if test "`wc -c < gpg.1`" -lt 200; then \
	    echo 'ERROR: dummy man page'; false; fi
