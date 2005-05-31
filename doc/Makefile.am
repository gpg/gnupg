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

EXTRA_DIST = DETAILS gpg.sgml gpg.1 gpgv.sgml gpgv.1 faq.raw FAQ faq.html \
             HACKING OpenPGP README.W32 samplekeys.asc gnupg.7 \
             TRANSLATE gpg.ru.sgml gpg.ru.1 highlights-1.4.txt

man_MANS = gpg.1 gpgv.1 gnupg.7 gpg.ru.1

info_TEXINFOS = gpg.texi gpgv.texi

# Need this to avoid building of dvis with automake 1.4
DVIS =

pkgdata_DATA = FAQ faq.html

BUILT_SOURCES = FAQ faq.html 
# we can't add gpg.texi gpgv.texi here because automake does not like them to
# be built files. 

CLEANFILES = faq.raw.xref gpg.xml gpgv.xml gpg.ru.xml


# We better build the texi versions manually.
#%.texi : %.xml
#if HAVE_DOCBOOK_TO_TEXI
#	 docbook2texi $< | sed 's,--,---,' \
#	    | $(top_srcdir)/scripts/fix-db-texi $@  >$@
#else
#	 : Warning: missing docbook to texinfo tools, cannot make $@
#	 touch $@
#endif
#
#%.xml : %.sgml
#if HAVE_DOCBOOK_TO_TEXI
#	 sgml2xml -x lower $< >$@
#else
#	 : Warning: missing docbook to texinfo tools, cannot make $@
#	 touch $@
#endif
#

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
