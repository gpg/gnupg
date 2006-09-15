# Copyright (C) 2002, 2004 Free Software Foundation, Inc.
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

examples = examples/README examples/scd-event examples/trustlist.txt

EXTRA_DIST = DETAILS HACKING TRANSLATE OpenPGP KEYSERVER samplekeys.asc \
	     gnupg-badge-openpgp.eps gnupg-badge-openpgp.jpg \
             gnupg-badge-openpgp.pdf \
             gnupg-card-architecture.eps gnupg-card-architecture.png \
             gnupg-card-architecture.pdf \
             faq.raw FAQ faq.html gnupg7.texi \
             opt-homedir.texi see-also-note.texi specify-user-id.texi \
	     $(examples)

BUILT_SOURCES = gnupg-card-architecture.eps gnupg-card-architecture.png \
                gnupg-card-architecture.pdf FAQ faq.html

noinst_PROGRAMS = yat2m

info_TEXINFOS = gnupg.texi

dist_pkgdata_DATA = qualified.txt FAQ faq.html

gnupg_TEXINFOS = \
	gpg.texi gpgsm.texi gpg-agent.texi scdaemon.texi assuan.texi \
	tools.texi debugging.texi glossary.texi contrib.texi gpl.texi \
	sysnotes.texi gnupg-card-architecture.fig

AM_MAKEFINFOFLAGS = -I $(srcdir)

YAT2M_OPTIONS = -I $(srcdir) \
        --release "GnuPG @PACKAGE_VERSION@" --source "GNU Privacy Guard"

myman_sources = gnupg7.texi gpg.texi gpgsm.texi gpg-agent.texi \
                scdaemon.texi tools.texi
myman_pages   = gnupg.7 gpg2.1 gpgsm.1 gpg-agent.1 scdaemon.1 gpgv2.1 \
                watchgnupg.1 gpgconf.1 addgnupghome.8 gpg-preset-passphrase.1 \
		gpg-connect-agent.1 gpgparsemail.1 symcryptrun.1 \
		gpgsm-gencert.sh.1

man_MANS = $(myman_pages)


watchgnupg_SOURCE = gnupg.texi


CLEANFILES = faq.raw.xref

DISTCLEANFILES = gnupg.tmp gnupg.ops yat2m-stamp.tmp yat2m-stamp \
		 $(myman_pages)

yat2m_SOURCES = yat2m.c


.fig.png:
	fig2dev -L png `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.jpg:
	fig2dev -L jpg `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.eps:
	fig2dev -L eps `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.pdf:
	fig2dev -L pdf `test -f '$<' || echo '$(srcdir)/'`$< $@


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

