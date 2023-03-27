# Copyright (C) 2002, 2004 Free Software Foundation, Inc.
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

AM_CPPFLAGS =

include $(top_srcdir)/am/cmacros.am

examples = examples/README examples/scd-event examples/trustlist.txt	\
	   examples/Automatic.prf                                       \
           examples/debug.prf                                           \
           examples/gpgconf.rnames examples/gpgconf.conf                \
	   examples/systemd-user/README 				\
	   examples/systemd-user/dirmngr.service 			\
	   examples/systemd-user/dirmngr.socket				\
	   examples/systemd-user/gpg-agent.service 			\
	   examples/systemd-user/gpg-agent.socket 			\
	   examples/systemd-user/gpg-agent-ssh.socket 			\
	   examples/systemd-user/gpg-agent-browser.socket		\
	   examples/systemd-user/gpg-agent-extra.socket 		\
	   examples/pwpattern.list

helpfiles = help.txt help.be.txt help.ca.txt help.cs.txt		\
            help.da.txt help.de.txt help.el.txt help.eo.txt		\
            help.es.txt help.et.txt help.fi.txt help.fr.txt		\
            help.gl.txt help.hu.txt help.id.txt help.it.txt		\
            help.ja.txt help.nb.txt help.pl.txt help.pt.txt		\
            help.pt_BR.txt help.ro.txt help.ru.txt help.sk.txt		\
            help.sv.txt help.tr.txt help.zh_CN.txt help.zh_TW.txt

profiles =

EXTRA_DIST = samplekeys.asc mksamplekeys com-certs.pem qualified.txt \
	     gnupg-logo.eps gnupg-logo.pdf gnupg-logo.png gnupg-logo-tr.png \
	     gnupg-module-overview.png gnupg-module-overview.pdf \
             gnupg-card-architecture.png gnupg-card-architecture.pdf \
             FAQ gnupg7.texi mkdefsinc.c defsincdate \
             opt-homedir.texi see-also-note.texi specify-user-id.texi \
	     gpgv.texi yat2m.c ChangeLog-2011 whats-new-in-2.1.txt \
             trust-values.texi

BUILT_SOURCES = gnupg-module-overview.png gnupg-module-overview.pdf \
                gnupg-card-architecture.png gnupg-card-architecture.pdf \
                defsincdate defs.inc

info_TEXINFOS = gnupg.texi

dist_pkgdata_DATA =  $(helpfiles) $(profiles)

nobase_dist_doc_DATA = FAQ DETAILS HACKING DCO TRANSLATE OpenPGP KEYSERVER \
                       $(examples)

#dist_html_DATA =


gnupg_TEXINFOS = \
	gpg.texi gpgsm.texi gpg-agent.texi scdaemon.texi instguide.texi \
	tools.texi debugging.texi glossary.texi contrib.texi gpl.texi \
	sysnotes.texi dirmngr.texi wks.texi \
        gnupg-module-overview.svg \
        gnupg-card-architecture.fig \
	howtos.texi howto-create-a-server-cert.texi

gnupg.texi : defs.inc

# We need EPS files for "make distcheck" but we do not want to distribute
# them due to their size.  Let's build them as needed.
gnupg.dvi : gnupg-module-overview.eps gnupg-card-architecture.eps


DVIPS = TEXINPUTS="$(srcdir)$(PATH_SEPARATOR)$$TEXINPUTS" dvips

AM_MAKEINFOFLAGS = -I $(srcdir) --css-ref=/share/site.css

YAT2M_OPTIONS = -I $(srcdir) \
        --release "GnuPG @PACKAGE_VERSION@" --source "GNU Privacy Guard 2.2"

myman_sources = gnupg7.texi gpg.texi gpgsm.texi gpg-agent.texi \
	        dirmngr.texi scdaemon.texi tools.texi wks.texi
myman_pages   = gpgsm.1 gpg-agent.1 dirmngr.8 scdaemon.1 \
                watchgnupg.1 gpgconf.1 addgnupghome.8 gpg-preset-passphrase.1 \
		gpg-connect-agent.1 gpgparsemail.1 gpgtar.1 \
                gpg-check-pattern.1 \
		applygnupgdefaults.8 gpg-wks-client.1 gpg-wks-server.1 \
		dirmngr-client.1
if USE_GPG2_HACK
myman_pages += gpg2.1 gpgv2.1
else
myman_pages += gpg.1 gpgv.1
endif

man_MANS = $(myman_pages) gnupg.7

watchgnupg_SOURCE = gnupg.texi


CLEANFILES = yat2m mkdefsinc defs.inc

DISTCLEANFILES = gnupg.tmp gnupg.ops yat2m-stamp.tmp yat2m-stamp \
                 gnupg-card-architecture.eps \
                 gnupg-module-overview.eps \
		 $(myman_pages) gnupg.7

if HAVE_YAT2M
YAT2M_CMD = $(YAT2M)
YAT2M_DEP = $(YAT2M)
else
YAT2M_CMD = ./yat2m
YAT2M_DEP = yat2m

yat2m: yat2m.c
	$(CC_FOR_BUILD) -o $@ $(srcdir)/yat2m.c
endif

mkdefsinc: mkdefsinc.c Makefile ../config.h
	$(CC_FOR_BUILD) -I. -I.. -I$(srcdir) $(AM_CPPFLAGS) \
                        -o $@ $(srcdir)/mkdefsinc.c

.svg.eps:
	convert `test -f '$<' || echo '$(srcdir)/'`$< $@

.svg.png:
	convert `test -f '$<' || echo '$(srcdir)/'`$< $@

.svg.pdf:
	convert `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.png:
	fig2dev -L png `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.jpg:
	fig2dev -L jpeg `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.eps:
	fig2dev -L eps `test -f '$<' || echo '$(srcdir)/'`$< $@

.fig.pdf:
	fig2dev -L pdf `test -f '$<' || echo '$(srcdir)/'`$< $@


yat2m-stamp: $(myman_sources) defs.inc
	@rm -f yat2m-stamp.tmp
	@touch yat2m-stamp.tmp
	incd="`test -f defsincdate || echo '$(srcdir)/'`defsincdate"; \
	for file in $(myman_sources) ; do \
              $(YAT2M_CMD) $(YAT2M_OPTIONS) --store \
                  --date "`cat $$incd 2>/dev/null`" \
	          `test -f '$$file' || echo '$(srcdir)/'`$$file ; done
	@mv -f yat2m-stamp.tmp $@

yat2m-stamp: $(YAT2M_DEP)

$(myman_pages) gnupg.7 : yat2m-stamp defs.inc
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

dist-hook: defsincdate

defsincdate: $(gnupg_TEXINFOS)
	: >defsincdate ; \
	if test -e $(top_srcdir)/.git; then \
	  (cd $(srcdir) && git log -1 --format='%ct' \
               -- $(gnupg_TEXINFOS) 2>/dev/null) >>defsincdate; \
        elif test x"$$SOURCE_DATE_EPOCH" != x; then   \
	   echo "$$SOURCE_DATE_EPOCH" >>defsincdate ; \
	fi

defs.inc : defsincdate Makefile mkdefsinc
	incd="`test -f defsincdate || echo '$(srcdir)/'`defsincdate"; \
	./mkdefsinc -C $(srcdir) --date "`cat $$incd 2>/dev/null`" \
	    $(gnupg_TEXINFOS) >$@


online: gnupg.html gnupg.pdf gnupg-module-overview.png \
           gnupg-card-architecture.png
	set -e; \
	echo "Uploading current manuals to www.gnupg.org ..."; \
	cp $(srcdir)/gnupg-logo-tr.png gnupg.html/; \
	cp gnupg-module-overview.png gnupg.html/; \
	cp gnupg-card-architecture.png gnupg.html/; \
        user=werner ; webhost="ftp.gnupg.org" ; dashdevel="" ; \
        if echo "@PACKAGE_VERSION@" | grep -- "-beta" >/dev/null; then \
	  dashdevel="-devel" ; \
	else \
          rsync -v gnupg.pdf $${user}@$${webhost}:webspace/manuals/gnupg-2.2.pdf ; \
        fi ; \
	cd gnupg.html ; \
        rsync -vr --exclude='.git' .  \
	  $${user}@$${webhost}:webspace/manuals/gnupg-2.2$${dashdevel}/
