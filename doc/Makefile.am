## Process this file with automake to create Makefile.in

EXTRA_DIST = DETAILS gpg.sgml gpg.1 gpgv.sgml gpgv.1 faq.raw FAQ faq.html \
             HACKING OpenPGP README.W32 

man_MANS = gpg.1 gpgv.1

pkgdata_DATA = FAQ faq.html

BUILT_SOURCES = FAQ faq.html

CLEANFILES = faq.raw.xref



%.1 : %.sgml
if HAVE_DOCBOOK_TO_MAN
	docbook-to-man $<  >$@
else
	: Warning: missing docbook-to-man, cannot make $@
	echo ".TH $< 1"   >$@
	echo "No man page due to missing docbook-to-man" >>$@
endif


FAQ : faq.raw
	$(FAQPROG) -f $<  $@ || $(FAQPROG) -f $< $@

faq.html : faq.raw
	$(FAQPROG) -h -f $< $@ 2>&1 || $(FAQPROG) -h -f $< $@

%.dvi: %.sgml
	db2dvi $<

%.ps: %.dvi
	dvips -o $@ $<

%/%.html: %.sgml
	-db2html $<


dist-hook:
	@if test `wc -c < gpg.1` -lt 200; then \
	    echo 'ERROR: dummy man page'; false; fi











