## Process this file with automake to create Makefile.in

##SUBDIRS = gph

EXTRA_DIST = DETAILS gpg.sgml gpg.1 FAQ HACKING OpenPGP

man_MANS = gpg.1


%.1 : %.sgml
if HAVE_DOCBOOK_TO_MAN
	docbook-to-man $<  >$@
else
	: Warning: missing docbook-to-man, cannot make $@
	echo ".TH $< 1"   >$@
	echo "No man page due to missing docbook-to-man" >>$@
endif


%.dvi: %.sgml
	db2dvi $<

%.ps: %.dvi
	dvips -o $@ $<

%/%.html: %.sgml
	-db2html $<


