## Process this file with automake to create Makefile.in

EXTRA_DIST = DETAILS gpg.sgml gpg.1 FAQ HACKING OpenPGP

man_MANS = gpg.1


gcryptref.dvi : gcryptref.sgml

gcryptref.texi : gcryptref.sgml
gcryptref.xml  : gcryptref.sgml


%.ps: %.dvi
	dvips -o $@ $<


if MAINTAINER_MODE

%.1 : %.sgml
	docbook-to-man $<  >$@

%.texi : %.xml
	docbook2texi $< >$@

%.xml  : %.sgml
	sgml2xml -x lower $< >$@

endif




