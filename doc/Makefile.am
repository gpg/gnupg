## Process this file with automake to create Makefile.in

EXTRA_DIST = DETAILS gpg.sgml gpg.1 FAQ HACKING OpenPGP

man_MANS = gpg.1


%.1 : %.sgml
if HAVE_DOCBOOK_TO_MAN
	  docbook-to-man $<  >$@
else
	  : Warning: missing docbook-to-man, cannot make $@
endif


%.txt : %.sgml
	 sgml2txt -c latin $*

%.html : %.sgml
	 sgml2html -c latin $*

%.dvi : %.sgml
	-rm $*.sgml.tmp
	mv $*.sgml $*.sgml.tmp
	sed -e '/<!entity/  s/"IGNORE">/"INCLUDE">/' $*.sgml.tmp >$*.sgml
	sgml2latex -b -l deutsch -c latin $* ; mv $*.sgml.tmp $*.sgml

%.ps : %.sgml
	-rm $*.sgml.tmp
	mv $*.sgml $*.sgml.tmp
	sed -e '/<!entity/  s/"IGNORE">/"INCLUDE">/' $*.sgml.tmp >$*.sgml
	sgml2latex -b -l deutsch -c latin -o ps $* ; mv $*.sgml.tmp $*.sgml

