## Process this file with automake to create Makefile.in

EXTRA_DIST = DETAILS rfcs gpg.1pod gpg.1

man_MANS = gpg.1

%: %pod
	 pod2man $< --section=`echo $@ | sed 's/^.*(?)$$/$$&/'`\
		    --release="`date -r $< '+%d %b %Y'`"\
		    --center="GNU Tools"  --date=' '\
		     >$@,$$$$ && mv -f $@,$$$$ $@\
		    || rm -f $@,$$$$



%.txt : %.sgml
	 sgml2txt -c latin $*

%.html : %.sgml
	 sgml2html -l deutsch -c latin $*

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

