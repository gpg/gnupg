## Process this file with automake to create Makefile.in

EXTRA_DIST = DETAILS rfcs gpg.1pod gpg.1

man_MANS = gpg.1

%: %pod
	 pod2man $< --section=`echo $@ | sed 's/^.*(?)$$/$$&/'`\
		    --release="`date -r $< '+%d %b %Y'`"\
		    --center="GNU Tools"  --date=' '\
		     >$@,$$$$ && mv -f $@,$$$$ $@\
		    || rm -f $@,$$$$

