## Process this file with automake to produce Makefile.in

SUBDIRS =  intl po zlib util mpi cipher tools g10 doc checks
EXTRA_DIST = VERSION


tar:	clean
	cd ..; tar czvf  ~/bkup/g10-`date +%d%m`.tar.gz src


dist-hook:
	@set -e; \
	 for file in `find $(srcdir) -type f -name distfiles`; do \
	    dir=`dirname $$file` ; $(mkinstalldirs) $(distdir)/$$dir ; \
	    for i in distfiles `cat $$file` ; do \
		ln $(srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	    done ; \
	done
	for file in po/cat-id-tbl.c po/gnupg.pot; do \
	    rm $(distdir)/$$file || true ; \
	done


