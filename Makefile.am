## Process this file with automake to produce Makefile.in

SUBDIRS =  intl po zlib util mpi cipher tools g10 doc checks
EXTRA_DIST = VERSION  PROJECTS


dist-hook:
	@set -e; \
	 for file in `cd $(top_srcdir); find . -type f -name distfiles`; do \
	    dir=`dirname $$file` ; $(mkinstalldirs) $(distdir)/$$dir ; \
	    for i in distfiles `cat $(top_srcdir)/$$file` ; do \
		ln $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i 2> /dev/null \
		|| cp -p $(top_srcdir)/$$dir/$$i $(distdir)/$$dir/$$i; \
	    done ; \
	done
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' $(top_srcdir)/scripts/gnupg.spec \
	    > $(distdir)/scripts/gnupg-$(VERSION).spec


