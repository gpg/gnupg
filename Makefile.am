## Process this file with automake to produce Makefile.in

SUBDIRS = intl zlib util mpi cipher tools g10 po doc checks
EXTRA_DIST = VERSION  PROJECTS BUGS

all-am: g10defs.h
all-recursive-am: g10defs.h


g10defs.h : config.h
	@( set -e; \
	echo "/* Generated automatically by Makefile */" ; \
	echo "#ifdef HAVE_DRIVE_LETTERS"; \
	echo "#define G10_LOCALEDIR \"c:/lib/gnupg/locale\""; \
	echo "#define GNUPG_LIBDIR \"c:/lib/gnupg\""; \
	echo "#define GNUPG_DATADIR \"c:/lib/gnupg\""; \
	echo "#else";\
	echo "#define G10_LOCALEDIR \"$(prefix)/$(DATADIRNAME)/locale\""; \
	echo "#define GNUPG_LIBDIR \"$(libdir)/gnupg\""; \
	echo "#define GNUPG_DATADIR \"$(datadir)/gnupg\""; \
	echo "#endif";\
	) >g10defs.h


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
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/scripts/gnupg.spec.in \
	    > $(distdir)/scripts/gnupg.spec


# maintainer only
cvs-get:
	rsync -Cavuzb  --exclude scratch --exclude .deps \
		      koch@ftp.guug.de:work/gnupg .

cvs-put:
	rsync -Cavuzb --exclude .deps --exclude scratch \
		      . koch@ftp.guug.de:work/gnupg

cvs-sync: cvs-get cvs-put


tobold-get:
	rsync -Cavuzb --exclude scratch --exclude .deps \
		      tobold:gnupg/ .

tobold-put:
	rsync -Cavuzb --exclude scratch --exclude .deps \
		      . tobold:gnupg/


.PHONY: cvs-get cvs-put cvs-sync

