## Process this file with automake to produce Makefile.in

#if COMPILE_LIBGCRYPT
#gcrypt = gcrypt
#my_clean_gcrypt =
#else
#gcrypt =
#my_clean_gcrypt = gcrypt/Makefile
#endif

gcrypt = gcrypt
my_clean_gcrypt =

if CROSS_COMPILING
checks =
else
checks = checks
endif

if COMPILE_AGENT
agent = agent
else
agent = 
endif

SUBDIRS = intl zlib jnlib util mpi cipher ${gcrypt} g10 po tools \
          ${agent} doc ${checks}
EXTRA_DIST = README-alpha PROJECTS BUGS
# gettext never gets it right, so we take here care of deleting the
# symlink.  my_clean_gcrypt is just a kludge until we can include
# libgcrypt.
DISTCLEANFILES = gnupg-defs.h intl/libintl.h ${my_clean_gcrypt}


# Add all the files listed in "distfiles" files to the distribution,
# apply version number s to some files and create a VERSION file which
# we need for the Prereq: patch file trick.
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
	    > $(distdir)/scripts/gnupg.spec ; \
	echo "$(VERSION)" > $(distdir)/VERSION


if MAINTAINER_MODE
# This is only useful within my local environment (wk)
cvs-get:
	rsync -Cavuzb  --exclude scratch --exclude .deps \
		      wkoch@sigtrap.guug.de:work/gnupg .

cvs-put:
	rsync -Cavuzb --exclude .deps --exclude scratch \
		      . wkoch@sigtrap.guug.de:work/gnupg

cvs-sync: cvs-get cvs-put

endif


.PHONY: cvs-get cvs-put cvs-sync

