## Process this file with automake to create Makefile.in

BUILT_SOURCES = version.sgml gcryptref.html gcryptref.ps


#EXTRA_DIST = DETAILS gpg.sgml gpg.1 FAQ HACKING OpenPGP \
#	     version.sgml.in $(BUILT_SOURCES)
EXTRA_DIST = DETAILS HACKING OpenPGP FAQ

#man_MANS = gpg.1

### pkgdata_DATA = gcryptref.html gcryptref.ps


CLEANFILES = gcryptref.aux gcryptref.log gcryptref.tex gcryptref.dvi


# gcryptref.sgml : version.sgml


if HAVE_DB2MAN
%.1 : %.sgml
	$(DB2MAN) $<  >$@
endif

if HAVE_DB2TEX
%.ps : %.dvi
	dvips -o $@ $<

%.tex : %.sgml
	$(DB2TEX) -V generate-book-toc $< > $@

%.dvi : %.tex
	$(JADETEX) $<
endif

if HAVE_DB2HTML
%.html : %.sgml
	$(DB2HTML) --nosplit $<
endif





