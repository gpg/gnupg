# GPH - GNU Privacy Handbook

PARTS = manual.sgml c1.sgml c2.sgml c3.sgml c4.sgml c5.sgml c6.sgml c7.sgml \
	signatures.fig signatures.jpg.asc

EXTRA_DIST = $(PARTS) index.html
#BUILT_SOURCES = index.html

all-local: ./signatures.jpg

./signatures.jpg: $(srcdir)/signatures.jpg.asc
	../../g10/gpg --yes --dearmor \
		      -o ./signatures.jpg $(srcdir)/signatures.jpg.asc
	test -d manual && cp ./signatures.jpg ./manual/signatures.jpg


index.html: $(PARTS)
	@set -e; \
	   for i in $(PARTS); do \
	     [ -f $$i ] || cat /dev/null $(srcdir)/$$i >./$$i ; \
	   done
	db2html manual.sgml
	echo '<html><body>' >index.html
	echo '<ul>'         >>index.html
	echo '<li><a href="manual/book1.html">GnuPG User Manual</a>' >>index.html
	echo '</ul>'          >>index.html
	echo '</body></html>' >>index.html
	-rm -r manual.junk
	-rm manual/signatures.jpg
	(cd manual; rm -r stylesheet-images; ls | grep -v distfiles >distfiles)


dist-hook: index.html


%.dvi: %.sgml
	db2dvi $<

%.ps: %.dvi
	dvips -o $@ $<

%/%.html: %.sgml
	db2html $<


%.png: %.fig
	fig2dev -L png $< $@

%.jpg: %.fig
	fig2dev -L jpeg $< $@

%.eps: %.fig
	fig2dev -L ps  $< $@

