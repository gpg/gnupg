## Process this file with automake to produce Makefile.in

gnupg_extensions = tiger twofish rndunix

INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LIBRARIES = libcipher.a
if ENABLE_GNUPG_EXTENSIONS
pkglib_PROGRAMS  = $(gnupg_extensions)
else
pkglib_PROGRAMS  =
endif

DYNLINK_MOD_CFLAGS = -DIS_MODULE @DYNLINK_MOD_CFLAGS@


libcipher_a_SOURCES = cipher.c	\
		 pubkey.c	\
		 md.c		\
		 dynload.c	\
		 dynload.h	\
		 des.c		\
		 des.h		\
		 blowfish.c	\
		 blowfish.h	\
		 cast5.c	\
		 cast5.h	\
		 elgamal.c	\
		 elgamal.h	\
		 md5.c		\
		 md5.h		\
		 primegen.c	\
		 random.h	\
		 random.c	\
		 rand-internal.h \
		 rndlinux.c	\
		 rmd.h		\
		 rmd160.c	\
		 sha1.h 	\
		 sha1.c 	\
		 dsa.h		\
		 dsa.c		\
		 g10c.c 	\
		 smallprime.c

EXTRA_tiger_SOURCES = tiger.c
EXTRA_twofish_SOURCES = twofish.c


tiger: $(srcdir)/tiger.c
	`echo $(COMPILE) $(DYNLINK_MOD_CFLAGS) -o tiger $(srcdir)/tiger.c | \
	    sed -e 's/-O[2-9]*/-O1/' `

twofish: $(srcdir)/twofish.c
	`echo $(COMPILE) $(DYNLINK_MOD_CFLAGS) -o twofish $(srcdir)/twofish.c | \
	    sed -e 's/-O[0-9]*/  /' `


rndunix: $(srcdir)/rndunix.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndunix $(srcdir)/rndunix.c

rndlinux: $(srcdir)/rndlinux.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndlinux $(srcdir)/rndlinux.c



install-exec-hook:
	@list='$(pkglib_PROGRAMS)'; for p in $$list; do \
	  if test -f $(pkglibdir)/$$p; then \
	    echo "chmod 644 $(pkglibdir)/$$p"; \
	    chmod 644 $(pkglibdir)/$$p; \
	  fi; \
	done

