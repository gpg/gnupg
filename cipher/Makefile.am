## Process this file with automake to produce Makefile.in

gnupg_extensions = tiger twofish

INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl -I../intl

noinst_LIBRARIES = libcipher.a
if ENABLE_GNUPG_EXTENSIONS
pkglib_PROGRAMS  = $(gnupg_extensions)
else
pkglib_PROGRAMS  =
endif


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
		 rand-unix.c	\
		 rand-w32.c	\
		 rand-dummy.c	\
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
	`echo $(COMPILE) -shared  -fPIC -lc -o tiger $(srcdir)/tiger.c | \
	    sed -e 's/-O2/-O1/' `

twofish: $(srcdir)/twofish.c
	`echo $(COMPILE) -shared  -fPIC -lc -o twofish $(srcdir)/twofish.c | \
	    sed -e 's/-O2/  /' `


install-exec-hook:
	@list='$(pkglib_PROGRAMS)'; for p in $$list; do \
	  if test -f $(pkglibdir)/$$p; then \
	    echo "chmod 644 $(pkglibdir)/$$p"; \
	    chmod 644 $(pkglibdir)/$$p; \
	  fi; \
	done

