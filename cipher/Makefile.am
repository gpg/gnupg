## Process this file with automake to produce Makefile.in


INCLUDES =  -I$(top_srcdir)/include -I$(top_srcdir)/intl

noinst_LTLIBRARIES = libcipher.la

# The configure script greps the module names from the following lines.
# You must also add all these names to EXTRA_PROGRAMS some lines below
# and EXTRA_foo_SOURCES entries.
# Hmmm is there a more easy way to do this?  (EXTRA_PROGRAMS
# might also list programs which are not modules)
# MODULES: rndunix rndlinux rndegd
# MODULES: sha1 rmd160 md5 tiger
EXTRA_PROGRAMS = rndunix rndlinux rndegd  \
		 sha1 rmd160 md5 tiger

EXTRA_rndlinux_SOURCES = rndlinux.c
EXTRA_rndunix_SOURCES = rndunix.c
EXTRA_rndegd_SOURCES = rndegd.c
EXTRA_md5_SOURCES = md5.c
EXTRA_rmd160_SOURCES = rmd160.c
EXTRA_sha1_SOURCES = sha1.c
EXTRA_tiger_SOURCES = tiger.c


if ENABLE_GNUPG_EXTENSIONS
pkglib_PROGRAMS  = @DYNAMIC_CIPHER_MODS@
else
pkglib_PROGRAMS  =
endif


DYNLINK_MOD_CFLAGS = -DIS_MODULE @DYNLINK_MOD_CFLAGS@

libcipher_la_LDFLAGS =
libcipher_la_SOURCES = cipher.c  \
		 pubkey.c	\
		 md.c		\
		 dynload.c	\
		 dynload.h	\
		 bithelp.h	\
		 des.c		\
		 des.h		\
		 twofish.c	\
		 blowfish.c	\
		 blowfish.h	\
		 cast5.c	\
		 cast5.h	\
		 elgamal.c	\
		 elgamal.h	\
		 primegen.c	\
		 random.h	\
		 random.c	\
		 rand-internal.h \
		 rmd.h		\
		 dsa.h		\
		 dsa.c		\
		 g10c.c 	\
		 smallprime.c	\
		 construct.c

# configure creates the constructor file
BUILT_SOURCES = construct.c


libcipher_la_DEPENDENCIES = @STATIC_CIPHER_OBJS@
libcipher_la_LIBADD =	    @STATIC_CIPHER_OBJS@


# If I remember it correct, automake 1.4 has a feature to set
# fooFLAGS depending on the program.  So we should check it out.

tiger: $(srcdir)/tiger.c
	`echo $(COMPILE) $(DYNLINK_MOD_CFLAGS) -o tiger $(srcdir)/tiger.c | \
	    sed -e 's/-O[2-9s]*/-O1/g' `

tiger.o: $(srcdir)/tiger.c
	`echo $(COMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `

#twofish: $(srcdir)/twofish.c
#	 `echo $(COMPILE) $(DYNLINK_MOD_CFLAGS) -o twofish $(srcdir)/twofish.c | \
#	     sed -e 's/-O[0-9s]*/  /g' `

twofish: $(srcdir)/twofish.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o twofish $(srcdir)/twofish.c

#twofish.o: $(srcdir)/twofish.c
#	 `echo $(COMPILE) -c $(srcdir)/twofish.c | sed -e 's/-O[0-9s]*/  /g' `


rndunix: $(srcdir)/rndunix.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndunix $(srcdir)/rndunix.c

rndlinux: $(srcdir)/rndlinux.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndlinux $(srcdir)/rndlinux.c

rndegd: $(srcdir)/rndegd.c
	$(COMPILE) $(DYNLINK_MOD_CFLAGS) -o rndegd $(srcdir)/rndegd.c



