# Makefile for the RISC OS development version of GnuPG
BRANCH=devel

CC=cc
LINK=link
AR=libfile
AS=objasm
MAKE=amu
DEPEND=-depend !Depend
LIBLDAP=^.^.openldap-2/0/27
ZLIB=zlib.zlib

CC_FLAGS=-Wdp -throwback -Otime -Iinclude,mpi,intl,util,zlib,$(LIBLDAP).include,^.^.regex-0/12,Unix: -JUnix: -D__riscos__ -DHAVE_CONFIG_H -DNO_ASM -UIS_MODULE -DVERSION="\"$(GnuPG$Version)\"" -DSAFE_VERSION="\"$(GnuPG$SafeVersion)\"" -DIS_DEVELOPMENT_VERSION
AR_FLAGS=
AS_FLAGS=-throwback -predefine "ARMv4 SETA 0"
LD_FLAGS=
UNIXLIB=Unix:o.UnixLib

CIPHER_OBJS=cipher.o.blowfish \
	cipher.o.cast5 \
	cipher.o.cipher \
	cipher.o.des \
	cipher.o.dsa \
	cipher.o.dynload \
	cipher.o.elgamal \
	cipher.o.g10c \
	cipher.o.md \
	cipher.o.md5 \
	cipher.o.primegen \
	cipher.o.pubkey \
	cipher.o.random \
	cipher.o.rijndael \
	cipher.o.rmd160 \
	cipher.o.rndriscos \
	cipher.o.rsa \
	cipher.o.sha1 \
	cipher.o.sha256 \
	cipher.o.sha512 \
	cipher.o.smallprime \
	cipher.o.twofish
GETTEXT_OBJS=intl.o.bindtextdom \
	intl.o.dcgettext \
	intl.o.dcigettext \
	intl.o.dcngettext \
	intl.o.dgettext \
	intl.o.dngettext \
	intl.o.explodename \
	intl.o.finddomain \
	intl.o.gettext \
	intl.o.intl-compat \
	intl.o.l10nflist \
	intl.o.loadmsgcat \
	intl.o.localealias \
	intl.o.ngettext \
	intl.o.plural \
	intl.o.textdomain
MPI_OBJS=mpi.o.mpi-add \
	mpi.o.mpi-bit \
	mpi.o.mpi-cmp \
	mpi.o.mpi-div \
	mpi.o.mpi-gcd \
	mpi.o.mpi-inline \
	mpi.o.mpi-inv \
	mpi.o.mpi-mul \
	mpi.o.mpi-pow \
	mpi.o.mpi-mpow \
	mpi.o.mpi-scan \
	mpi.o.mpicoder \
	mpi.o.mpih-div \
	mpi.o.mpih-mul \
	mpi.o.mpiutil \
	mpi.o.g10m \
	mpi.arm.o.mpih
UTIL_OBJS=util.o.argparse \
	util.o.dotlock \
	util.o.errors \
	util.o.fileutil \
	util.o.g10u \
	util.o.http \
	util.o.iobuf \
	util.o.logger \
	util.o.memory \
	util.o.miscutil \
	util.o.secmem \
	util.o.srv \
	util.o.strgutil \
	util.o.ttyio \
	util.o.riscos
ZLIB_OBJS=zlib.o.adler32 \
	zlib.o.compress \
	zlib.o.crc32 \
	zlib.o.deflate \
	zlib.o.infblock \
	zlib.o.infcodes \
	zlib.o.inffast \
	zlib.o.inflate \
	zlib.o.inftrees \
	zlib.o.infutil \
	zlib.o.trees \
	zlib.o.uncompr \
	zlib.o.zutil
G10_OBJS=g10.o.armor \
	g10.o.build-packet \
	g10.o.cipher \
	g10.o.comment \
	g10.o.compress \
	g10.o.dearmor \
	g10.o.decrypt \
	g10.o.delkey \
	g10.o.encode \
	g10.o.encr-data \
	g10.o.exec \
	g10.o.export \
	g10.o.free-packet \
	g10.o.getkey \
	g10.o.helptext \
	g10.o.import \
	g10.o.kbnode \
	g10.o.keydb \
	g10.o.keyedit \
	g10.o.keygen \
	g10.o.keyid \
	g10.o.keylist \
	g10.o.keyring \
	g10.o.keyserver \
	g10.o.mainproc \
	g10.o.mdfilter \
	g10.o.misc \
	g10.o.mkdtemp \
	g10.o.openfile \
	g10.o.parse-packet \
	g10.o.passphrase \
	g10.o.photoid \
	g10.o.pipemode \
	g10.o.pkclist \
	g10.o.plaintext \
	g10.o.progress \
	g10.o.pubkey-enc \
	g10.o.revoke \
	g10.o.seckey-cert \
	g10.o.seskey \
	g10.o.sig-check \
	g10.o.sign \
	g10.o.signal \
	g10.o.skclist \
	g10.o.status \
	g10.o.tdbdump \
	g10.o.tdbio \
	g10.o.textfilter \
	g10.o.trustdb \
	g10.o.verify
GPGV_OBJS=g10.o.armor \
	g10.o.build-packet \
	g10.o.compress \
	g10.o.free-packet \
	g10.o.getkey \
	g10.o.gpgv \
	g10.o.keydb \
	g10.o.keylist \
	g10.o.kbnode \
	g10.o.keyid \
	g10.o.keyring \
	g10.o.mainproc \
	g10.o.mdfilter \
	g10.o.misc \
	g10.o.openfile \
	g10.o.parse-packet \
	g10.o.plaintext \
	g10.o.progress \
	g10.o.seskey \
	g10.o.sig-check \
	g10.o.signal \
	g10.o.status \
	g10.o.textfilter \
	g10.o.verify \
	util.o.argparse \
	util.o.errors \
	util.o.fileutil \
	util.o.g10u \
	util.o.iobuf \
	util.o.logger \
	util.o.memory \
	util.o.miscutil \
	util.o.secmem \
	util.o.strgutil \
	util.o.riscos \
	cipher.o.dsa \
	cipher.o.dynload \
	cipher.o.elgamal \
	cipher.o.g10c \
	cipher.o.md \
	cipher.o.md5 \
	cipher.o.pubkey \
	cipher.o.rmd160 \
	cipher.o.rsa \
	cipher.o.sha1 \
	cipher.o.sha256 \
	cipher.o.sha512 \
	mpi.mpi
GPGKEYS_OBJS=util.util \
	intl.gettext

## Rule Patterns ##

.SUFFIXES:	.c .o .s

.c.o:
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o $@ $<

.s.o:
	$(AS) $(AS_FLAGS) $(DEPEND) $< $@

# Static dependencies:

all:
	@echo Use one of the following as target:
	@echo |  dev   to build the development version
	@echo |  dist  to build the distribution with all archives
	@echo All other targets are internal and shouldn't be used!

cipher.cipher: $(CIPHER_OBJS)
	$(AR) $(AR_FLAGS) -c -o cipher.cipher $(CIPHER_OBJS)

intl.gettext: $(GETTEXT_OBJS)
	$(AR) $(AR_FLAGS) -c -o intl.gettext $(GETTEXT_OBJS)

mpi.mpi: $(MPI_OBJS)
	$(AR) $(AR_FLAGS) -c -o mpi.mpi $(MPI_OBJS)

tools.gpgsplit: tools.o.gpgsplit util.util intl.gettext $(ZLIB)
	$(LINK) $(LD_FLAGS) -o tools.gpgsplit tools.o.gpgsplit util.util intl.gettext $(ZLIB) $(UNIXLIB)
	-squeeze tools.gpgsplit
	-copy tools.gpgsplit ADFS::A4.$.tmp.!GnuPG.gpgsplit ~CF~V

keyserver.gpgkeys_ldap: keyserver.o.gpgkeys_ldap $(GPGKEYS_OBJS) $(LIBLDAP).libraries.libldap.libldap
	$(LINK) $(LD_FLAGS) -o keyserver.gpgkeys_ldap keyserver.o.gpgkeys_ldap $(GPGKEYS_OBJS) $(LIBLDAP).libraries.libldap.libldap $(UNIXLIB)
	-squeeze keyserver.gpgkeys_ldap
	-copy keyserver.gpgkeys_ldap ADFS::A4.$.tmp.!GnuPG.gpgkeys_ldap ~CF~V

keyserver.gpgkeys_hkp: keyserver.o.gpgkeys_hkp $(GPGKEYS_OBJS)
	$(LINK) $(LD_FLAGS) -o keyserver.gpgkeys_hkp keyserver.o.gpgkeys_hkp $(GPGKEYS_OBJS) $(UNIXLIB)
	-squeeze keyserver.gpgkeys_hkp
	-copy keyserver.gpgkeys_hkp ADFS::A4.$.tmp.!GnuPG.gpgkeys_hkp ~CF~V

riscos.jpegview.jpegview:
	-dir riscos.jpegview
	-$(MAKE)
	-back

util.util: $(UTIL_OBJS)
	$(AR) $(AR_FLAGS) -c -o util.util $(UTIL_OBJS)

zlib.zlib: $(ZLIB_OBJS)
	$(AR) $(AR_FLAGS) -c -o zlib.zlib $(ZLIB_OBJS)

g10.gpg: g10.o.g10 $(G10_OBJS) cipher.o.idea cipher.cipher intl.gettext mpi.mpi util.util $(ZLIB) BUILD
	$(LINK) $(LD_FLAGS) -o g10.gpg g10.o.g10 $(G10_OBJS) cipher.o.idea cipher.cipher intl.gettext mpi.mpi util.util $(ZLIB) $(UNIXLIB)
	-copy g10.gpg ADFS::A4.$.tmp.!GnuPG.gpg ~CFR~V

g10.gpgv: $(GPGV_OBJS) intl.gettext $(ZLIB) BUILD
	$(LINK) $(LD_FLAGS) -o g10.gpgv $(GPGV_OBJS) intl.gettext $(ZLIB) $(UNIXLIB)
	-copy g10.gpgv ADFS::A4.$.tmp.!GnuPG.gpgv ~CFR~V

g10.gpgpart: $(G10_OBJS) BUILD
	copy $(UNIXLIB) g10.gpgpart ~CF~V
	$(AR) $(AR_FLAGS) -i g10.gpgpart $(CIPHER_OBJS)
	$(AR) $(AR_FLAGS) -i g10.gpgpart $(GETTEXT_OBJS)
	$(AR) $(AR_FLAGS) -i g10.gpgpart $(MPI_OBJS)
	$(AR) $(AR_FLAGS) -i g10.gpgpart $(UTIL_OBJS)
ifdef ZLIB
	$(AR) $(AR_FLAGS) -i g10.gpgpart $(ZLIB_OBJS)
endif
	$(AR) $(AR_FLAGS) -i g10.gpgpart $(G10_OBJS)

select-idea-src:
	-copy distrib.idea-addon.cipher.c.idea cipher.c.idea ~CF~NR~V
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o cipher.o.idea cipher.c.idea

select-gpl-src:
	-copy distrib.non-idea.cipher.c.idea cipher.c.idea ~CF~NR~V
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o cipher.o.idea cipher.c.idea

distrib.gnupgsrc/zip: select-gpl-src
	-zip -9@ distrib.gnupgsrc/zip < distrib.resources.distfiles

distrib.gnupg/zip: distrib.gpl-bin.!GnuPG.JPEGview distrib.gpl-bin.!GnuPG.gpgsplit distrib.gpl-bin.!GnuPG.gpgkeys_hkp distrib.gpl-bin.!GnuPG.gpg distrib.gpl-bin.!GnuPG.gpgv select-gpl-src
	-copy distrib.resources.History distrib.gpl-bin.History ~CFR~V
	-copy distrib.resources.Upgrading distrib.gpl-bin.Upgrading ~CFR~V
	-copy distrib.resources.ReadMe_bin distrib.gpl-bin.!ReadMe1st ~CFR~V
	-copy distrib.resources.!GnuPG distrib.gpl-bin.!GnuPG ~CFR~V
	-copy distrib.resources.!GnuPGUser distrib.gpl-bin.!GnuPGUser ~CFR~V
	-copy distrib.resources.orig_docs distrib.gpl-bin.orig_docs ~CFR~V
	-dir distrib.gpl-bin
	-zip -r9 ^.gnupg/zip *
	-back

distrib.gnupgdev/zip: distrib.private.!GnuPG.JPEGview distrib.private.!GnuPG.gpgsplit distrib.private.!GnuPG.gpgkeys_ldap distrib.private.!GnuPG.gpgkeys_hkp distrib.private.!GnuPG.gpg distrib.private.!GnuPG.gpgv select-idea-src
	-ifthere distrib.private.!GnuPG.locale then wipe distrib.private.!GnuPG.locale ~CFR~V
	-copy distrib.intl.!GnuPG.locale distrib.private.!GnuPG.locale ~CFR~V
	-copy distrib.resources.History distrib.private.History ~CFR~V
	-copy distrib.resources.Upgrading distrib.private.Upgrading ~CFR~V
	-copy distrib.resources.ReadMe_bin distrib.private.!ReadMe1st ~CFR~V
	-copy distrib.resources.!GnuPG distrib.private.!GnuPG ~CFR~V
	-copy distrib.resources.!GnuPGUser distrib.private.!GnuPGUser ~CFR~V
	-copy distrib.resources.orig_docs distrib.private.orig_docs ~CFR~V
	-dir distrib.private
	-zip -r9 ^.gnupgdev/zip *
	-back

distrib.gnupgidea/zip: cipher.o.idea select-idea-src
	-copy distrib.resources.ReadMe_idea distrib.idea-addon.!ReadMe ~CFR~V
	-copy cipher.o.idea distrib.idea-addon.cipher.o.idea ~CFR~V
	-dir distrib.idea-addon
	-zip -r9 ^.gnupgidea/zip *
	-back

distrib.gnupgpart/zip: g10.o.g10 g10.gpgpart select-idea-src
	-copy distrib.resources.ReadMe_part distrib.part.!ReadMe1st ~CFR~V
	-copy g10.gpgpart distrib.part.g10.gpgpart ~CFR~V
	-copy g10.o.g10 distrib.part.g10.g10 ~CFR~V
	-dir distrib.part
	-zip -r9 ^.gnupgpart/zip *
	-back

distrib.gnupgldap/zip: keyserver.gpgkeys_ldap
	-copy distrib.resources.ReadMe_ldap distrib.ldap.!ReadMe ~CFR~V
	-copy keyserver.gpgkeys_ldap distrib.ldap.!GnuPG.gpgkeys_ldap ~CFR~V
	-dir distrib.ldap
	-zip -r9 ^.gnupgldap/zip *
	-back

distrib.gnupgintl/zip:
	-dir distrib.intl
	-zip -r9 ^.gnupgintl/zip *
	-back

distrib.gpl-bin.!GnuPG.gpg: g10.gpg
	-copy g10.gpg distrib.gpl-bin.!GnuPG.gpg ~CFR~V
	-squeeze distrib.gpl-bin.!GnuPG.gpg

distrib.gpl-bin.!GnuPG.gpgv: g10.gpgv
	-copy g10.gpgv distrib.gpl-bin.!GnuPG.gpgv ~CFR~V
	-squeeze distrib.gpl-bin.!GnuPG.gpgv

distrib.gpl-bin.!GnuPG.gpgsplit: tools.gpgsplit
	-copy tools.gpgsplit distrib.gpl-bin.!GnuPG.gpgsplit ~CFR~V
	-squeeze distrib.gpl-bin.!GnuPG.gpgsplit

distrib.gpl-bin.!GnuPG.gpgkeys_hkp: keyserver.gpgkeys_hkp
	-copy keyserver.gpgkeys_hkp distrib.gpl-bin.!GnuPG.gpgkeys_hkp ~CFR~V
	-squeeze distrib.gpl-bin.!GnuPG.gpgkeys_hkp

distrib.gpl-bin.!GnuPG.JPEGview: riscos.jpegview.jpegview
	-copy riscos.jpegview.jpegview distrib.gpl-bin.!GnuPG.JPEGview ~CFR~V

distrib.private.!GnuPG.gpg: g10.gpg
	-copy g10.gpg distrib.private.!GnuPG.gpg ~CFR~V
	-squeeze distrib.private.!GnuPG.gpg

distrib.private.!GnuPG.gpgv: g10.gpgv
	-copy g10.gpgv distrib.private.!GnuPG.gpgv ~CFR~V
	-squeeze distrib.private.!GnuPG.gpgv

distrib.private.!GnuPG.gpgsplit: tools.gpgsplit
	-copy tools.gpgsplit distrib.private.!GnuPG.gpgsplit ~CFR~V
	-squeeze distrib.private.!GnuPG.gpgsplit

distrib.private.!GnuPG.gpgkeys_ldap: keyserver.gpgkeys_ldap
	-copy keyserver.gpgkeys_ldap distrib.private.!GnuPG.gpgkeys_ldap ~CFR~V
	-squeeze distrib.private.!GnuPG.gpgkeys_ldap

distrib.private.!GnuPG.gpgkeys_hkp: keyserver.gpgkeys_hkp
	-copy keyserver.gpgkeys_hkp distrib.private.!GnuPG.gpgkeys_hkp ~CFR~V
	-squeeze distrib.private.!GnuPG.gpgkeys_hkp

distrib.private.!GnuPG.JPEGview: riscos.jpegview.jpegview
	-copy riscos.jpegview.jpegview distrib.private.!GnuPG.JPEGview ~CFR~V

clean-cipher:
	-ifthere cipher.o.* then wipe cipher.o.* ~CFR~V
	-ifthere cipher.cipher then wipe cipher.cipher ~CFR~V

clean-intl:
	-ifthere intl.o.* then wipe intl.o.* ~CFR~V
	-ifthere intl.gettext then wipe intl.gettext ~CFR~V

clean-mpi:
	-ifthere mpi.o.* then wipe mpi.o.* ~CFR~V
	-ifthere mpi.arm.o.* then wipe mpi.arm.o.* ~CFR~V
	-ifthere mpi.mpi then wipe mpi.mpi ~CFR~V

clean-util:
	-ifthere util.o.* then wipe util.o.* ~CFR~V
	-ifthere util.util then wipe util.util ~CFR~V

clean-zlib:
	-ifthere zlib.o.* then wipe zlib.o.* ~CFR~V
	-ifthere zlib.zlib then wipe zlib.zlib ~CFR~V

clean-dist:
	-ifthere distrib.*/zip then wipe distrib.*/zip ~CFR~V

clean-g10:
	-ifthere g10.gpg then wipe g10.gpg ~CFR~V
	-ifthere g10.gpgv then wipe g10.gpgv ~CFR~V
	-ifthere g10.gpgpart then wipe g10.gpgpart ~CFR~V
	-ifthere g10.o.* then wipe g10.o.* ~CFR~V

clean-keyserver:
	-ifthere keyserver.gpgkeys_ldap then wipe keyserver.gpgkeys_ldap ~CFR~V
	-ifthere keyserver.gpgkeys_hkp then wipe keyserver.gpgkeys_hkp ~CFR~V
	-ifthere keyserver.o.* then wipe keyserver.o.* ~CFR~V

clean-tools:
	-ifthere tools.gpgsplit then wipe tools.gpgsplit ~CFR~V
	-ifthere tools.o.* then wipe tools.o.* ~CFR~V

clean-riscos:
	-ifthere riscos.jpegview.jpegview then wipe riscos.jpegview.jpegview ~CFR~V

clean-version:
	-ifthere g10.o.armor then wipe g10.o.armor ~CFR~V
	-ifthere g10.o.encode then wipe g10.o.encode ~CFR~V
	-ifthere g10.o.g10 then wipe g10.o.g10 ~CFR~V
	-ifthere g10.o.gpgv then wipe g10.o.gpgv ~CFR~V
	-ifthere g10.o.keygen then wipe g10.o.keygen ~CFR~V
	-ifthere g10.o.keyserver then wipe g10.o.keyserver ~CFR~V
	-ifthere g10.gpg then wipe g10.gpg ~CFR~V
	-ifthere g10.gpgv then wipe g10.gpgv ~CFR~V
	-ifthere g10.gpgpart then wipe g10.gpgpart ~CFR~V

clean: clean-dist clean-cipher clean-intl clean-mpi clean-util clean-zlib clean-g10 clean-keyserver clean-tools clean-riscos

g10.o.armor: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.armor g10.c.armor

g10.o.encode: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.encode g10.c.encode

g10.o.g10: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.g10 g10.c.g10

g10.o.gpgv: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.gpgv g10.c.gpgv

g10.o.keygen: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.keygen g10.c.keygen

g10.o.keyserver: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.keyserver g10.c.keyserver

dev: clean-version
	$(MAKE) fast-dev

fast-dev: BUILD
ifdef USE_ZLIBRISCOS
	zlib-riscos-use
else
	zlib-riscos-nouse
endif
	setver configure/ac AC_INIT(gnupg, , dev
	wipe distrib.private.!GnuPG.gpg* ~CFR~V
	-$(MAKE) keyserver.gpgkeys_ldap
	$(MAKE) tools.gpgsplit
	$(MAKE) distrib.gnupgdev/zip
	ifthere <WebServe$ServeRoot>.private.gnupgdev/zip then wipe <WebServe$ServeRoot>.private.gnupgdev/zip ~CFR~V
	rename distrib.gnupgdev/zip <WebServe$ServeRoot>.private.gnupgdev/zip

dist: BUILD clean-version tools.gpgsplit
ifdef USE_ZLIBRISCOS
	zlib-riscos-use
else
	zlib-riscos-nouse
endif
	setver configure/ac AC_INIT(gnupg, , dist
	wipe distrib.gpl-bin.!GnuPG.gpg* ~CFR~V
	$(MAKE) distrib.gnupg/zip
	$(MAKE) distrib.gnupgidea/zip
	$(MAKE) distrib.gnupgpart/zip
	wipe distrib.private.!GnuPG.gpg* ~CFR~V
	$(MAKE) distrib.gnupgdev/zip
	$(MAKE) distrib.gnupgsrc/zip
	$(MAKE) distrib.gnupgintl/zip
	$(MAKE) distrib.gnupgldap/zip
	$(MAKE) select-idea-src
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg/zip then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.private.gnupgdev/zip then wipe <WebServe$ServeRoot>.private.gnupgdev/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgidea/zip then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgidea/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgpart/zip then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgpart/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgsrc/zip then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgsrc/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgintl/zip then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgintl/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgldap/zip then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgldap/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg_history/txt then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg_history/txt ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg_news/txt then wipe <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg_news/txt ~CFR~V
	rename distrib.gnupgdev/zip <WebServe$ServeRoot>.private.gnupgdev/zip
	rename distrib.gnupg/zip <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg/zip
	rename distrib.gnupgidea/zip <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgidea/zip
	rename distrib.gnupgpart/zip <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgpart/zip
	rename distrib.gnupgsrc/zip <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgsrc/zip
	rename distrib.gnupgintl/zip <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgintl/zip
	rename distrib.gnupgldap/zip <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupgldap/zip
	copy distrib.resources.History <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg_history/txt ~CFR~V
	copy distrib.resources.orig_docs.NEWS <WebServe$ServeRoot>.archives.gnupg-$(BRANCH).gnupg_news/txt ~CFR~V
	unset GnuPG$DevDefine
	unset GnuPG$Version
	unset GnuPG$SafeVersion
	updatesigs <WebServe$ServeRoot>.archives.gnupg-$(BRANCH) --secring adfs::pgp.$.secring/gpg

# Dynamic dependencies:
