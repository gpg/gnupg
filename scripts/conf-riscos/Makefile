# Makefile for the RISC OS version of GnuPG
CC=cc
LINK=link
AS=objasm
MAKE=amu
DEPEND=-depend !Depend
CC_FLAGS=-Wp -apcs 3/26bit -throwback -Otime -IUnix:,include.,mpi.,intl.,zlib. -JUnix: -D__riscos__ -DHAVE_CONFIG_H -DNO_ASM -UIS_MODULE -DVERSION="\"$(GnuPG$Version)\"" $(GnuPG$DevDefine)
AS_FLAGS=-apcs 3/26bit -throwback -predefine "ARMv4 SETA 0"
LD_FLAGS=Unix:o.unixlib
CIPHER_OBJS=cipher.blowfish.o \
	cipher.cast5.o \
	cipher.cipher.o \
	cipher.construct.o \
	cipher.des.o \
	cipher.dsa.o \
	cipher.dynload.o \
	cipher.elgamal.o \
	cipher.g10c.o \
	cipher.md.o \
	cipher.md5.o \
	cipher.primegen.o \
	cipher.pubkey.o \
	cipher.random.o \
	cipher.rijndael.o \
	cipher.rmd160.o \
	cipher.rndriscos.o \
	cipher.rsa.o \
	cipher.sha1.o \
	cipher.smallprime.o \
	cipher.tiger32.o \
	cipher.twofish.o
GETTEXT_OBJS=intl.bindtextdom.o \
	intl.dcgettext.o \
	intl.dgettext.o \
	intl.explodename.o \
	intl.finddomain.o \
	intl.gettext.o \
	intl.intl-compat.o \
	intl.l10nflist.o \
	intl.loadmsgcat.o \
	intl.localealias.o \
	intl.textdomain.o
MPI_OBJS=mpi.mpi-add.o \
	mpi.mpi-bit.o \
	mpi.mpi-cmp.o \
	mpi.mpi-div.o \
	mpi.mpi-gcd.o \
	mpi.mpi-inline.o \
	mpi.mpi-inv.o \
	mpi.mpi-mul.o \
	mpi.mpi-pow.o \
	mpi.mpi-mpow.o \
	mpi.mpi-scan.o \
	mpi.mpicoder.o \
	mpi.mpih-div.o \
	mpi.mpih-mul.o \
	mpi.mpiutil.o \
	mpi.g10m.o \
	mpi.arm.mpih.o
UTIL_OBJS=util.argparse.o \
	util.dotlock.o \
	util.errors.o \
	util.fileutil.o \
	util.g10u.o \
	util.http.o \
	util.iobuf.o \
	util.logger.o \
	util.memory.o \
	util.miscutil.o \
	util.secmem.o \
	util.strgutil.o \
	util.ttyio.o \
	util.riscos.o
ZLIB_OBJS=zlib.adler32.o \
	zlib.compress.o \
	zlib.crc32.o \
	zlib.deflate.o \
	zlib.infblock.o \
	zlib.infcodes.o \
	zlib.inffast.o \
	zlib.inflate.o \
	zlib.inftrees.o \
	zlib.infutil.o \
	zlib.trees.o \
	zlib.uncompr.o \
	zlib.zutil.o
G10_OBJS=g10.armor.o \
	g10.build-packet.o \
	g10.cipher.o \
	g10.comment.o \
	g10.compress.o \
	g10.dearmor.o \
	g10.decrypt.o \
	g10.delkey.o \
	g10.encode.o \
	g10.encr-data.o \
	g10.export.o \
	g10.free-packet.o \
	g10.g10.o \
	g10.getkey.o \
	g10.helptext.o \
	g10.hkp.o \
	g10.import.o \
	g10.kbnode.o \
	g10.keyedit.o \
	g10.keygen.o \
	g10.keyid.o \
	g10.keylist.o \
	g10.mainproc.o \
	g10.mdfilter.o \
	g10.misc.o \
	g10.openfile.o \
	g10.parse-packet.o \
	g10.passphrase.o \
	g10.pipemode.o \
	g10.pkclist.o \
	g10.plaintext.o \
	g10.pubkey-enc.o \
	g10.revoke.o \
	g10.ringedit.o \
	g10.seckey-cert.o \
	g10.seskey.o \
	g10.sig-check.o \
	g10.sign.o \
	g10.signal.o \
	g10.skclist.o \
	g10.status.o \
	g10.tdbdump.o \
	g10.tdbio.o \
	g10.textfilter.o \
	g10.trustdb.o \
	g10.verify.o
GPGV_OBJS=g10.armor.o \
	g10.build-packet.o \
	g10.compress.o \
	g10.free-packet.o \
	g10.getkey.o \
	g10.gpgv.o \
	g10.kbnode.o \
	g10.keyid.o \
	g10.mainproc.o \
	g10.mdfilter.o \
	g10.misc.o \
	g10.openfile.o \
	g10.parse-packet.o \
	g10.plaintext.o \
	g10.ringedit.o \
	g10.seskey.o \
	g10.sig-check.o \
	g10.signal.o \
	g10.status.o \
	g10.textfilter.o \
	g10.verify.o \
	util.argparse.o \
	util.errors.o \
	util.fileutil.o \
	util.g10u.o \
	util.iobuf.o \
	util.logger.o \
	util.memory.o \
	util.miscutil.o \
	util.secmem.o \
	util.strgutil.o \
	util.riscos.o \
	cipher.constructv.o \
	cipher.dsa.o \
	cipher.dynload.o \
	cipher.elgamal.o \
	cipher.g10c.o \
	cipher.md.o \
	cipher.pubkey.o \
	cipher.rmd160.o \
	cipher.rsa.o \
	mpi.mpi \
	zlib.zlib

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
	$(LINK) -aof $(CIPHER_OBJS) -o cipher.cipher

intl.gettext: $(GETTEXT_OBJS)
	$(LINK) -aof $(GETTEXT_OBJS) -o intl.gettext

mpi.mpi: $(MPI_OBJS)
	$(LINK) -aof $(MPI_OBJS) -o mpi.mpi

tools.gpgsplit: tools.o.gpgsplit util.util intl.gettext
	$(LINK) $(LD_FLAGS) tools.o.gpgsplit util.util intl.gettext -o tools.gpgsplit

util.util: $(UTIL_OBJS)
	$(LINK) -aof $(UTIL_OBJS) -o util.util

zlib.zlib: $(ZLIB_OBJS)
	$(LINK) -aof zlib.o.* -o zlib.zlib

g10.gpg: $(G10_OBJS) cipher.o.idea cipher.cipher intl.gettext mpi.mpi util.util zlib.zlib BUILD
	$(LINK) $(G10_OBJS) $(LD_FLAGS) cipher.o.idea cipher.cipher intl.gettext mpi.mpi util.util zlib.zlib -o g10.gpg
	-copy g10.gpg ADFS::A5.$.tmp.!GnuPG.gpg ~CFR~V

g10.gpgv: $(GPGV_OBJS) intl.gettext BUILD
	$(LINK) $(GPGV_OBJS) intl.gettext $(LD_FLAGS) -o g10.gpgv
	-copy g10.gpgv ADFS::A5.$.tmp.!GnuPG.gpgv ~CFR~V

g10.gpgpart: $(G10_OBJS) cipher.cipher intl.gettext mpi.mpi util.util zlib.zlib BUILD
	drlink -aof $(G10_OBJS) $(LD_FLAGS) cipher.cipher intl.gettext mpi.mpi util.util zlib.zlib -o g10.gpgpart

select-idea-src:
	-copy distrib.idea-addon.cipher.c.idea cipher.c.idea ~CF~NR~V
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o cipher.o.idea cipher.c.idea

select-gpl-src:
	-copy distrib.non-idea.cipher.c.idea cipher.c.idea ~CF~NR~V
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o cipher.o.idea cipher.c.idea

distrib.gnupgsrc/zip: select-gpl-src
	-zip -9@ distrib.gnupgsrc/zip < distrib.resources.srcfiles

distrib.gnupg/zip: distrib.gpl-bin.!GnuPG.gpg distrib.gpl-bin.!GnuPG.gpgv select-gpl-src
	-copy distrib.resources.History distrib.gpl-bin.History ~CFR~V
	-copy distrib.resources.Upgrading distrib.gpl-bin.Upgrading ~CFR~V
	-copy distrib.resources.ReadMe_bin distrib.gpl-bin.!ReadMe1st ~CFR~V
	-copy distrib.resources.!GnuPG distrib.gpl-bin.!GnuPG ~CFR~V
	-copy distrib.resources.!GnuPGUser distrib.gpl-bin.!GnuPGUser ~CFR~V
	-copy distrib.resources.orig_docs distrib.gpl-bin.orig_docs ~CFR~V
	-dir distrib.gpl-bin
	-zip -r9 ^.gnupg/zip *
	-back

distrib.gnupgdev/zip: distrib.private.!GnuPG.gpg distrib.private.!GnuPG.gpgv select-idea-src
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

distrib.gnupgpart/zip: g10.gpgpart select-idea-src
	-copy distrib.resources.ReadMe_part distrib.part.!ReadMe1st ~CFR~V
	-copy g10.gpgpart distrib.part.g10.gpgpart ~CFR~V
	-dir distrib.part
	-zip -r9 ^.gnupgpart/zip *
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

distrib.private.!GnuPG.gpg: g10.gpg
	-copy g10.gpg distrib.private.!GnuPG.gpg ~CFR~V
	-squeeze distrib.private.!GnuPG.gpg

distrib.private.!GnuPG.gpgv: g10.gpgv
	-copy g10.gpgv distrib.private.!GnuPG.gpgv ~CFR~V
	-squeeze distrib.private.!GnuPG.gpgv

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

clean-version:
	-ifthere g10.o.armor then wipe g10.o.armor ~CFR~V
	-ifthere g10.o.encode then wipe g10.o.encode ~CFR~V
	-ifthere g10.o.g10 then wipe g10.o.g10 ~CFR~V
	-ifthere g10.o.gpgv then wipe g10.o.gpgv ~CFR~V
	-ifthere g10.o.keygen then wipe g10.o.keygen ~CFR~V
	-ifthere g10.o.sign then wipe g10.o.sign ~CFR~V
	-ifthere g10.gpg then wipe g10.gpg ~CFR~V
	-ifthere g10.gpgv then wipe g10.gpgv ~CFR~V
	-ifthere g10.gpgpart then wipe g10.gpgpart ~CFR~V

clean: clean-dist clean-cipher clean-intl clean-mpi clean-util clean-zlib clean-g10

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

g10.o.sign: BUILD
	$(CC) $(CC_FLAGS) $(DEPEND) -c -o g10.o.sign g10.c.sign

dev: clean-version
	$(MAKE) fast-dev

#egrep "^AC_INIT\(gnupg,.*\)$" < configure/ac { | sed "s/^AC_INIT(gnupg,\(.*\))$/\1/" }
fast-dev: BUILD
	setver configure/ac AC_INIT(gnupg, ) dev
	wipe distrib.private.!GnuPG.gpg* ~CFR~V
	$(MAKE) distrib.gnupgdev/zip
	ifthere <WebServe$ServeRoot>.private.gnupgdev/zip then wipe <WebServe$ServeRoot>.private.gnupgdev/zip ~CFR~V
	rename distrib.gnupgdev/zip <WebServe$ServeRoot>.private.gnupgdev/zip
	unset GnuPG$DevDefine
	unset GnuPG$Version

#egrep "^AC_INIT\(gnupg,.*\)$" < configure/ac { | sed "s/^AC_INIT(gnupg,\(.*\))$/\1/" }
dist: BUILD clean-version
	setver configure/ac AC_INIT(gnupg, ) dist
	wipe distrib.gpl-bin.!GnuPG.gpg* ~CFR~V
	$(MAKE) distrib.gnupg/zip
	$(MAKE) distrib.gnupgidea/zip
	$(MAKE) distrib.gnupgpart/zip
	wipe distrib.private.!GnuPG.gpg* ~CFR~V
	$(MAKE) distrib.gnupgdev/zip
	$(MAKE) distrib.gnupgsrc/zip
	$(MAKE) distrib.gnupgintl/zip
	$(MAKE) select-idea-src
	ifthere <WebServe$ServeRoot>.archives.gnupg/zip then wipe <WebServe$ServeRoot>.archives.gnupg/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.private.gnupgdev/zip then wipe <WebServe$ServeRoot>.private.gnupgdev/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupgidea/zip then wipe <WebServe$ServeRoot>.archives.gnupgidea/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupgpart/zip then wipe <WebServe$ServeRoot>.archives.gnupgpart/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupgsrc/zip then wipe <WebServe$ServeRoot>.archives.gnupgsrc/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.archives.gnupgintl/zip then wipe <WebServe$ServeRoot>.archives.gnupgintl/zip ~CFR~V
	ifthere <WebServe$ServeRoot>.gnupg_history/txt then wipe <WebServe$ServeRoot>.gnupg_history/txt ~CFR~V
	rename distrib.gnupgdev/zip <WebServe$ServeRoot>.private.gnupgdev/zip
	rename distrib.gnupg/zip <WebServe$ServeRoot>.archives.gnupg/zip
	rename distrib.gnupgidea/zip <WebServe$ServeRoot>.archives.gnupgidea/zip
	rename distrib.gnupgpart/zip <WebServe$ServeRoot>.archives.gnupgpart/zip
	rename distrib.gnupgsrc/zip <WebServe$ServeRoot>.archives.gnupgsrc/zip
	rename distrib.gnupgintl/zip <WebServe$ServeRoot>.archives.gnupgintl/zip
	copy distrib.resources.History <WebServe$ServeRoot>.gnupg_history/txt ~CFR~V
	unset GnuPG$DevDefine
	unset GnuPG$Version
	updatesigs <WebServe$ServeRoot>.archives --secring adfs::ap.$.secring/gpg

# Dynamic dependencies:
