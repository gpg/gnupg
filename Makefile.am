# Makefile.am - main makefile for GnuPG
#     	Copyright (C) 2001, 2004, 2010 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

# Location of the released tarball archives.  This is prefixed by
# the variable RELEASE_ARCHIVE in ~/.gnupg-autogen.rc.  For example:
# RELEASE_ARCHIVE=user@host:archive/tarballs
RELEASE_ARCHIVE_SUFFIX  = gnupg/v2.2
# The variable RELEASE_SIGNKEY in ~/.gnupg-autogen.rc is used
# to specify the key for signing.  For example:
# RELEASE_SIGNKEY=D8692123C4065DEA5E0F3AB5249B39D24F25E3B6


# Autoconf flags.
ACLOCAL_AMFLAGS = -I m4
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-gnupg-builddir-envvar \
  --enable-all-tests --enable-g13 \
  --enable-gpgtar --enable-wks-tools --disable-ntbtls

GITLOG_TO_CHANGELOG=gitlog-to-changelog

EXTRA_DIST = build-aux/config.rpath build-aux/potomo autogen.sh autogen.rc \
	     ChangeLog-2011 po/ChangeLog-2011 build-aux/ChangeLog-2011     \
	     VERSION README.GIT build-aux/gitlog-to-changelog              \
	     COPYING.GPL2 COPYING.LGPL21 COPYING.LGPL3      \
             COPYING.CC0 COPYING.other                      \
	     build-aux/git-log-fix build-aux/git-log-footer \
	     build-aux/getswdb.sh                           \
	     build-aux/speedo.mk                            \
             build-aux/speedo/zlib.pc			    \
             build-aux/speedo/w32/inst-options.ini	    \
             build-aux/speedo/w32/inst.nsi		    \
             build-aux/speedo/w32/pkg-copyright.txt	    \
             build-aux/speedo/w32/g4wihelp.c		    \
             build-aux/speedo/w32/pango.modules		    \
             build-aux/speedo/w32/gdk-pixbuf-loaders.cache  \
             build-aux/speedo/w32/exdll.h		    \
             build-aux/speedo/w32/exdll.c		    \
             build-aux/speedo/w32/README.txt		    \
             build-aux/speedo/w32/gnupg-logo-150x57.bmp	    \
             build-aux/speedo/w32/gnupg-logo-164x314.bmp    \
             build-aux/speedo/w32/wixlib.wxs                \
             build-aux/speedo/patches/atk-1.32.0.patch	    \
             build-aux/speedo/patches/libiconv-1.14.patch   \
             build-aux/speedo/patches/pango-1.29.4.patch    \
             build-aux/speedo/patches/gpgme-1.12.0.patch    \
             build-aux/speedo/patches/sqlite.patch


DISTCLEANFILES = g10defs.h

if BUILD_GPG
gpg = g10
else
gpg =
endif
if BUILD_GPGSM
sm = sm
else
sm =
endif
if BUILD_AGENT
agent = agent
else
agent =
endif
if BUILD_SCDAEMON
scd = scd
else
scd =
endif
if BUILD_G13
g13 = g13
else
g13 =
endif
if BUILD_DIRMNGR
dirmngr = dirmngr
else
dirmngr =
endif
if BUILD_DOC
doc = doc
else
doc =
endif
if DISABLE_TESTS
tests =
else
tests = tests
endif

SUBDIRS = m4 common regexp kbx \
          ${gpg} ${sm} ${agent} ${scd} ${g13} ${dirmngr} \
          tools po ${doc} ${tests}

dist_doc_DATA = README


dist-hook: gen-ChangeLog

distcheck-hook:
	set -e; ( \
	pref="#+macro: gnupg22_" ;\
	reldate="$$(date -u +%Y-%m-%d)" ;\
        echo "$${pref}ver  $(PACKAGE_VERSION)"  ;\
        echo "$${pref}date $${reldate}" ;\
        list='$(DIST_ARCHIVES)'; for i in $$list; do \
	  case "$$i" in *.tar.bz2) \
            echo "$${pref}size $$(wc -c <$$i|awk '{print int($$1/1024)}')k" ;\
	    echo "$${pref}sha1 $$(sha1sum <$$i|cut -d' ' -f1)" ;\
	    echo "$${pref}sha2 $$(sha256sum <$$i|cut -d' ' -f1)" ;;\
	  esac;\
	done ) | tee $(distdir).swdb


if HAVE_W32_SYSTEM
install-data-hook:
	set -e; \
	for i in $$($(top_srcdir)/build-aux/potomo \
                     --get-linguas $(top_srcdir)/po) ; do \
           $(MKDIR_P) "$(DESTDIR)$(localedir)/$$i/LC_MESSAGES" || true; \
           rm -f "$(DESTDIR)$(localedir)/$$i/LC_MESSAGES/gnupg2.mo" \
                                                 2>/dev/null || true; \
           $(top_srcdir)/build-aux/potomo $(top_srcdir)/po/$$i.po \
              "$(DESTDIR)$(localedir)/$$i/LC_MESSAGES/gnupg2.mo" ; \
	done
endif


gen_start_date = 2011-12-01T06:00:00
.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -e $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	    $(GITLOG_TO_CHANGELOG) --append-dot --tear-off		\
	    --amend=build-aux/git-log-fix 				\
	    --since=$(gen_start_date) ) > $(distdir)/cl-t;		\
          cat $(top_srcdir)/build-aux/git-log-footer >> $(distdir)/cl-t;  \
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi


stowinstall:
	$(MAKE) $(AM_MAKEFLAGS) install prefix=/usr/local/stow/gnupg

TESTS_ENVIRONMENT = \
	LC_ALL=C \
	EXEEXT=$(EXEEXT) \
	PATH=$(abs_top_builddir)/tests/gpgscm:$(PATH) \
	abs_top_srcdir=$(abs_top_srcdir) \
	objdir=$(abs_top_builddir) \
	GPGSCM_PATH=$(abs_top_srcdir)/tests/gpgscm

.PHONY: check-all release sign-release
check-all:
	$(TESTS_ENVIRONMENT) \
	  $(abs_top_builddir)/tests/gpgscm/gpgscm \
	  $(abs_srcdir)/tests/run-tests.scm $(TESTFLAGS) $(TESTS)

# Names of to help the release target.
RELEASE_NAME = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
RELEASE_W32_STEM_NAME = $(PACKAGE_TARNAME)-w32-$(PACKAGE_VERSION)

release:
	+(set -e;\
	 if [ "$(abs_top_builddir)" = "$(abs_top_srcdir)" ]; then \
           echo "error: build directory must not be the source directory" >&2;\
	   exit 2;\
         fi ;\
	 echo "/* Build started at $$(date -uIseconds) */" ;\
	 cd $(top_srcdir); \
	 ./autogen.sh --force; \
	 cd $(abs_top_builddir); \
	 rm -rf dist; mkdir dist ; cd dist ; \
         mkopt=""; \
	 if [ -n "$$CUSTOM_SWDB" ]; then \
            mkopt="CUSTOM_SWB=1"; \
	    x=$$(grep '^OVERRIDE_TARBALLS=' \
                 $$HOME/.gnupg-autogen.rc|cut -d= -f2);\
	    if [ -f "$$x/swdb.lst" ]; then \
	      echo "/* Copying swdb.lst from the overrides directory */"; \
              cp "$$x/swdb.lst" . ; \
              cp "$$x/swdb.lst.sig" . ; \
	    fi; \
	 fi; \
	 echo "/* Running configure */";\
	 $(abs_top_srcdir)/configure --enable-maintainer-mode; \
	 echo "/* Running make distcheck */";\
	 $(MAKE) distcheck TESTFLAGS=--parallel; \
	 echo "/* Unpacking release */";\
	 $(TAR) xjf $(RELEASE_NAME).tar.bz2 ;\
	 echo "/* Running $(MAKE) -f $(RELEASE_NAME)/build-aux/speedo.mk w32-release $$mkopt";\
	 $(MAKE) -f  $(RELEASE_NAME)/build-aux/speedo.mk w32-release $$mkopt;\
	 echo "/* Build finished at $$(date -uIseconds) */" ;\
         echo "/*" ;\
	 echo " * Please run the final step interactivly:" ;\
	 echo " *   make sign-release" ;\
	 echo " */" ;\
	) 2>&1 | tee "$(RELEASE_NAME).buildlog"

sign-release:
	 +(set -e; \
	  test $$(pwd | sed 's,.*/,,') = dist || cd dist; \
	  x=$$(grep '^RELEASE_ARCHIVE=' $$HOME/.gnupg-autogen.rc|cut -d= -f2);\
          if [ -z "$$x" ]; then \
             echo "error: RELEASE_ARCHIVE missing in ~/.gnupg-autogen.rc">&2; \
             exit 2;\
          fi;\
          myarchive="$$x/$(RELEASE_ARCHIVE_SUFFIX)";\
	  x=$$(grep '^RELEASE_SIGNKEY=' $$HOME/.gnupg-autogen.rc|cut -d= -f2);\
          if [ -z "$$x" ]; then \
             echo "error: RELEASE_SIGNKEY missing in ~/.gnupg-autogen.rc">&2; \
             exit 2;\
          fi;\
	  mysignkey="$$x";\
	  release_w32_name="$(RELEASE_W32_STEM_NAME)_$$(date -u +%Y%m%d)" ;\
	  files1="$(RELEASE_NAME).tar.bz2 \
                  $${release_w32_name}.tar.xz \
                  $${release_w32_name}.exe" ;\
	  files2="$(RELEASE_NAME).tar.bz2.sig \
		  $(RELEASE_NAME).swdb \
		  $(RELEASE_NAME).buildlog \
		  $${release_w32_name}.tar.xz.sig \
		  $${release_w32_name}.exe.sig    \
		  $${release_w32_name}.exe.swdb" ;\
	  files3="$${release_w32_name}.wixlib \
	          $${release_w32_name}.wixlib.sig"; \
	  $(MAKE) -f $(RELEASE_NAME)/build-aux/speedo.mk w32-sign-installer ;\
	  echo "/* Signing the source tarball ..." ;\
	  gpg -sbu $$mysignkey $(RELEASE_NAME).tar.bz2 ;\
	  echo "/* Signing the W32 source tarball ..." ;\
	  gpg -sbu $$mysignkey $${release_w32_name}.tar.xz ;\
	  echo "/* Signing the W32 installer ..." ;\
	  gpg -sbu $$mysignkey $${release_w32_name}.exe ;\
	  echo "/* Signing the Wixlib ..." ;\
	  gpg -sbu $$mysignkey $${release_w32_name}.wixlib ;\
	  cat $(RELEASE_NAME).swdb >swdb.snippet;\
	  echo '#+macro: gnupg22_branch  STABLE-BRANCH-2-2' >>swdb.snippet;\
	  cat  $${release_w32_name}.exe.swdb >>swdb.snippet;\
	  echo >>swdb.snippet ;\
	  sha1sum $${files1} >>swdb.snippet ;\
          cat "../$(RELEASE_NAME).buildlog" swdb.snippet \
               | gzip >$(RELEASE_NAME).buildlog ;\
          echo "Release created - copying it to the archive ..." ;\
	  scp -p $${files1} $${files2} $${files3} $$myarchive/ \
	    || echo "/* Error copying files to the archive - ignored */" ;\
	  echo '/*' ;\
	  echo ' * All done; for checksums see dist/swdb.snippet' ;\
	  echo ' */' ;\
         )
