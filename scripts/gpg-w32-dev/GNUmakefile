# Makefile - Makefile for speedo
# Copyright (C) 2008 g10 Code GmbH
# 
# This file is part of speedo.
# 
# speedo is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# speedo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# speedo builds gnupg-related packages from SVN and installs them in a
# user directory, thereby providing a non-obstrusive test environment.
# The build system is similar to that of gpg4win.  The following commands
# are supported:
#
# make all  or  make
#
# Builds all packages and installs them under playground/install.
# At the end, speedo prints commands that can be executed in the local shell
# to make use of the installed packages.
#
# make clean  or  make clean-PACKAGE
#
# Removes all packages or the package PACKAGE from the installation
# and build tree.  A subsequent make will rebuild these (and only
# these) packages.
#
# make report  or make report-PACKAGE
#
# Lists packages and versions.
#
# make dist
# 
# Create a development ZIP archive.


# --------

# The packages that should be built.  The order is also the build order.
speedo_spkgs = libgpg-error libgcrypt libassuan libksba gpgme

# For each package, the following variables can be defined:
#
# speedo_pkg_PACKAGE_svn: The SVN repository that should be built.
# Branches or specific revisions can also be specified.
#
# speedo_pkg_PACKAGE_tar: URL to the tar file that should be built.
# 
# Exactly one of the above variables is required.  Note that this
# version of speedo does not cache repositories or tar files, and does
# not test the integrity of the downloaded software.  If you care
# about this, you can also specify filenames to locally verified files.
# Filenames are differentiated from URLs by starting with a slash '/'.
#
# speedo_pkg_PACKAGE_configure: Extra arguments to configure.
#
# speedo_pkg_PACKAGE_make_args: Extra arguments to make.
#
# speedo_pkg_PACKAGE_make_args_inst: Extra arguments to make install.
#
# Note that you can override the defaults in this file in a local file
# "config.mk"

# Set this to "svn" or "release".
WHAT=release

ifeq ($(WHAT),svn)
  svnrep = svn://cvs.gnupg.org/
  speedo_pkg_libgpg_error_svn = $(svnrep)/libgpg-error/trunk
  speedo_pkg_libassuan_svn = $(svnrep)/libassuan/trunk
  speedo_pkg_libgcrypt_svn = $(svnrep)/libgcrypt/trunk
  speedo_pkg_libksba_svn = $(svnrep)/libksba/trunk
  speedo_pkg_gpgme_svn = $(svnrep)/gpgme/trunk
else
  pkgrep = ftp://ftp.gnupg.org/gcrypt
  speedo_pkg_libgpg_error_tar = $(pkgrep)/libgpg-error/libgpg-error-1.8.tar.bz2
  speedo_pkg_libassuan_tar = $(pkgrep)/libassuan/libassuan-2.0.0.tar.bz2
  speedo_pkg_libgcrypt_tar = $(pkgrep)/libgcrypt/libgcrypt-1.4.5.tar.bz2
  speedo_pkg_libksba_tar = $(pkgrep)/libksba/libksba-1.0.7.tar.bz2
  speedo_pkg_gpgme_tar = $(pkgrep)/gpgme/gpgme-1.3.0.tar.bz2
endif

speedo_pkg_gnupg_configure = --with-pinentry-pgm=$(idir)/bin/pinentry \
  --with-dirmngr-pgm=$(idir)/bin/dirmngr

speedo_pkg_dirmngr_configure = --localstatedir=/var --sysconfdir=/etc \
  --with-libgcrypt-prefix=$(idir) --with-gpg-error-prefix=$(idir) \
  --with-libassuan-prefix=$(idir) --with-libksba-prefix=$(idir)

speedo_pkg_gpgme_configure = --with-gpg=$(idir)/bin/gpg2	\
	--with-gpgsm=$(idir)/bin/gpgsm				\
	--with-gpgconf=$(idir)/bin/gpgconf

speedo_pkg_pinentry_configure = --disable-pinentry-qt4

speedo_pkg_libgcrypt_configure = --disable-static

speedo_pkg_libksba_configure = --disable-static


# ---------

all: all-speedo
	@echo export PATH=\"$(idir)/bin\":\$$PATH
	@echo export LD_LIBRARY_PATH=\"$(idir)/lib\":\$$LD_LIBRARY_PATH
	@echo hash -r

report: report-speedo

clean: clean-speedo


dist: all
	set -e; date=$$(date -u +%Y%m%d); pkgname=gpg-w32-dev-$$date; \
	rm -rf $$pkgname $${pkgname}.zip || true; \
	cp -rL playground/install $${pkgname}; \
	rm -r $${pkgname}/share/info || true; \
	mkdir -p $${pkgname}/share/doc/gpg-w32-dev ;\
	echo "Included versions:" > $${pkgname}/README.txt ; \
	echo ""                   >> $${pkgname}/README.txt ; \
	$(MAKE) --no-print-directory report \
              | awk '{print $$2}' >> $${pkgname}/README.txt ; \
	cp GNUmakefile speedo.mk $${pkgname}/README.txt \
                  $${pkgname}/share/doc/gpg-w32-dev/ ; \
	i586-mingw32msvc-strip $${pkgname}/bin/*.dll ; \
	zip -r9 $${pkgname}.zip $${pkgname} >/dev/null ; \
	rm -rf $$pkgname; \
	echo "$$pkgname.zip ready for distribution" >&2


speedo_build_list = $(speedo_spkgs)

-include config.mk
include speedo.mk
