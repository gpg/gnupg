# speedo.mk - Speedo rebuilds speedily.
# Copyright (C) 2008, 2014, 2019 g10 Code GmbH
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

# speedo builds gnupg-related packages from GIT and installs them in a
# user directory, thereby providing a non-obstrusive test environment.
# speedo does only work with GNU make.  The build system is similar to
# that of gpg4win.  The following commands are supported:
#
#   make -f speedo.mk all  pkg2rep=/dir/with/tarballs
# or
#   make -f speedo.mk
#
# Builds all packages and installs them under PLAY/inst.  At the end,
# speedo prints commands that can be executed in the local shell to
# make use of the installed packages.
#
#   make -f speedo.mk clean
# or
#   make -f speedo.mk clean-PACKAGE
#
# Removes all packages or the package PACKAGE from the installation
# and build tree.  A subsequent make will rebuild these (and only
# these) packages.
#
#   make -f speedo.mk report
# or
#   make -f speedo.mk report-PACKAGE
#
# Lists packages and versions.
#
# The information reyured to sign the tarballs and binaries
# are expected in the developer specific file ~/.gnupg-autogen.rc".
# Here is an example:
#--8<---------------cut here---------------start------------->8---
# # Location of the released tarball archives.  Note that this is an
# # internal archive and before uploading this to the public server,
# # manual tests should be run and the git release tagged and pushed.
# # This is greped by the Makefile.
# RELEASE_ARCHIVE=foo@somehost:tarball-archive
#
# # The key used to sign the released sources.
# # This is greped by the Makefile.
# RELEASE_SIGNKEY=6DAA6E64A76D2840571B4902528897B826403ADA
#
# # For signing Windows binaries we need to employ a Windows machine.
# # We connect to this machine via ssh and take the connection
# # parameters via .ssh/config. For example a VM could be specified
# # like this:
# #
# #   Host authenticode-signhost
# #        HostName localhost
# #        Port 27042
# #        User gpgsign
# #
# # Depending on the used token it might be necessary to allow single
# # signon and unlock the token before running the make.  The following
# # variable references this entry.  This is greped by the Makefile.
# AUTHENTICODE_SIGNHOST=authenticode-signhost
#
# # The name of the signtool as used on Windows.
# # This is greped by the Makefile.
# AUTHENTICODE_TOOL="C:\Program Files (x86)\Windows Kits\10\bin\signtool.exe"
#
# # To use osslsigncode the follwing entries are required and
# # an empty string must be given for AUTHENTICODE_SIGNHOST.
# # They are greped by the Makefile.
# AUTHENTICODE_KEY=/home/foo/.gnupg/my-authenticode-key.p12
# AUTHENTICODE_CERTS=/home/foo/.gnupg/my-authenticode-certs.pem
#
# If a tarball has not been published while building a release it
# may be stored in a directory specified by:
# OVERRIDE_TARBALLS=/home/foo/override-tarballs
#--8<---------------cut here---------------end--------------->8---


# We need to know our own name.
SPEEDO_MK := $(realpath $(lastword $(MAKEFILE_LIST)))

.PHONY : help native native-gui w32-installer w32-source w32-wixlib
.PHONY :      git-native git-native-gui git-w32-installer git-w32-source
.PHONY :      this-native this-native-gui this-w32-installer this-w32-source

help:
	@echo 'usage: make -f speedo.mk TARGET'
	@echo '       with TARGET being one of:'
	@echo '  help               This help'
	@echo '  native             Native build of the GnuPG core'
	@echo '  native-gui         Ditto but with pinentry and GPA'
	@echo '  w32-installer      Build a Windows installer'
	@echo '  w32-source         Pack a source archive'
	@echo '  w32-release        Build a Windows release'
	@echo '  w32-wixlib         Build a wixlib for MSI packages'
	@echo '  w32-sign-installer Sign the installer'
	@echo
	@echo 'You may append INSTALL_PREFIX=<dir> for native builds.'
	@echo 'Prepend TARGET with "git-" to build from GIT repos.'
	@echo 'Prepend TARGET with "this-" to build from the source tarball.'
	@echo 'Use STATIC=1 to build with statically linked libraries.'
	@echo 'Use SELFCHECK=0 for a non-released version.'
	@echo 'Use CUSTOM_SWDB=1 for an already downloaded swdb.lst.'
	@echo 'Use WIXPREFIX to provide the WIX binaries for the MSI package.'
	@echo '    Using WIX also requires wine with installed wine mono.'
	@echo '    See help-wixlib for more information'

help-wixlib:
	@echo 'The buildsystem can create a wixlib to build MSI packages.'
	@echo ''
	@echo 'On debian install the packages "wine"'
	@echo '  apt-get install wine'
	@echo ''
	@echo 'Download the wine-mono msi:'
	@echo '  https://dl.winehq.org/wine/wine-mono/'
	@echo ''
	@echo 'Install it:'
	@echo '  wine msiexec /i ~/Downloads/wine-mono-4.9.4.msi'
	@echo ''
	@echo 'Download the wix toolset binary zip from:'
	@echo '  https://github.com/wixtoolset/wix3/releases'
	@echo 'The default folder searches for ~/w32root/wixtools'
	@echo 'Alternative locations can be passed by WIXPREFIX variable'
	@echo '  unzip -d ~/w32root/wixtools ~/Downloads/wix311-binaries.zip'
	@echo ''
	@echo 'Afterwards w32-release will build also a wixlib.'

# NB: we can't use +$(MAKE) here because we would need to define the
# dependencies of our packages.  This does not make much sense given that
# we have a clear order in how they are build and concurrent builds
# would anyway clutter up the logs.
SPEEDOMAKE := $(MAKE) -f $(SPEEDO_MK) UPD_SWDB=1

native: check-tools
	$(SPEEDOMAKE) TARGETOS=native WHAT=release WITH_GUI=0 all

git-native: check-tools
	$(SPEEDOMAKE) TARGETOS=native WHAT=git     WITH_GUI=0 all

this-native: check-tools
	$(SPEEDOMAKE) TARGETOS=native WHAT=this    WITH_GUI=0 all

native-gui: check-tools
	$(SPEEDOMAKE) TARGETOS=native WHAT=release WITH_GUI=1 all

git-native-gui: check-tools
	$(SPEEDOMAKE) TARGETOS=native WHAT=git     WITH_GUI=1 all

this-native-gui: check-tools
	$(SPEEDOMAKE) TARGETOS=native WHAT=this    WITH_GUI=1 all

w32-installer: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=release WITH_GUI=0 installer

git-w32-installer: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=git     WITH_GUI=0 installer

this-w32-installer: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=this    WITH_GUI=0 \
	                                           CUSTOM_SWDB=1 installer
w32-wixlib: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=release WITH_GUI=0 wixlib

git-w32-wixlib: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=git     WITH_GUI=0 wixlib

this-w32-wixlib: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=this    WITH_GUI=0 \
	                                           CUSTOM_SWDB=1 wixlib

w32-source: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=release WITH_GUI=0 dist-source

git-w32-source: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=git     WITH_GUI=0 dist-source

this-w32-source: check-tools
	$(SPEEDOMAKE) TARGETOS=w32    WHAT=this    WITH_GUI=0 \
	                                           CUSTOM_SWDB=1 dist-source

w32-release: check-tools
	$(SPEEDOMAKE) TARGETOS=w32 WHAT=release    WITH_GUI=0 SELFCHECK=0 \
                                                   installer-from-source

w32-sign-installer: check-tools
	$(SPEEDOMAKE) TARGETOS=w32 WHAT=release    WITH_GUI=0 SELFCHECK=0 \
                                                   sign-installer

w32-release-offline: check-tools
	$(SPEEDOMAKE) TARGETOS=w32 WHAT=release    WITH_GUI=0 SELFCHECK=0 \
	  CUSTOM_SWDB=1 pkgrep=${HOME}/b pkg10rep=${HOME}/b  \
	  installer-from-source


# Set this to "git" to build from git,
#          to "release" from tarballs,
#          to "this" from the unpacked sources.
WHAT=git

# Set target to "native" or "w32"
TARGETOS=

# Set to 1 to build the GUI tools
WITH_GUI=0

# Set to 1 to use a pre-installed swdb.lst instead of the online version.
CUSTOM_SWDB=0

# Set to 1 to really download the swdb.
UPD_SWDB=0

# Set to 0 to skip the GnuPG version self-check
SELFCHECK=1

# Set to 1 to build with statically linked libraries.
STATIC=0

# Set to the location of the directory with tarballs of
# external packages.
TARBALLS=$(shell pwd)/../tarballs

#  Number of parallel make jobs in each package
MAKE_J=3

# Name to use for the w32 installer and sources
INST_NAME=gnupg-w32

# Use this to override the installaion directory for native builds.
INSTALL_PREFIX=none

# Set this to the location of wixtools
WIXPREFIX=$(shell readlink -f ~/w32root/wixtools)

# Read signing information from ~/.gnupg-autogen.rc
define READ_AUTOGEN_template
$(1) = $$(shell grep '^$(1)=' $$$$HOME/.gnupg-autogen.rc|cut -d= -f2)
endef
$(eval $(call READ_AUTOGEN_template,AUTHENTICODE_SIGNHOST))
$(eval $(call READ_AUTOGEN_template,AUTHENTICODE_TOOL))
$(eval $(call READ_AUTOGEN_template,AUTHENTICODE_KEY))
$(eval $(call READ_AUTOGEN_template,AUTHENTICODE_CERTS))
$(eval $(call READ_AUTOGEN_template,OSSLSIGNCODE))
$(eval $(call READ_AUTOGEN_template,OSSLPKCS11ENGINE))
$(eval $(call READ_AUTOGEN_template,SCUTEMODULE))
$(eval $(call READ_AUTOGEN_template,OVERRIDE_TARBALLS))

# All files given in AUTHENTICODE_FILES are signed before
# they are put into the installer.
AUTHENTICODE_FILES= \
                    dirmngr.exe               \
                    dirmngr_ldap.exe          \
                    gpg-agent.exe             \
                    gpg-connect-agent.exe     \
                    gpg-preset-passphrase.exe \
                    gpg-check-pattern.exe     \
                    gpg-wks-client.exe        \
                    gpg.exe                   \
                    gpgconf.exe               \
                    gpgconf-w32.exe           \
                    gpgme-w32spawn.exe        \
                    gpgsm.exe                 \
                    gpgtar.exe                \
                    gpgv.exe                  \
                    libassuan-0.dll           \
                    libgcrypt-20.dll          \
                    libgpg-error-0.dll        \
                    libgpgme-11.dll           \
                    libksba-8.dll             \
                    libnpth-0.dll             \
                    libsqlite3-0.dll          \
                    pinentry-w32.exe          \
                    scdaemon.exe	      \
                    zlib1.dll



# Directory names.
# They must be absolute, as we switch directories pretty often.
root := $(shell pwd)/PLAY
sdir := $(root)/src
bdir := $(root)/build
bdir6:= $(root)/build-w64
ifeq ($(INSTALL_PREFIX),none)
idir := $(root)/inst
else
idir := $(abspath $(INSTALL_PREFIX))
endif
idir6:= $(root)/inst-w64
stampdir := $(root)/stamps
topsrc := $(shell cd $(dir $(SPEEDO_MK)).. && pwd)
auxsrc := $(topsrc)/build-aux/speedo
patdir := $(topsrc)/build-aux/speedo/patches
w32src := $(topsrc)/build-aux/speedo/w32

# =====BEGIN LIST OF PACKAGES=====
# The packages that should be built.  The order is also the build order.
# Fixme: Do we need to build pkg-config for cross-building?

speedo_spkgs  = \
	libgpg-error npth libgcrypt

ifeq ($(TARGETOS),w32)
speedo_spkgs += \
	zlib bzip2 sqlite
ifeq ($(WITH_GUI),1)
speedo_spkgs += gettext libiconv
endif
endif

speedo_spkgs += \
	libassuan libksba

ifeq ($(TARGETOS),w32)
speedo_spkgs += \
	ntbtls
endif

speedo_spkgs += \
	gnupg

ifeq ($(TARGETOS),w32)
ifeq ($(WITH_GUI),1)
speedo_spkgs += \
	libffi glib pkg-config
endif
endif

ifeq ($(STATIC),0)
speedo_spkgs += \
	gpgme
endif

ifeq ($(TARGETOS),w32)
ifeq ($(WITH_GUI),1)
speedo_spkgs += \
	libpng \
	gdk-pixbuf atk pixman cairo pango gtk+
endif
endif

ifeq ($(TARGETOS),w32)

speedo_spkgs += pinentry
ifeq ($(WITH_GUI),1)
speedo_spkgs += gpa gpgex
endif

else

ifeq ($(WITH_GUI),1)
speedo_spkgs += pinentry gpa
endif

endif


# =====END LIST OF PACKAGES=====


# Packages which are additionally build for 64 bit Windows.  They are
# only used for gpgex and thus we need to build them only if we want
# a full installer.
speedo_w64_spkgs  =
ifeq ($(WITH_GUI),1)
speedo_w64_spkgs += libgpg-error libiconv gettext libassuan gpgex
endif

# Packages which use the gnupg autogen.sh build style
speedo_gnupg_style = \
	libgpg-error npth libgcrypt  \
	libassuan libksba ntbtls gnupg gpgme \
	pinentry gpa gpgex

# Packages which use only make and no build directory
speedo_make_only_style = \
	zlib bzip2

# Get the content of the software DB.
ifeq ($(CUSTOM_SWDB),1)
getswdb_options = --skip-download --skip-verify
else
getswdb_options =
endif
ifeq ($(SELFCHECK),0)
getswdb_options += --skip-selfcheck
endif
ifeq ($(UPD_SWDB),1)
SWDB := $(shell $(topsrc)/build-aux/getswdb.sh $(getswdb_options) && echo okay)
ifeq ($(strip $(SWDB)),)
ifneq ($(WHAT),git)
$(error Error getting GnuPG software version database)
endif
endif

# Version numbers of the released packages
gnupg_ver_this = $(shell cat $(topsrc)/VERSION)

gnupg_ver        := $(shell awk '$$1=="gnupg22_ver" {print $$2}' swdb.lst)

libgpg_error_ver := $(shell awk '$$1=="libgpg_error_ver" {print $$2}' swdb.lst)
libgpg_error_sha1:= $(shell awk '$$1=="libgpg_error_sha1" {print $$2}' swdb.lst)
libgpg_error_sha2:= $(shell awk '$$1=="libgpg_error_sha2" {print $$2}' swdb.lst)

npth_ver  := $(shell awk '$$1=="npth_ver" {print $$2}' swdb.lst)
npth_sha1 := $(shell awk '$$1=="npth_sha1" {print $$2}' swdb.lst)
npth_sha2 := $(shell awk '$$1=="npth_sha2" {print $$2}' swdb.lst)

libgcrypt_ver  := $(shell awk '$$1=="libgcrypt18_ver" {print $$2}' swdb.lst)
libgcrypt_sha1 := $(shell awk '$$1=="libgcrypt18_sha1" {print $$2}' swdb.lst)
libgcrypt_sha2 := $(shell awk '$$1=="libgcrypt18_sha2" {print $$2}' swdb.lst)

libassuan_ver  := $(shell awk '$$1=="libassuan_ver" {print $$2}' swdb.lst)
libassuan_sha1 := $(shell awk '$$1=="libassuan_sha1" {print $$2}' swdb.lst)
libassuan_sha2 := $(shell awk '$$1=="libassuan_sha2" {print $$2}' swdb.lst)

libksba_ver  := $(shell awk '$$1=="libksba_ver" {print $$2}' swdb.lst)
libksba_sha1 := $(shell awk '$$1=="libksba_sha1" {print $$2}' swdb.lst)
libksba_sha2 := $(shell awk '$$1=="libksba_sha2" {print $$2}' swdb.lst)

ntbtls_ver  := $(shell awk '$$1=="ntbtls_ver" {print $$2}' swdb.lst)
ntbtls_sha1 := $(shell awk '$$1=="ntbtls_sha1" {print $$2}' swdb.lst)
ntbtls_sha2 := $(shell awk '$$1=="ntbtls_sha2" {print $$2}' swdb.lst)

gpgme_ver  := $(shell awk '$$1=="gpgme_ver" {print $$2}' swdb.lst)
gpgme_sha1 := $(shell awk '$$1=="gpgme_sha1" {print $$2}' swdb.lst)
gpgme_sha2 := $(shell awk '$$1=="gpgme_sha2" {print $$2}' swdb.lst)

pinentry_ver  := $(shell awk '$$1=="pinentry_ver" {print $$2}' swdb.lst)
pinentry_sha1 := $(shell awk '$$1=="pinentry_sha1" {print $$2}' swdb.lst)
pinentry_sha2 := $(shell awk '$$1=="pinentry_sha2" {print $$2}' swdb.lst)

gpa_ver  := $(shell awk '$$1=="gpa_ver" {print $$2}' swdb.lst)
gpa_sha1 := $(shell awk '$$1=="gpa_sha1" {print $$2}' swdb.lst)
gpa_sha2 := $(shell awk '$$1=="gpa_sha2" {print $$2}' swdb.lst)

gpgex_ver  := $(shell awk '$$1=="gpgex_ver" {print $$2}' swdb.lst)
gpgex_sha1 := $(shell awk '$$1=="gpgex_sha1" {print $$2}' swdb.lst)
gpgex_sha2 := $(shell awk '$$1=="gpgex_sha2" {print $$2}' swdb.lst)

zlib_ver  := $(shell awk '$$1=="zlib_ver" {print $$2}' swdb.lst)
zlib_sha1 := $(shell awk '$$1=="zlib_sha1_gz" {print $$2}' swdb.lst)
zlib_sha2 := $(shell awk '$$1=="zlib_sha2_gz" {print $$2}' swdb.lst)

bzip2_ver  := $(shell awk '$$1=="bzip2_ver" {print $$2}' swdb.lst)
bzip2_sha1 := $(shell awk '$$1=="bzip2_sha1_gz" {print $$2}' swdb.lst)
bzip2_sha2 := $(shell awk '$$1=="bzip2_sha2_gz" {print $$2}' swdb.lst)

sqlite_ver  := $(shell awk '$$1=="sqlite_ver" {print $$2}' swdb.lst)
sqlite_sha1 := $(shell awk '$$1=="sqlite_sha1_gz" {print $$2}' swdb.lst)
sqlite_sha2 := $(shell awk '$$1=="sqlite_sha2_gz" {print $$2}' swdb.lst)


$(info Information from the version database)
$(info GnuPG ..........: $(gnupg_ver) (building $(gnupg_ver_this)))
$(info Libgpg-error ...: $(libgpg_error_ver))
$(info Npth ...........: $(npth_ver))
$(info Libgcrypt ......: $(libgcrypt_ver))
$(info Libassuan ......: $(libassuan_ver))
$(info Libksba ........: $(libksba_ver))
$(info Zlib ...........: $(zlib_ver))
$(info Bzip2 ..........: $(bzip2_ver))
$(info SQLite .........: $(sqlite_ver))
$(info NtbTLS .. ......: $(ntbtls_ver))
$(info GPGME ..........: $(gpgme_ver))
$(info Pinentry .......: $(pinentry_ver))
$(info GPA ............: $(gpa_ver))
$(info GpgEX.... ......: $(gpgex_ver))
endif

# Version number for external packages
pkg_config_ver = 0.23
libiconv_ver = 1.14
gettext_ver = 0.18.2.1
libffi_ver = 3.0.13
glib_ver = 2.34.3
libpng_ver = 1.4.12
gdk_pixbuf_ver = 2.26.5
atk_ver = 1.32.0
pango_ver = 1.29.4
pixman_ver = 0.32.4
cairo_ver = 1.12.16
gtk__ver = 2.24.17

# The GIT repository.  Using a local repo is much faster.
#gitrep = git://git.gnupg.org
gitrep = ${HOME}/s

# The tarball directories
pkgrep = https://gnupg.org/ftp/gcrypt
pkg10rep = ftp://ftp.g10code.com/g10code
pkg2rep = $(TARBALLS)

# For each package, the following variables can be defined:
#
# speedo_pkg_PACKAGE_git: The GIT repository that should be built.
# speedo_pkg_PACKAGE_gitref: The GIT revision to checkout
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

ifeq ($(WHAT),this)
else ifeq ($(WHAT),git)
  speedo_pkg_libgpg_error_git = $(gitrep)/libgpg-error
  speedo_pkg_libgpg_error_gitref = master
  speedo_pkg_npth_git = $(gitrep)/npth
  speedo_pkg_npth_gitref = master
  speedo_pkg_libassuan_git = $(gitrep)/libassuan
  speedo_pkg_libassuan_gitref = master
  speedo_pkg_libgcrypt_git = $(gitrep)/libgcrypt
  speedo_pkg_libgcrypt_gitref = master
  speedo_pkg_libksba_git = $(gitrep)/libksba
  speedo_pkg_libksba_gitref = master
  speedo_pkg_ntbtls_git = $(gitrep)/ntbtls
  speedo_pkg_ntbtls_gitref = master
  speedo_pkg_gpgme_git = $(gitrep)/gpgme
  speedo_pkg_gpgme_gitref = master
  speedo_pkg_pinentry_git = $(gitrep)/pinentry
  speedo_pkg_pinentry_gitref = master
  speedo_pkg_gpa_git = $(gitrep)/gpa
  speedo_pkg_gpa_gitref = master
  speedo_pkg_gpgex_git = $(gitrep)/gpgex
  speedo_pkg_gpgex_gitref = master
else ifeq ($(WHAT),release)
  speedo_pkg_libgpg_error_tar = \
	$(pkgrep)/libgpg-error/libgpg-error-$(libgpg_error_ver).tar.bz2
  speedo_pkg_npth_tar = \
	$(pkgrep)/npth/npth-$(npth_ver).tar.bz2
  speedo_pkg_libassuan_tar = \
	$(pkgrep)/libassuan/libassuan-$(libassuan_ver).tar.bz2
  speedo_pkg_libgcrypt_tar = \
	$(pkgrep)/libgcrypt/libgcrypt-$(libgcrypt_ver).tar.bz2
  speedo_pkg_libksba_tar = \
	$(pkgrep)/libksba/libksba-$(libksba_ver).tar.bz2
  speedo_pkg_ntbtls_tar = \
	$(pkgrep)/ntbtls/ntbtls-$(ntbtls_ver).tar.bz2
  speedo_pkg_gpgme_tar = \
	$(pkgrep)/gpgme/gpgme-$(gpgme_ver).tar.bz2
  speedo_pkg_pinentry_tar = \
	$(pkgrep)/pinentry/pinentry-$(pinentry_ver).tar.bz2
  speedo_pkg_gpa_tar = \
	$(pkgrep)/gpa/gpa-$(gpa_ver).tar.bz2
  speedo_pkg_gpgex_tar = \
	$(pkg10rep)/gpgex/gpgex-$(gpgex_ver).tar.bz2
else
  $(error invalid value for WHAT (use on of: git release this))
endif

speedo_pkg_pkg_config_tar = $(pkg2rep)/pkg-config-$(pkg_config_ver).tar.gz
speedo_pkg_zlib_tar       = $(pkgrep)/zlib/zlib-$(zlib_ver).tar.gz
speedo_pkg_bzip2_tar      = $(pkgrep)/bzip2/bzip2-$(bzip2_ver).tar.gz
speedo_pkg_sqlite_tar     = $(pkgrep)/sqlite/sqlite-autoconf-$(sqlite_ver).tar.gz
speedo_pkg_libiconv_tar   = $(pkg2rep)/libiconv-$(libiconv_ver).tar.gz
speedo_pkg_gettext_tar    = $(pkg2rep)/gettext-$(gettext_ver).tar.gz
speedo_pkg_libffi_tar     = $(pkg2rep)/libffi-$(libffi_ver).tar.gz
speedo_pkg_glib_tar       = $(pkg2rep)/glib-$(glib_ver).tar.xz
speedo_pkg_libpng_tar     = $(pkg2rep)/libpng-$(libpng_ver).tar.bz2
speedo_pkg_gdk_pixbuf_tar = $(pkg2rep)/gdk-pixbuf-$(gdk_pixbuf_ver).tar.xz
speedo_pkg_atk_tar        = $(pkg2rep)/atk-$(atk_ver).tar.bz2
speedo_pkg_pango_tar      = $(pkg2rep)/pango-$(pango_ver).tar.bz2
speedo_pkg_pixman_tar     = $(pkg2rep)/pixman-$(pixman_ver).tar.gz
speedo_pkg_cairo_tar      = $(pkg2rep)/cairo-$(cairo_ver).tar.xz
speedo_pkg_gtk__tar       = $(pkg2rep)/gtk+-$(gtk__ver).tar.xz


#
# Package build options
#

speedo_pkg_npth_configure = --enable-static

speedo_pkg_libgpg_error_configure = --enable-static --enable-install-gpg-error-config
speedo_pkg_w64_libgpg_error_configure = --enable-static --enable-install-gpg-error-config

speedo_pkg_libassuan_configure = --enable-static
speedo_pkg_w64_libassuan_configure = --enable-static

speedo_pkg_libgcrypt_configure = --disable-static

speedo_pkg_libksba_configure = --disable-static

speedo_pkg_ntbtls_configure = --enable-static


ifeq ($(STATIC),1)
speedo_pkg_npth_configure += --disable-shared

speedo_pkg_libgpg_error_configure += --disable-shared

speedo_pkg_libassuan_configure += --disable-shared

speedo_pkg_libgcrypt_configure += --disable-shared

speedo_pkg_libksba_configure += --disable-shared
endif

# For now we build ntbtls only static
speedo_pkg_ntbtls_configure = --disable-shared

ifeq ($(TARGETOS),w32)
speedo_pkg_gnupg_configure = \
        --disable-g13 --enable-ntbtls
else
speedo_pkg_gnupg_configure = --disable-g13 --enable-wks-tools
endif
speedo_pkg_gnupg_extracflags = -g

# Create the version info files only for W32 so that they won't get
# installed if for example INSTALL_PREFIX=/usr/local is used.
ifeq ($(TARGETOS),w32)
define speedo_pkg_gnupg_post_install
(set -e; \
 sed -n  's/.*PACKAGE_VERSION "\(.*\)"/\1/p' config.h >$(idir)/INST_VERSION; \
 sed -n  's/.*W32INFO_VI_PRODUCTVERSION \(.*\)/\1/p' common/w32info-rc.h \
    |sed 's/,/./g' >$(idir)/INST_PROD_VERSION )
endef
endif

# The LDFLAGS is needed for -lintl for glib.
ifeq ($(WITH_GUI),1)
speedo_pkg_gpgme_configure = \
	--enable-static --enable-w32-glib  \
	--with-gpg-error-prefix=$(idir) \
	LDFLAGS=-L$(idir)/lib
else
speedo_pkg_gpgme_configure = \
	--disable-static --disable-w32-glib \
	--with-gpg-error-prefix=$(idir) \
	LDFLAGS=-L$(idir)/lib
endif


ifeq ($(TARGETOS),w32)
speedo_pkg_pinentry_configure = --disable-pinentry-gtk2
else
speedo_pkg_pinentry_configure = --enable-pinentry-gtk2
endif
speedo_pkg_pinentry_configure += \
        --disable-pinentry-qt5   \
        --disable-pinentry-qt    \
	--disable-pinentry-fltk  \
	--disable-pinentry-tty   \
	CPPFLAGS=-I$(idir)/include   \
	LDFLAGS=-L$(idir)/lib        \
	CXXFLAGS=-static-libstdc++


speedo_pkg_gpa_configure = \
        --with-libiconv-prefix=$(idir) --with-libintl-prefix=$(idir) \
        --with-gpgme-prefix=$(idir) --with-zlib=$(idir) \
        --with-libassuan-prefix=$(idir) --with-gpg-error-prefix=$(idir)

speedo_pkg_gpgex_configure = \
	--with-gpg-error-prefix=$(idir) \
	--with-libassuan-prefix=$(idir) \
	--enable-gpa-only

speedo_pkg_w64_gpgex_configure = \
	--with-gpg-error-prefix=$(idir6) \
	--with-libassuan-prefix=$(idir6) \
	--enable-gpa-only


#
# External packages
#

# gcc 10.2 takes __udivdi3 from the exception handler DLL and thus
# requires it.  This is a regression from gcc 8.3 and earlier.  To fix
# this we need to pass -static-libgcc.
ifeq ($(TARGETOS),w32)
speedo_pkg_zlib_make_args = \
        -fwin32/Makefile.gcc PREFIX=$(host)- IMPLIB=libz.dll.a \
         LDFLAGS=-static-libgcc

speedo_pkg_zlib_make_args_inst = \
        -fwin32/Makefile.gcc \
        BINARY_PATH=$(idir)/bin INCLUDE_PATH=$(idir)/include \
	LIBRARY_PATH=$(idir)/lib SHARED_MODE=1 IMPLIB=libz.dll.a

# Zlib needs some special magic to generate a libtool file.
# We also install the pc file here.
define speedo_pkg_zlib_post_install
(set -e; mkdir $(idir)/lib/pkgconfig || true;	        \
cp $(auxsrc)/zlib.pc $(idir)/lib/pkgconfig/; 	        \
cd $(idir);						\
echo "# Generated by libtool" > lib/libz.la		\
echo "dlname='../bin/zlib1.dll'" >> lib/libz.la;	\
echo "library_names='libz.dll.a'" >> lib/libz.la;	\
echo "old_library='libz.a'" >> lib/libz.la;		\
echo "dependency_libs=''" >> lib/libz.la;		\
echo "current=1" >> lib/libz.la;			\
echo "age=2" >> lib/libz.la;				\
echo "revision=5" >> lib/libz.la;			\
echo "installed=yes" >> lib/libz.la;			\
echo "shouldnotlink=no" >> lib/libz.la;			\
echo "dlopen=''" >> lib/libz.la;			\
echo "dlpreopen=''" >> lib/libz.la;			\
echo "libdir=\"$(idir)/lib\"" >> lib/libz.la)
endef

endif

ifeq ($(TARGETOS),w32)
speedo_pkg_bzip2_make_args = \
	CC="$(host)-gcc" AR="$(host)-ar" RANLIB="$(host)-ranlib"

speedo_pkg_bzip2_make_args_inst = \
	PREFIX=$(idir) CC="$(host)-gcc" AR="$(host)-ar" RANLIB="$(host)-ranlib"
endif

speedo_pkg_w64_libiconv_configure = \
	--enable-shared=no --enable-static=yes

speedo_pkg_gettext_configure = \
	--with-lib-prefix=$(idir) --with-libiconv-prefix=$(idir) \
        CPPFLAGS=-I$(idir)/include LDFLAGS=-L$(idir)/lib
speedo_pkg_w64_gettext_configure = \
	--with-lib-prefix=$(idir) --with-libiconv-prefix=$(idir) \
        CPPFLAGS=-I$(idir6)/include LDFLAGS=-L$(idir6)/lib
speedo_pkg_gettext_extracflags = -O2
# We only need gettext-runtime and there is sadly no top level
# configure option for this
speedo_pkg_gettext_make_dir = gettext-runtime


speedo_pkg_glib_configure = \
	--disable-modular-tests \
	--with-libiconv=gnu \
	CPPFLAGS=-I$(idir)/include \
	LDFLAGS=-L$(idir)/lib \
	CCC=$(host)-g++ \
        LIBFFI_CFLAGS=-I$(idir)/lib/libffi-$(libffi_ver)/include \
	LIBFFI_LIBS=\"-L$(idir)/lib -lffi\"
ifeq ($(TARGETOS),w32)
speedo_pkg_glib_extracflags = -march=i486
endif

ifeq ($(TARGETOS),w32)
speedo_pkg_libpng_configure = \
	CPPFLAGS=\"-I$(idir)/include -DPNG_BUILD_DLL\" \
	LDFLAGS=\"-L$(idir)/lib\" LIBPNG_DEFINES=\"-DPNG_BUILD_DLL\"
else
speedo_pkg_libpng_configure = \
        CPPFLAGS=\"-I$(idir)/include\" \
        LDFLAGS=\"-L$(idir)/lib\"
endif

ifneq ($(TARGETOS),w32)
speedo_pkg_gdk_pixbuf_configure = --without-libtiff --without-libjpeg
endif

speedo_pkg_pixman_configure = \
	CPPFLAGS=-I$(idir)/include \
	LDFLAGS=-L$(idir)/lib

ifeq ($(TARGETOS),w32)
speedo_pkg_cairo_configure = \
	--disable-qt --disable-ft --disable-fc \
	--enable-win32 --enable-win32-font \
	CPPFLAGS=-I$(idir)/include \
	LDFLAGS=-L$(idir)/lib
else
speedo_pkg_cairo_configure = \
	--disable-qt \
        CPPFLAGS=-I$(idir)/include \
        LDFLAGS=-L$(idir)/lib
endif

speedo_pkg_pango_configure = \
	--disable-gtk-doc  \
	CPPFLAGS=-I$(idir)/include \
	LDFLAGS=-L$(idir)/lib

speedo_pkg_gtk__configure = \
	--disable-cups \
	CPPFLAGS=-I$(idir)/include \
	LDFLAGS=-L$(idir)/lib


# ---------

all: all-speedo

report: report-speedo

clean: clean-speedo

ifeq ($(TARGETOS),w32)
STRIP = i686-w64-mingw32-strip
else
STRIP = strip
endif
W32CC = i686-w64-mingw32-gcc

-include config.mk

#
#  The generic speedo code
#

MKDIR=mkdir
MAKENSIS=makensis
WINE=wine

SHA1SUM := $(shell $(topsrc)/build-aux/getswdb.sh --find-sha1sum)
ifeq ($(SHA1SUM),false)
$(error The sha1sum tool is missing)
endif
SHA2SUM := $(shell $(topsrc)/build-aux/getswdb.sh --find-sha256sum)
ifeq ($(SHA2SUM),false)
$(error The sha256sum tool is missing)
endif


BUILD_ISODATE=$(shell date -u +%Y-%m-%d)
BUILD_DATESTR=$(subst -,,$(BUILD_ISODATE))

# The next two macros will work only after gnupg has been build.
ifeq ($(TARGETOS),w32)
INST_VERSION=$(shell head -1 $(idir)/INST_VERSION)
INST_PROD_VERSION=$(shell head -1 $(idir)/INST_PROD_VERSION)
endif

# List with packages
speedo_build_list = $(speedo_spkgs)
speedo_w64_build_list = $(speedo_w64_spkgs)

# To avoid running external commands during the read phase (":=" style
# assignments), we check that the targetos has been given
ifneq ($(TARGETOS),)

# Determine build and host system
build := $(shell $(topsrc)/autogen.sh --silent --print-build)
ifeq ($(TARGETOS),w32)
  speedo_autogen_buildopt := --build-w32
  speedo_autogen_buildopt6 := --build-w64
  host := $(shell $(topsrc)/autogen.sh --silent --print-host --build-w32)
  host6:= $(shell $(topsrc)/autogen.sh --silent --print-host --build-w64)
  speedo_host_build_option := --host=$(host) --build=$(build)
  speedo_host_build_option6 := --host=$(host6) --build=$(build)
  speedo_w32_cflags := -mms-bitfields
else
  speedo_autogen_buildopt :=
  host :=
  speedo_host_build_option :=
  speedo_w32_cflags :=
endif

ifeq ($(MAKE_J),)
  speedo_makeopt=
else
  speedo_makeopt=-j$(MAKE_J)
endif

# End non-empty TARGETOS
endif



# The playground area is our scratch area, where we unpack, build and
# install the packages.
$(stampdir)/stamp-directories:
	$(MKDIR) -p $(root)
	$(MKDIR) -p $(stampdir)
	$(MKDIR) -p $(sdir)
	$(MKDIR) -p $(bdir)
	$(MKDIR) -p $(idir)
ifeq ($(TARGETOS),w32)
	$(MKDIR) -p $(bdir6)
	$(MKDIR) -p $(idir6)
endif
	touch $(stampdir)/stamp-directories


# Frob the name $1 by converting all '-' and '+' characters to '_'.
define FROB_macro
$(subst +,_,$(subst -,_,$(1)))
endef

# Get the variable $(1) (which may contain '-' and '+' characters).
define GETVAR
$($(call FROB_macro,$(1)))
endef

# Set a couple of common variables.
define SETVARS
        pkg="$(1)";                                                     \
        git="$(call GETVAR,speedo_pkg_$(1)_git)";                       \
        gitref="$(call GETVAR,speedo_pkg_$(1)_gitref)";                 \
        tar="$(call GETVAR,speedo_pkg_$(1)_tar)";                       \
        ver="$(call GETVAR,$(1)_ver)";                                  \
        sha2="$(call GETVAR,$(1)_sha2)";                                \
        sha1="$(call GETVAR,$(1)_sha1)";                                \
        pkgsdir="$(sdir)/$(1)";                                         \
        if [ "$(1)" = "gnupg" ]; then                                   \
          git='';                                                       \
          gitref='';                                                    \
          tar='';                                                       \
          pkgsdir="$(topsrc)";                                          \
        fi;                                                             \
        pkgbdir="$(bdir)/$(1)";                                         \
        pkgcfg="$(call GETVAR,speedo_pkg_$(1)_configure)";              \
        tmp="$(speedo_w32_cflags)                                       \
             $(call GETVAR,speedo_pkg_$(1)_extracflags)";               \
        if [ x$$$$(echo "$$$$tmp" | tr -d '[:space:]')x != xx ]; then   \
          pkgextracflags="CFLAGS=\"$$$$tmp\"";                          \
        else                                                            \
          pkgextracflags=;                                              \
        fi;                                                             \
        pkgmkdir="$(call GETVAR,speedo_pkg_$(1)_make_dir)";             \
        pkgmkargs="$(call GETVAR,speedo_pkg_$(1)_make_args)";           \
        pkgmkargs_inst="$(call GETVAR,speedo_pkg_$(1)_make_args_inst)"; \
        pkgmkargs_uninst="$(call GETVAR,speedo_pkg_$(1)_make_args_uninst)"; \
        export PKG_CONFIG="/usr/bin/pkg-config";                        \
        export PKG_CONFIG_PATH="$(idir)/lib/pkgconfig";                 \
        [ "$(TARGETOS)" != native ] && export PKG_CONFIG_LIBDIR="";     \
        export SYSROOT="$(idir)";                                       \
        export PATH="$(idir)/bin:$${PATH}";                             \
        export LD_LIBRARY_PATH="$(idir)/lib:$${LD_LIBRARY_PATH}"
endef

define SETVARS_W64
        pkg="$(1)";                                                     \
        git="$(call GETVAR,speedo_pkg_$(1)_git)";                       \
        gitref="$(call GETVAR,speedo_pkg_$(1)_gitref)";                 \
        tar="$(call GETVAR,speedo_pkg_$(1)_tar)";                       \
        ver="$(call GETVAR,$(1)_ver)";                                  \
        sha2="$(call GETVAR,$(1)_sha2)";                                \
        sha1="$(call GETVAR,$(1)_sha1)";                                \
        pkgsdir="$(sdir)/$(1)";                                         \
        if [ "$(1)" = "gnupg" ]; then                                   \
          git='';                                                       \
          gitref='';                                                    \
          tar='';                                                       \
          pkgsdir="$(topsrc)";                                          \
        fi;                                                             \
        pkgbdir="$(bdir6)/$(1)";                                        \
        pkgcfg="$(call GETVAR,speedo_pkg_w64_$(1)_configure)";          \
        tmp="$(speedo_w32_cflags)                                       \
             $(call GETVAR,speedo_pkg_$(1)_extracflags)";               \
        if [ x$$$$(echo "$$$$tmp" | tr -d '[:space:]')x != xx ]; then   \
          pkgextracflags="CFLAGS=\"$$$$tmp\"";                          \
        else                                                            \
          pkgextracflags=;                                              \
        fi;                                                             \
        pkgmkdir="$(call GETVAR,speedo_pkg_$(1)_make_dir)";             \
        pkgmkargs="$(call GETVAR,speedo_pkg_$(1)_make_args)";           \
        pkgmkargs_inst="$(call GETVAR,speedo_pkg_$(1)_make_args_inst)"; \
        pkgmkargs_uninst="$(call GETVAR,speedo_pkg_$(1)_make_args_uninst)"; \
        export PKG_CONFIG="/usr/bin/pkg-config";                        \
        export PKG_CONFIG_PATH="$(idir6)/lib/pkgconfig";                \
        [ "$(TARGETOS)" != native ] && export PKG_CONFIG_LIBDIR="";     \
        export SYSROOT="$(idir6)";                                      \
        export PATH="$(idir6)/bin:$${PATH}";                            \
        export LD_LIBRARY_PATH="$(idir6)/lib:$${LD_LIBRARY_PATH}"
endef


# Template for source packages.

# Note that the gnupg package is special: The package source dir is
# the same as the topsrc dir and thus we need to detect the gnupg
# package and cd to that directory.  We also test that no in-source build
# has been done.  autogen.sh is not run for gnupg.
#
define SPKG_template

$(stampdir)/stamp-$(1)-00-unpack:
	@echo "speedo: /*"
	@echo "speedo:  *   $(1)"
	@echo "speedo:  */"
	@(set -e; cd $(sdir);				\
	 $(call SETVARS,$(1)); 				\
	 if [ "$(WHAT)" = "this" ]; then                \
           echo "speedo: using included source";        \
	 elif [ "$(1)" = "gnupg" ]; then                \
	   cd $$$${pkgsdir};                            \
           if [ -f config.log ]; then                   \
             echo "GnuPG has already been build in-source" >&2  ;\
	     echo "Please run \"make distclean\" and retry" >&2 ;\
	     exit 1 ;	                         	\
           fi;                                          \
	   echo "speedo: unpacking gnupg not needed";   \
	 elif [ -n "$$$${git}" ]; then			\
	   echo "speedo: unpacking $(1) from $$$${git}:$$$${gitref}"; \
           git clone -b "$$$${gitref}" "$$$${git}" "$$$${pkg}"; \
	   cd "$$$${pkg}"; 				\
	   AUTOGEN_SH_SILENT=1 ./autogen.sh;            \
         elif [ -n "$$$${tar}" ]; then			\
           tar2="$(OVERRIDE_TARBALLS)/$$$$(basename $$$${tar})";\
           if [ -f "$$$${tar2}" ]; then                 \
             tar="$$$$tar2";                            \
             echo "speedo: /*";                         \
             echo "speedo:  * Note: using an override"; \
             echo "speedo:  */";                        \
           fi;                                          \
	   echo "speedo: unpacking $(1) from $$$${tar}"; \
           case "$$$${tar}" in				\
             *.gz) pretar=zcat ;;	   		\
             *.bz2) pretar=bzcat ;;			\
	     *.xz) pretar=xzcat ;;                     	\
             *) pretar=cat ;;				\
           esac;					\
           [ -f tmp.tgz ] && rm tmp.tgz;                \
           case "$$$${tar}" in				\
	     /*) $$$${pretar} < $$$${tar} | tar xf - ;;	\
	     *)  wget -q -O - $$$${tar} | tee tmp.tgz   \
                  | $$$${pretar} | tar x$$$${opt}f - ;; \
	   esac;					\
	   if [ -f tmp.tgz ]; then                      \
	     if [ -n "$$$${sha2}" ]; then               \
               tmp=$$$$($(SHA2SUM) <tmp.tgz|cut -d' ' -f1);\
               if [ "$$$${tmp}" != "$$$${sha2}" ]; then \
	         echo "speedo:";                        \
                 echo "speedo: ERROR: SHA-256 checksum mismatch for $(1)";\
	         echo "speedo:";                        \
                 exit 1;                                \
               fi;                                      \
	     elif [ -n "$$$${sha1}" ]; then            \
               tmp=$$$$($(SHA1SUM) <tmp.tgz|cut -d' ' -f1);\
               if [ "$$$${tmp}" != "$$$${sha1}" ]; then \
	         echo "speedo:";                        \
                 echo "speedo: ERROR: SHA-1 checksum mismatch for $(1)";\
	         echo "speedo:";                        \
                 exit 1;                                \
               fi;                                      \
	     else                                       \
               echo "speedo:";                          \
               echo "speedo: Warning: No checksum known for $(1)";\
               echo "speedo:";                          \
             fi;                                        \
	     rm tmp.tgz;                                \
           fi;                                          \
	   base=`echo "$$$${tar}" | sed -e 's,^.*/,,'   \
                 | sed -e 's,\.tar.*$$$$,,'`;		\
	   mv $$$${base} $(1);				\
	   patch="$(patdir)/$(1)-$$$${base#$(1)-}.patch";\
	   patchx="$(patdir)/$(1).patch";               \
	   if [ -x "$$$${patch}" ]; then  		\
             echo "speedo: applying patch $$$${patch}"; \
             cd $(1); "$$$${patch}"; 	 		\
	   elif [ -x "$$$${patchx}" ]; then  		\
             echo "speedo: applying patch $$$${patchx}";\
             cd $(1); "$$$${patchx}"; 	 		\
	   elif [ -f "$$$${patch}" ]; then  		\
             echo "speedo: warning: $$$${patch} is not executable"; \
	   fi;						\
	 else                                           \
	   echo "speedo: unpacking $(1) from UNKNOWN";  \
	 fi)
	@touch $(stampdir)/stamp-$(1)-00-unpack

$(stampdir)/stamp-$(1)-01-configure: $(stampdir)/stamp-$(1)-00-unpack
	@echo "speedo: configuring $(1)"
ifneq ($(findstring $(1),$(speedo_make_only_style)),)
	@echo "speedo: configure run not required"
else ifneq ($(findstring $(1),$(speedo_gnupg_style)),)
	@($(call SETVARS,$(1));				\
	 mkdir "$$$${pkgbdir}";				\
	 cd "$$$${pkgbdir}";		        	\
         if [ -n "$(speedo_autogen_buildopt)" ]; then   \
            eval AUTOGEN_SH_SILENT=1 w32root="$(idir)"  \
               "$$$${pkgsdir}/autogen.sh"               \
               $(speedo_autogen_buildopt)            	\
               $$$${pkgcfg} $$$${pkgextracflags}; 	\
         else                                        	\
            eval "$$$${pkgsdir}/configure" 		\
	       --silent                 		\
	       --enable-maintainer-mode			\
               --prefix="$(idir)"		        \
               $$$${pkgcfg} $$$${pkgextracflags};     	\
	 fi)
else
	@($(call SETVARS,$(1)); 			\
	 mkdir "$$$${pkgbdir}";				\
	 cd "$$$${pkgbdir}";		        	\
	 eval "$$$${pkgsdir}/configure" 		\
	     --silent $(speedo_host_build_option)	\
             --prefix="$(idir)"		        	\
	     $$$${pkgcfg}  $$$${pkgextracflags};	\
	 )
endif
	@touch $(stampdir)/stamp-$(1)-01-configure

# Note that unpack has no 64 bit version becuase it is just the source.
# Fixme: We should use templates to create the standard and w64
# version of these rules.
$(stampdir)/stamp-w64-$(1)-01-configure: $(stampdir)/stamp-$(1)-00-unpack
	@echo "speedo: configuring $(1) (64 bit)"
ifneq ($(findstring $(1),$(speedo_make_only_style)),)
	@echo "speedo: configure run not required"
else ifneq ($(findstring $(1),$(speedo_gnupg_style)),)
	@($(call SETVARS_W64,$(1));			\
	 mkdir "$$$${pkgbdir}";				\
	 cd "$$$${pkgbdir}";		        	\
         if [ -n "$(speedo_autogen_buildopt)" ]; then   \
            eval AUTOGEN_SH_SILENT=1 w64root="$(idir6)" \
               "$$$${pkgsdir}/autogen.sh"               \
               $(speedo_autogen_buildopt6)            	\
               $$$${pkgcfg} $$$${pkgextracflags};       \
         else                                        	\
            eval "$$$${pkgsdir}/configure" 		\
	       --silent                 		\
	       --enable-maintainer-mode			\
               --prefix="$(idir6)"		        \
               $$$${pkgcfg} $$$${pkgextracflags};       \
	 fi)
else
	@($(call SETVARS_W64,$(1)); 			\
	 mkdir "$$$${pkgbdir}";				\
	 cd "$$$${pkgbdir}";		        	\
	 eval "$$$${pkgsdir}/configure" 		\
	     --silent $(speedo_host_build_option6)	\
             --prefix="$(idir6)"	        	\
	     $$$${pkgcfg} $$$${pkgextracflags};       	\
	 )
endif
	@touch $(stampdir)/stamp-w64-$(1)-01-configure


$(stampdir)/stamp-$(1)-02-make: $(stampdir)/stamp-$(1)-01-configure
	@echo "speedo: making $(1)"
ifneq ($(findstring $(1),$(speedo_make_only_style)),)
	@($(call SETVARS,$(1));				\
          cd "$$$${pkgsdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
          if test "$$$${pkg}" = zlib -a "$(TARGETOS)" != w32 ; then \
            ./configure --prefix="$(idir)" ; \
          fi ;\
	  $(MAKE) --no-print-directory $(speedo_makeopt) $$$${pkgmkargs} V=0)
else
	@($(call SETVARS,$(1));				\
          cd "$$$${pkgbdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $(speedo_makeopt) $$$${pkgmkargs} V=0)
endif
	@touch $(stampdir)/stamp-$(1)-02-make

$(stampdir)/stamp-w64-$(1)-02-make: $(stampdir)/stamp-w64-$(1)-01-configure
	@echo "speedo: making $(1) (64 bit)"
ifneq ($(findstring $(1),$(speedo_make_only_style)),)
	@($(call SETVARS_W64,$(1));				\
          cd "$$$${pkgsdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $(speedo_makeopt) $$$${pkgmkargs} V=0)
else
	@($(call SETVARS_W64,$(1));				\
          cd "$$$${pkgbdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $(speedo_makeopt) $$$${pkgmkargs} V=0)
endif
	@touch $(stampdir)/stamp-w64-$(1)-02-make

# Note that post_install must come last because it may be empty and
# "; ;" is a syntax error.
$(stampdir)/stamp-$(1)-03-install: $(stampdir)/stamp-$(1)-02-make
	@echo "speedo: installing $(1)"
ifneq ($(findstring $(1),$(speedo_make_only_style)),)
	@($(call SETVARS,$(1));				\
          cd "$$$${pkgsdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $$$${pkgmkargs_inst} install V=0;\
	  $(call speedo_pkg_$(call FROB_macro,$(1))_post_install))
else
	@($(call SETVARS,$(1));				\
          cd "$$$${pkgbdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $$$${pkgmkargs_inst} install-strip V=0;\
	  $(call speedo_pkg_$(call FROB_macro,$(1))_post_install))
endif
	touch $(stampdir)/stamp-$(1)-03-install

$(stampdir)/stamp-w64-$(1)-03-install: $(stampdir)/stamp-w64-$(1)-02-make
	@echo "speedo: installing $(1) (64 bit)"
ifneq ($(findstring $(1),$(speedo_make_only_style)),)
	@($(call SETVARS_W64,$(1));				\
          cd "$$$${pkgsdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $$$${pkgmkargs_inst} install V=0;\
	  $(call speedo_pkg_$(call FROB_macro,$(1))_post_install))
else
	@($(call SETVARS_W64,$(1));				\
          cd "$$$${pkgbdir}";				\
	  test -n "$$$${pkgmkdir}" && cd "$$$${pkgmkdir}"; \
	  $(MAKE) --no-print-directory $$$${pkgmkargs_inst} install-strip V=0;\
	  $(call speedo_pkg_$(call FROB_macro,$(1))_post_install))
endif
	touch $(stampdir)/stamp-w64-$(1)-03-install

$(stampdir)/stamp-final-$(1): $(stampdir)/stamp-$(1)-03-install
	@($(call SETVARS,$(1));                                  \
	  printf "%-14s %-12s %s\n" $(1) "$$$${ver}" "$$$${sha1}" \
	      >> $(bdir)/pkg-versions.txt)
	@echo "speedo: $(1) done"
	@touch $(stampdir)/stamp-final-$(1)

$(stampdir)/stamp-w64-final-$(1): $(stampdir)/stamp-w64-$(1)-03-install
	@echo "speedo: $(1) (64 bit) done"
	@touch $(stampdir)/stamp-w64-final-$(1)

.PHONY : clean-$(1)
clean-$(1):
	@echo "speedo: uninstalling $(1)"
	@($(call SETVARS,$(1));			          \
	 (cd "$$$${pkgbdir}" 2>/dev/null &&		  \
	  $(MAKE) --no-print-directory                    \
           $$$${pkgmkargs_uninst} uninstall V=0 ) || true;\
         if [ "$(1)" = "gnupg" ]; then                    \
	   rm -fR "$$$${pkgbdir}" || true                ;\
	 else                                             \
	   rm -fR "$$$${pkgsdir}" "$$$${pkgbdir}" || true;\
	 fi)
	-rm -f $(stampdir)/stamp-final-$(1) $(stampdir)/stamp-$(1)-*


.PHONY : build-$(1)
build-$(1): $(stampdir)/stamp-final-$(1)


.PHONY : report-$(1)
report-$(1):
	@($(call SETVARS,$(1));				\
	 echo -n $(1):\  ;				\
	 if [ -n "$$$${git}" ]; then			\
           if [ -e "$$$${pkgsdir}/.git" ]; then		\
	     cd "$$$${pkgsdir}" &&			\
             git describe ;		                \
	   else						\
             echo missing;				\
	   fi						\
         elif [ -n "$$$${tar}" ]; then			\
	   base=`echo "$$$${tar}" | sed -e 's,^.*/,,'   \
                 | sed -e 's,\.tar.*$$$$,,'`;		\
	   echo $$$${base} ;				\
         fi)

endef


# Insert the template for each source package.
$(foreach spkg, $(speedo_spkgs), $(eval $(call SPKG_template,$(spkg))))

$(stampdir)/stamp-final: clean-pkg-versions
ifeq ($(TARGETOS),w32)
$(stampdir)/stamp-final: $(addprefix $(stampdir)/stamp-w64-final-,$(speedo_w64_build_list))
endif
$(stampdir)/stamp-final: $(addprefix $(stampdir)/stamp-final-,$(speedo_build_list))
	touch $(stampdir)/stamp-final

clean-pkg-versions:
        @: >$(bdir)/pkg-versions.txt

all-speedo: $(stampdir)/stamp-final

report-speedo: $(addprefix report-,$(speedo_build_list))

# Just to check if we catched all stamps.
clean-stamps:
	$(RM) -fR $(stampdir)

clean-speedo:
	$(RM) -fR PLAY


#
# Windows installer
#
# {{{
ifeq ($(TARGETOS),w32)

dist-source: installer
	for i in 00 01 02 03; do sleep 1;touch PLAY/stamps/stamp-*-${i}-*;done
	(set -e;\
	 tarname="$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).tar" ;\
	 [ -f "$$tarname" ] && rm "$$tarname" ;\
         tar -C $(topsrc) -cf "$$tarname" --exclude-backups --exclude-vcs \
             --transform='s,^\./,$(INST_NAME)-$(INST_VERSION)/,' \
             --anchored --exclude './PLAY' . ;\
	 tar --totals -rf "$$tarname" --exclude-backups --exclude-vcs \
              --transform='s,^,$(INST_NAME)-$(INST_VERSION)/,' \
	     PLAY/stamps/stamp-*-00-unpack PLAY/src swdb.lst swdb.lst.sig ;\
	 [ -f "$$tarname".xz ] && rm "$$tarname".xz;\
         xz -T0 "$$tarname" ;\
	)


# Extract the two latest news entries.  */
$(bdir)/NEWS.tmp: $(topsrc)/NEWS
	awk '/^Notewo/ {if(okay>1){exit}; okay++};okay {print $0}' \
	    <$(topsrc)/NEWS  >$(bdir)/NEWS.tmp

# Sort the file with the package versions.
$(bdir)/pkg-versions.sorted: $(bdir)/pkg-versions.txt
	grep -v '^gnupg ' <$(bdir)/pkg-versions.txt \
	    | sort | uniq >$(bdir)/pkg-versions.sorted

$(bdir)/README.txt: $(bdir)/NEWS.tmp $(topsrc)/README $(w32src)/README.txt \
                    $(w32src)/pkg-copyright.txt $(bdir)/pkg-versions.sorted
	sed -e '/^;.*/d;' \
	-e '/!NEWSFILE!/{r $(bdir)/NEWS.tmp' -e 'd;}' \
	-e '/!GNUPGREADME!/{r $(topsrc)/README' -e 'd;}' \
        -e '/!PKG-COPYRIGHT!/{r $(w32src)/pkg-copyright.txt' -e 'd;}' \
        -e '/!PKG-VERSIONS!/{r $(bdir)/pkg-versions.sorted' -e 'd;}' \
        -e 's,!VERSION!,$(INST_VERSION),g' \
	   < $(w32src)/README.txt \
           | sed -e '/^#/d' \
           | awk '{printf "%s\r\n", $$0}' >$(bdir)/README.txt

$(bdir)/g4wihelp.dll: $(w32src)/g4wihelp.c $(w32src)/exdll.h $(w32src)/exdll.c
	(set -e; cd $(bdir); \
         $(W32CC) -DUNICODE -static-libgcc -I . -O2 -c \
                          -o exdll.o $(w32src)/exdll.c; \
	 $(W32CC) -DUNICODE -static-libgcc -I. -shared -O2 \
                          -o g4wihelp.dll $(w32src)/g4wihelp.c exdll.o \
	                  -lwinmm -lgdi32 -luserenv \
                          -lshell32 -loleaut32 -lshlwapi -lmsimg32; \
	 $(STRIP) g4wihelp.dll)

w32_insthelpers: $(bdir)/g4wihelp.dll

$(bdir)/inst-options.ini: $(w32src)/inst-options.ini
	cat $(w32src)/inst-options.ini >$(bdir)/inst-options.ini

extra_installer_options =
ifeq ($(WITH_GUI),1)
extra_installer_options += -DWITH_GUI=1
endif

# Note that we sign only when doing the final installer.
installer: all w32_insthelpers $(w32src)/inst-options.ini $(bdir)/README.txt
	(set -e;\
	 cd "$(idir)"; \
	 if echo "$(idir)" | grep -q '/PLAY-release/' ; then \
	   for f in $(AUTHENTICODE_FILES); do \
             if [ -f "bin/$$f" ]; then \
	       $(call AUTHENTICODE_sign,"bin/$$f","bin/$$f");\
	     elif [ -f "libexec/$$f" ]; then \
	       $(call AUTHENTICODE_sign,"libexec/$$f","libexec/$$f");\
	     else \
	       echo "speedo: WARNING: file '$$f' not available for signing";\
             fi;\
           done; \
         fi \
        )
	$(MAKENSIS) -V2 \
                    -DINST_DIR=$(idir) \
                    -DINST6_DIR=$(idir6) \
                    -DBUILD_DIR=$(bdir) \
                    -DTOP_SRCDIR=$(topsrc) \
                    -DW32_SRCDIR=$(w32src) \
                    -DBUILD_ISODATE=$(BUILD_ISODATE) \
                    -DBUILD_DATESTR=$(BUILD_DATESTR) \
		    -DNAME=$(INST_NAME) \
	            -DVERSION=$(INST_VERSION) \
		    -DPROD_VERSION=$(INST_PROD_VERSION) \
		    $(extra_installer_options) $(w32src)/inst.nsi
	@echo "Ready: $(idir)/$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).exe"

# We use the installer target to ensure everything is done and signed
wixlib: installer $(bdir)/README.txt $(w32src)/wixlib.wxs
	if [ -z "$$(which $(WINE))" ]; then \
		echo "ERROR: For the w32-wixlib wine needs to be installed."; \
		echo "ERROR: see 'help-w32-wixlib'"; \
		exit 1; \
	fi;
	if [ ! -d "$(WIXPREFIX)" ]; then \
		echo "ERROR: You must set WIXPREFIX to an installation of wixtools."; \
		echo "ERROR: see 'help-w32-wixlib'"; \
		exit 1; \
	fi;
	(if [ -z "$$WINEPREFIX" ]; then \
		WINEPREFIX="$$HOME/.wine"; \
		if [ ! -e "$$WINEPREFIX/dosdevices" ]; then \
			echo "ERROR: No wine prefix found under $$WINEPREFIX"; \
			exit 1; \
		fi; \
	fi; \
	WINEINST=$$WINEPREFIX/dosdevices/k:; \
	WINESRC=$$WINEPREFIX/dosdevices/i:; \
	WINEBUILD=$$WINEPREFIX/dosdevices/j:; \
	if [ -e "$$WINEINST" ]; then \
		echo "ERROR: $$WINEINST already exists. Please remove."; \
		exit 1; \
	fi; \
	if [ -e "$$WINESRC" ]; then \
		echo "ERROR: $$WINESRC already exists. Please remove."; \
		exit 1; \
	fi; \
	if [ -e "$$WINEBUILD" ]; then \
		echo "ERROR: $$WINEBUILD already exists. Please remove."; \
		exit 1; \
	fi; \
	echo "$(INST_NAME)" > $(bdir)/VERSION; \
	echo "$(INST_VERSION)" >> $(bdir)/VERSION; \
	MSI_VERSION=$$(echo $(INST_VERSION) | tr -s \\-beta .); \
	(ln -s $(idir) $$WINEINST; \
	 ln -s $(w32src) $$WINESRC; \
	 ln -s $(bdir)  $$WINEBUILD; \
		$(WINE) $(WIXPREFIX)/candle.exe \
		-dSourceDir=k: \
		-dBuildDir=j: \
		-dVersion=$$MSI_VERSION \
		-out k:\\$(INST_NAME).wixobj \
		-pedantic -wx i:\\wixlib.wxs ;\
		$(WINE) $(WIXPREFIX)/lit.exe \
		-out k:\\$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).wixlib \
		-bf \
		-wx \
		-pedantic \
		k:\\$(INST_NAME).wixobj \
	); \
		(rm $$WINEINST; rm $$WINESRC; rm $$WINEBUILD;) \
	)

define MKSWDB_commands
 ( pref="#+macro: gnupg22_w32_$(3)" ;\
   echo "$${pref}ver  $(INST_VERSION)_$(BUILD_DATESTR)"  ;\
   echo "$${pref}date $(2)" ;\
   echo "$${pref}size $$(wc -c <$(1)|awk '{print int($$1/1024)}')k";\
   echo "$${pref}sha1 $$(sha1sum <$(1)|cut -d' ' -f1)" ;\
   echo "$${pref}sha2 $$(sha256sum <$(1)|cut -d' ' -f1)" ;\
 ) | tee $(1).swdb
endef

# Sign the file $1 and save the result as $2
define AUTHENTICODE_sign
   set -e;\
   if [ -n "$(AUTHENTICODE_SIGNHOST)" ]; then \
     echo "speedo: Signing via host $(AUTHENTICODE_SIGNHOST)";\
     scp $(1) "$(AUTHENTICODE_SIGNHOST):a.exe" ;\
     ssh "$(AUTHENTICODE_SIGNHOST)" '$(AUTHENTICODE_TOOL)' sign \
        /a /n '"g10 Code GmbH"' \
        /tr 'http://rfc3161timestamp.globalsign.com/advanced' /td sha256 \
        /fd sha256 /du https://gnupg.org a.exe ;\
     scp "$(AUTHENTICODE_SIGNHOST):a.exe" $(2);\
     echo "speedo: signed file is '$(2)'" ;\
   elif [ "$(AUTHENTICODE_KEY)" = card ]; then \
     echo "speedo: Signing using a card";\
     $(OSSLSIGNCODE) sign \
       -pkcs11engine $(OSSLPKCS11ENGINE) \
       -pkcs11module $(SCUTEMODULE) \
       -certs $(AUTHENTICODE_CERTS) \
       -h sha256 -n GnuPG -i https://gnupg.org \
       -ts http://rfc3161timestamp.globalsign.com/advanced \
       -in $(1) -out $(2).tmp ; mv $(2).tmp $(2) ; \
   elif [ -e "$(AUTHENTICODE_KEY)" ]; then \
     echo "speedo: Signing using key $(AUTHENTICODE_KEY)";\
     osslsigncode sign -certs $(AUTHENTICODE_CERTS) \
       -pkcs12 $(AUTHENTICODE_KEY) -askpass \
       -ts "http://timestamp.globalsign.com/scripts/timstamp.dll" \
       -h sha256 -n GnuPG -i https://gnupg.org \
       -in $(1) -out $(2) ;\
   else \
     echo "speedo: WARNING: Binaries are not signed"; \
   fi
endef

# Help target for testing to sign a file.
# Usage: make -f speedo.mk test-authenticode-sign TARGETOS=w32 FILE=foo.exe
test-authenticode-sign:
	(set -e; \
	 echo "Test signining of $(FILE)" ; \
	 $(call AUTHENTICODE_sign,"$(FILE)","$(FILE)");\
	)


# Build the installer from the source tarball.
installer-from-source: dist-source
	(set -e;\
	 [ -d PLAY-release ] && rm -rf PLAY-release; \
	 mkdir PLAY-release;\
	 cd PLAY-release; \
	 tar xJf "../$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).tar.xz";\
	 cd $(INST_NAME)-$(INST_VERSION); \
	 $(MAKE) -f build-aux/speedo.mk this-w32-installer SELFCHECK=0;\
	 if [ -d "$(WIXPREFIX)" ]; then \
		 $(MAKE) -f build-aux/speedo.mk this-w32-wixlib SELFCHECK=0;\
	 fi; \
	 reldate="$$(date -u +%Y-%m-%d)" ;\
	 exefile="$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).exe" ;\
	 cp "PLAY/inst/$$exefile" ../.. ;\
	 exefile="../../$$exefile" ;\
	 $(call MKSWDB_commands,$${exefile},$${reldate}); \
	 msifile="$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).wixlib"; \
	 if [ -e "PLAY/inst/$${msifile}" ]; then \
		 cp "PLAY/inst/$$msifile" ../..; \
		 msifile="../../$$msifile" ; \
		 $(call MKSWDB_commands,$${msifile},$${reldate},"wixlib_"); \
	 fi \
	)

# This target repeats some of the installer-from-source steps but it
# is intended to be called interactively, so that the passphrase can be
# entered.
sign-installer:
	@(set -e; \
	 cd PLAY-release; \
	 cd $(INST_NAME)-$(INST_VERSION); \
	 reldate="$$(date -u +%Y-%m-%d)" ;\
	 exefile="$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).exe" ;\
	 msifile="$(INST_NAME)-$(INST_VERSION)_$(BUILD_DATESTR).wixlib" ;\
	 echo "speedo: /*" ;\
	 echo "speedo:  * Signing installer" ;\
	 echo "speedo:  */" ;\
	 $(call AUTHENTICODE_sign,"PLAY/inst/$$exefile","../../$$exefile");\
	 exefile="../../$$exefile" ;\
	 msifile="../../$$msifile" ;\
	 $(call MKSWDB_commands,$${exefile},$${reldate}); \
	 if [ -e "$${msifile}" ]; then \
	   $(call MKSWDB_commands,$${msifile},$${reldate},"wixlib_"); \
	 fi; \
	 echo "speedo: /* (osslsigncode verify disabled) */" ;\
	 echo osslsigncode verify $${exefile} \
	)



endif
# }}} W32


#
# Check availibility of standard tools and prepare everything.
#
check-tools: $(stampdir)/stamp-directories


#
# Mark phony targets
#
.PHONY: all all-speedo report-speedo clean-stamps clean-speedo installer \
	w32_insthelpers check-tools clean-pkg-versions
