# speedo.mk - Speedo rebuilds speedily.
# Copyright (C) 2008, 2014 g10 Code GmbH
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
#   make -f speedo.mk all
# or
#   make -f speedo.mk
#
# Builds all packages and installs them under play/inst.  At the end,
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



# --------

# The packages that should be built.  The order is also the build order.
speedo_spkgs = libgpg-error npth libgcrypt libassuan libksba gnupg gpgme gpa

# version numbers of the released packages
# Fixme: Take the version numbers from gnupg-doc/web/swdb.mac
libgpg_error_ver = 1.12
npth_ver = 0.91
libgcrypt_ver = 1.6.0
libassuan_ver = 2.1.1
libksba_ver = 1.3.0
gnupg_ver = 2.0.22
gpgme_ver = 1.5.0
gpa_ver = 0.9.5

# The GIT repository.  Using a local repo is much faster.
#gitrep = git://git.gnupg.org
gitrep = ${HOME}/s


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

# Set this to "git" or "release".
WHAT=release

# Set target to "native" or "w32"
TARGETOS=native

#  Number of parallel make jobs
MAKE_J=3

ifeq ($(WHAT),git)
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
  speedo_pkg_gnupg_git = $(gitrep)/gnupg
  speedo_pkg_gnupg_gitref = master
  speedo_pkg_gpgme_git = $(gitrep)/gpgme
  speedo_pkg_gpgme_gitref = master
  speedo_pkg_gpa_git = $(gitrep)/gpa
  speedo_pkg_gpa_gitref = master
else
  pkgrep = ftp://ftp.gnupg.org/gcrypt
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
  speedo_pkg_gnupg_tar = \
	$(pkgrep)/gnupg/gnupg-$(gnupg_ver).tar.bz2
  speedo_pkg_gpgme_tar = \
	$(pkgrep)/gpgme/gpgme-$(gpgme_ver).tar.bz2
  speedo_pkg_gpa_tar = \
	$(pkgrep)/gpa/gpa-$(gpa_ver).tar.bz2
endif

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


# Fixme: The dist target does not work anymore.
STRIP = i686-w64-mingw32-strip

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
	$(STRIP) $${pkgname}/bin/*.dll ; \
	zip -r9 $${pkgname}.zip $${pkgname} >/dev/null ; \
	rm -rf $$pkgname; \
	echo "$$pkgname.zip ready for distribution" >&2


-include config.mk

#
#  The generic speedo code
#

MKDIR=mkdir


# These paths must be absolute, as we switch directories pretty often.
root := $(shell pwd)/play
stampdir := $(root)/stamps
sdir := $(root)/src
bdir := $(root)/build
idir := $(root)/inst

speedo_build_list = $(speedo_spkgs)

ifeq ($(TARGETOS),w32)
  speedo_autogen_buildopt="--build-w32"
else
  speedo_autogen_buildopt=
endif

ifeq ($(MAKE_J),)
  speedo_makeopt=
else
  speedo_makeopt=-j$(MAKE_J)
endif


# The playground area is our scratch area, where we unpack, build and
# install the packages.
$(stampdir)/stamp-directories:
	$(MKDIR) $(root)
	$(MKDIR) $(stampdir)
	$(MKDIR) $(sdir)
	$(MKDIR) $(bdir)
	$(MKDIR) $(idir)
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
	pkg="$(1)";							\
	git="$(call GETVAR,speedo_pkg_$(1)_git)";			\
	gitref="$(call GETVAR,speedo_pkg_$(1)_gitref)";			\
	tar="$(call GETVAR,speedo_pkg_$(1)_tar)";			\
	pkgsdir="$(sdir)/$(1)";						\
	pkgbdir="$(bdir)/$(1)";	                    			\
	pkgcfg="$(call GETVAR,speedo_pkg_$(1)_configure)";		\
	pkgmkargs="$(call GETVAR,speedo_pkg_$(1)_make_args)";           \
	pkgmkargs_inst="$(call GETVAR,speedo_pkg_$(1)_make_args_inst)"; \
	export PATH="$(idir)/bin:$${PATH}";				\
	export LD_LIBRARY_PATH="$(idir)/lib:$${LD_LIBRARY_PATH}"
endef


# Template for source packages.

define SPKG_template

$(stampdir)/stamp-$(1)-00-unpack: $(stampdir)/stamp-directories
	@echo "speedo: /*"
	@echo "speedo:  *   $(1)"
	@echo "speedo:  */"
	@(cd $(sdir);					\
	 $(call SETVARS,$(1));				\
	 if [ -n "$$$${git}" ]; then			\
	   echo "speedo: unpacking $(1) from $$$${git}:$$$${gitref}"; \
           git clone -q -b "$$$${gitref}" "$$$${git}" "$$$${pkg}"; \
	   cd "$$$${pkg}" &&				\
	   AUTOGEN_SH_SILENT=1 ./autogen.sh;		\
         elif [ -n "$$$${tar}" ]; then			\
	   echo "speedo: unpacking $(1) from $$$${tar}"; \
           case "$$$${tar}" in				\
             *.gz) opt=z ;;				\
             *.bz2) opt=j ;;				\
             *) opt= ;;					\
           esac;					\
           case "$$$${tar}" in				\
	     /*) cmd=cat ;;				\
	     *) cmd="wget -q -O -" ;;			\
	   esac;					\
	   $$$${cmd} "$$$${tar}" | tar x$$$${opt}f - ;	\
	   base=`echo "$$$${tar}" | sed -e 's,^.*/,,'   \
                 | sed -e 's,\.tar.*$$$$,,'`;		\
	   mv $$$${base} $(1);				\
	 else                                           \
	   echo "speedo: unpacking $(1) from UNKNOWN";  \
	 fi)
	@touch $(stampdir)/stamp-$(1)-00-unpack

$(stampdir)/stamp-$(1)-01-configure: $(stampdir)/stamp-$(1)-00-unpack
	@echo "speedo: configuring $(1)"
	@($(call SETVARS,$(1));				\
	 mkdir "$$$${pkgbdir}";				\
	 cd "$$$${pkgbdir}";				\
	 if [ -n "$(speedo_autogen_buildopt)" ]; then   \
	    eval AUTOGEN_SH_SILENT=1 w32root="$(idir)"  \
                 "$$$${pkgsdir}/autogen.sh"             \
                 $(speedo_autogen_buildopt) --silent   \
		 $$$${pkgcfg};                         \
	 else                                           \
            eval "$$$${pkgsdir}/configure" 		\
		 --silent                 		\
		 --enable-maintainer-mode		\
                 --prefix="$(idir)"		        \
		 $$$${pkgcfg};                          \
	 fi)
	@touch $(stampdir)/stamp-$(1)-01-configure

$(stampdir)/stamp-$(1)-02-make: $(stampdir)/stamp-$(1)-01-configure
	@echo "speedo: making $(1)"
	@($(call SETVARS,$(1));				\
	  cd "$$$${pkgbdir}";				\
	  $(MAKE) --no-print-directory $(speedo_makeopt) $$$${pkgmkargs} V=0)
	@touch $(stampdir)/stamp-$(1)-02-make

# Note that post_install must come last because it may be empty and
# "; ;" is a syntax error.
$(stampdir)/stamp-$(1)-03-install: $(stampdir)/stamp-$(1)-02-make
	@echo "speedo: installing $(1)"
	@($(call SETVARS,$(1));				\
	  cd "$$$${pkgbdir}";				\
	  $(MAKE) --no-print-directory $$$${pkgmkargs_inst} install-strip V=0;\
	  $(call gpg4win_pkg_$(call FROB_macro,$(1))_post_install))
	@touch $(stampdir)/stamp-$(1)-03-install

$(stampdir)/stamp-final-$(1): $(stampdir)/stamp-$(1)-03-install
	@touch $(stampdir)/stamp-final-$(1)

.PHONY : clean-$(1)
clean-$(1):
	@echo "speedo: uninstalling $(1)"
	@($(call SETVARS,$(1));				\
	 (cd "$$$${pkgbdir}";				\
	  $(MAKE) --no-print-directory $$$${pkgmkargs_inst} uninstall V=0); \
	 rm -fR "$$$${pkgsdir}" "$$$${pkgbdir}")
	@rm -f $(stampdir)/stamp-final-$(1) $(stampdir)/stamp-$(1)-*

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

$(stampdir)/stamp-final: $(stampdir)/stamp-directories
$(stampdir)/stamp-final: $(addprefix $(stampdir)/stamp-final-,$(speedo_build_list))
	touch $(stampdir)/stamp-final

all-speedo: $(stampdir)/stamp-final

report-speedo: $(addprefix report-,$(speedo_build_list))

# Just to check if we catched all stamps.
clean-stamps:
	$(RM) -fR $(stampdir)

clean-speedo:
	$(RM) -fR play

.PHONY : all-speedo report-speedo clean-stamps clean-speedo
