# speedo.mk - Speedo rebuilds speedily.
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

MKDIR=mkdir
STOW=stow

# These paths must be absolute, as we switch directories pretty often.
root := $(shell pwd)/playground
bdir := $(root)/build
idir := $(root)/install
ipdir := $(root)/install/pkgs

# The playground area is our scratch area, where we unpack, build and
# install the packages.
stamps/stamp-directories:
	$(MKDIR) stamps
	$(MKDIR) playground
	$(MKDIR) $(bdir)
	$(MKDIR) $(idir)
	#$(MKDIR) $(ipdir)
	touch stamps/stamp-directories

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
	svn="$(call GETVAR,speedo_pkg_$(1)_svn)";			\
	tar="$(call GETVAR,speedo_pkg_$(1)_tar)";			\
	pkgsdir="$(bdir)/$(1)";						\
	pkgbdir="$(bdir)/$(1)-build";					\
	pkgidir="$(ipdir)/$(1)";					\
	pkgcfg="$(call GETVAR,speedo_pkg_$(1)_configure)";		\
	pkgmkargs="$(call GETVAR,speedo_pkg_$(1)_make_args)";           \
	pkgmkargs_inst="$(call GETVAR,speedo_pkg_$(1)_make_args_inst)"; \
	export PATH="$(idir)/bin:$${PATH}";				\
	export LD_LIBRARY_PATH="$(idir)/lib:$${LD_LIBRARY_PATH}"
endef


# Template for source packages.

define SPKG_template

stamps/stamp-$(1)-00-unpack: stamps/stamp-directories 
	(cd $(bdir);					\
	 $(call SETVARS,$(1));				\
	 if [ -n "$$$${svn}" ]; then			\
           svn checkout "$$$${svn}" "$$$${pkg}";	\
	   cd "$$$${pkg}";				\
	   ./autogen.sh;				\
         elif [ -n "$$$${tar}" ]; then			\
           case "$$$${tar}" in				\
             (*.gz) opt=z ;;				\
             (*.bz2) opt=j ;;				\
             (*) opt= ;;				\
           esac;					\
           case "$$$${tar}" in				\
	     (/*) cmd=cat ;;				\
	     (*) cmd="wget -q -O -" ;;			\
	   esac;					\
	   $$$${cmd} "$$$${tar}" | tar x$$$${opt}f - ;	\
	   base=`echo "$$$${tar}" | sed -e 's,^.*/,,'   \
                 | sed -e 's,\.tar.*$$$$,,'`;		\
	   mv $$$${base} $(1);				\
         fi)
	touch stamps/stamp-$(1)-00-unpack

stamps/stamp-$(1)-01-configure: stamps/stamp-$(1)-00-unpack
	($(call SETVARS,$(1));				\
	 mkdir "$$$${pkgbdir}";				\
	 cd "$$$${pkgbdir}";				\
	 eval "../$$$${pkg}/configure"			\
		--enable-maintainer-mode		\
		--prefix="$(idir)"		\
		--host=i586-mingw32msvc		\
		$$$${pkgcfg})
	touch stamps/stamp-$(1)-01-configure

stamps/stamp-$(1)-02-make: stamps/stamp-$(1)-01-configure
	($(call SETVARS,$(1));				\
	  cd "$$$${pkgbdir}";				\
	  $(MAKE) $$$${pkgmkargs})
	touch stamps/stamp-$(1)-02-make

# Note that post_install must come last because it may be empty and
# "; ;" is a syntax error.
stamps/stamp-$(1)-03-install: stamps/stamp-$(1)-02-make
	($(call SETVARS,$(1));				\
	  cd "$$$${pkgbdir}";				\
	  $(MAKE) $$$${pkgmkargs_inst} install-strip ; \
	  $(call gpg4win_pkg_$(call FROB_macro,$(1))_post_install))
	touch stamps/stamp-$(1)-03-install

stamps/stamp-final-$(1): stamps/stamp-$(1)-03-install
	touch stamps/stamp-final-$(1)

.PHONY : clean-$(1)
clean-$(1):
	($(call SETVARS,$(1));				\
	 (cd $(ipdir) &&				\
	  ($(STOW) -D "$$$${pkg}";			\
	   rm -fR "$$$${pkg}"));			\
	 rm -fR "$$$${pkgsdir}" "$$$${pkgbdir}")
	rm -f stamps/stamp-final-$(1) stamps/stamp-$(1)-*

.PHONY : report-$(1)
report-$(1):
	@($(call SETVARS,$(1));				\
	 echo -n $(1):\  ;				\
	 if [ -n "$$$${svn}" ]; then			\
           if [ -e .svn ]; then				\
	     cd $(bdir)/$(1) &&				\
             svn info | grep Repository ;		\
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

stamps/stamp-final: stamps/stamp-directories
stamps/stamp-final: $(addprefix stamps/stamp-final-,$(speedo_build_list))
	touch stamps/stamp-final

all-speedo: stamps/stamp-final

report-speedo: $(addprefix report-,$(speedo_build_list))

# Just to check if we catched all stamps.
clean-stamps:
	$(RM) -fR $(stamps)

clean-speedo:
	$(RM) -fR playground stamps

.PHONY : all-speedo report-speedo clean-stamps clean-speedo
