# configure.ac - for GnuPG 1.9
#       Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc,
# 
# This file is part of GnuPG.
# 
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.52)
# Version number: Remember to change it immediately *after* a release.
#                 Add a "-cvs" prefix for non-released code.
AC_INIT(gnupg, 1.9.0-cvs, gnupg-devel@gnupg.org)
NEED_LIBGCRYPT_VERSION=1.1.8
NEED_LIBASSUAN_VERSION=0.0.1
NEED_KSBA_VERSION=0.4.6
NEED_OPENSC_VERSION=0.7.0

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AM_GNU_GETTEXT_VERSION(0.11.5)

AC_CONFIG_AUX_DIR(scripts)
AC_CONFIG_SRCDIR(sm/gpgsm.c)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_MAINTAINER_MODE

# Some status variables to give feedback at the end of a configure run
habe_libassuan=no
have_ksba=no
have_opensc=no
have_pth=no

GNUPG_BUILD_PROGRAM(gpg, yes)
GNUPG_BUILD_PROGRAM(gpgsm, yes)
GNUPG_BUILD_PROGRAM(agent, yes)
GNUPG_BUILD_PROGRAM(scdaemon, yes)


AH_TOP([
/* We need this, because some autoconf tests rely on this (e.g. stpcpy)
   and it should be used for new programs anyway. */
#define _GNU_SOURCE  1
])

AH_BOTTOM([
/* Some global constants. */
#ifdef HAVE_DRIVE_LETTERS
#define GNUPG_DEFAULT_HOMEDIR "c:/gnupg"
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.gnupg"
#endif 
#define GNUPG_PRIVATE_KEYS_DIR "private-keys-v1.d"
])



AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",
                                        [Bug report address])
AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION, "$NEED_LIBGCRYPT_VERSION",
                                       [Required version of Libgcrypt])
AC_DEFINE_UNQUOTED(NEED_KSBA_VERSION, "$NEED_KSBA_VERSION",
                                       [Required version of Libksba])




# Checks for programs.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
#AC_ARG_PROGRAM

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi

case "${target}" in
    *-*-mingw32*)
        PRINTABLE_OS_NAME="MingW32"
        AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
                  [defined if we run on some of the PCDOS like systems 
                   (DOS, Windoze. OS/2) with special properties like
                    no file modes])
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        PRINTABLE_OS_NAME="OS/2"
        ;;
    i?86-*-msdosdjgpp*)
        PRINTABLE_OS_NAME="MSDOS/DJGPP"
        try_dynload=no
        ;;
    *-linux*)
        PRINTABLE_OS_NAME="GNU/Linux"
        ;;
dnl let that after linux to avoid gnu-linux problems
    *-gnu*)
        PRINTABLE_OS_NAME="GNU/Hurd"
        ;;
    *)
        PRINTABLE_OS_NAME=`uname -s || echo "Unknown"`
        ;;
esac
AC_DEFINE_UNQUOTED(PRINTABLE_OS_NAME, "$PRINTABLE_OS_NAME",
                   [A human readable text with the name of the OS])


# I know that it is in general not a good idea to evaluate bindir in
# the configuration but we want to hard code the defaults into some of
# the programs and doing this during a make install is not a good
# idea.  We also have the problem that 2 of the programs are included
# in the package but the others are distributed in other packages.
eval my_default_bindir=${exec_prefix}
test "x${my_default_bindir}" = xNONE && my_default_bindir=${ac_default_prefix}
my_default_bindir=${my_default_bindir}/bin

# Same goes for the pkglibdir which is used to call the gpg-protect-tool.
eval my_default_pkglibdir=${exec_prefix}
test "x${my_default_pkglibdir}" = xNONE && my_default_pkglibdir=${ac_default_prefix}
my_default_pkglibdir=${my_default_pkglibdir}/lib/${PACKAGE_NAME}

AC_ARG_WITH(agent-pgm,
    [  --with-agent-pgm=PATH  Use PATH as the default for the gpg-agent)],
          gnupg_agent_pgm="$withval",
          gnupg_agent_pgm="${my_default_bindir}/gpg-agent" )
AC_DEFINE_UNQUOTED(GNUPG_DEFAULT_AGENT, "$gnupg_agent_pgm",
                   [Default location of the gpg-agent program])
AC_ARG_WITH(pinentry-pgm,
    [  --with-pinentry-pgm=PATH  Use PATH as the default for the pinentry)],
          gnupg_pinentry_pgm="$withval", gnupg_pinentry_pgm="" )
if test -z "$gnupg_pinentry_pgm"; then
  gnupg_pinentry_pgm=${my_default_bindir}/pinentry
fi
AC_DEFINE_UNQUOTED(GNUPG_DEFAULT_PINENTRY, "$gnupg_pinentry_pgm",
                   [Default location of the pinentry program])
AC_ARG_WITH(scdaemon-pgm,
    [  --with-scdaemon-pgm=PATH  Use PATH as the default for the scdaemon)],
          gnupg_scdaemon_pgm="$withval", gnupg_scdaemon_pgm="" )
if test -z "$gnupg_scdaemon_pgm"; then
  gnupg_scdaemon_pgm=${my_default_bindir}/scdaemon
fi
AC_DEFINE_UNQUOTED(GNUPG_DEFAULT_SCDAEMON, "$gnupg_scdaemon_pgm",
                   [Default location of the scdaemon program])
AC_ARG_WITH(dirmngr-pgm,
    [  --with-dirmngr-pgm=PATH  Use PATH as the default for the dirmngr)],
          gnupg_dirmngr_pgm="$withval", gnupg_dirmngr_pgm="" )
if test -z "$gnupg_dirmngr_pgm"; then
  gnupg_dirmngr_pgm=${my_default_bindir}/dirmngr
fi
AC_DEFINE_UNQUOTED(GNUPG_DEFAULT_DIRMNGR, "$gnupg_dirmngr_pgm",
                   [Default location of the dirmngr program])

AC_ARG_WITH(protect-tool,
    [  --with-protect-tool=PATH  Use PATH as the protect-tool)],
          gnupg_protect_tool="$withval", gnupg_protect_tool="" )
if test -z "$gnupg_protect_tool"; then
  gnupg_protect_tool=${my_default_pkglibdir}/gpg-protect-tool
fi
AC_DEFINE_UNQUOTED(GNUPG_PROTECT_TOOL, "$gnupg_protect_tool",
                   [Name of the protect tool program])


#
# Checks for libraries.
#

#
# Libgcrypt is our generic crypto library
#
#AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config)
#if test -n "$LIBGCRYPT_CONFIG"; then
#	LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG --cflags`
#	LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG --libs`
#else
#    AC_MSG_ERROR([[
#***
#*** You need libgcrypt to build this program.
#*** It should be available at the same place you 
#*** got this software.
#***]])
#fi
#AC_SUBST(LIBGCRYPT_CFLAGS)
#AC_SUBST(LIBGCRYPT_LIBS)
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_VERSION",,
 	AC_MSG_ERROR([[
***  
*** libgcrypt was not found. You may want to get it from
*** ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgcrypt/
***
]]))


#
# libassuan is used for IPC
#
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_VERSION",
                  have_libasssuan=yes,have_libasssun=no)
if test "$have_libassuan" = "no"; then
    AC_MSG_ERROR([[
***
*** You need libassuan to build this program..
*** It should be available at the same place you 
*** got this software.
***]])
fi


#
# libksba is our X.509 support library
#
AM_PATH_KSBA("$NEED_KSBA_VERSION",have_ksba=yes,have_ksba=no)
if test "$have_ksba" = "no"; then
    AC_MSG_ERROR([[
***
*** You need libksba to build this program..
*** It should be available at the same place you 
*** got this software.
***]])
fi


#
# OpenSC is needed by the SCdaemon - if it is not availbale we can only
# build a limited SCdaemon
#
AM_PATH_OPENSC("$NEED_OPENSC_VERSION",have_opensc=yes,have_opensc=no)
if test $have_opensc = yes; then
  AC_DEFINE(HAVE_OPENSC,1,
            [defined if the OpenSC library is available])
fi


#
# Check whether the (highly desirable) GNU Pth library is available
#
AC_ARG_WITH(pth-prefix,
            AC_HELP_STRING([--with-pth-prefix=PFX],
                           [prefix where GNU Pth is installed (optional)]),
     pth_config_prefix="$withval", pth_config_prefix="")
if test x$pth_config_prefix != x ; then
   PTH_CONFIG="$pth_config_prefix/bin/pth-config"
fi
AC_PATH_PROG(PTH_CONFIG, pth-config, no)
if test "$PTH_CONFIG" = "no"; then
    AC_MSG_WARN([[
***
*** To support concurrent access to the gpg-agent and the SCdaemon
*** we need the support of the GNU Portable Threads Library.
*** Download it from ftp://ftp.gnu.org/gnu/pth/
*** On a Debian GNU/Linux system you might want to try 
***   apt-get install libpth-dev
***]])
else
  GNUPG_PTH_VERSION_CHECK(1.3.7)
  if test $have_pth = yes; then      
     PTH_CFLAGS=`$PTH_CONFIG --cflags`
     PTH_LIBS=`$PTH_CONFIG --ldflags`
     PTH_LIBS="$PTH_LIBS `$PTH_CONFIG --libs`"
     AC_DEFINE(USE_GNU_PTH, 1,
              [Defined if the GNU Portable Thread Library should be used])
  fi
fi
AC_SUBST(PTH_CFLAGS)
AC_SUBST(PTH_LIBS)

AM_GNU_GETTEXT

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h locale.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)

GNUPG_SYS_SO_PEERCRED

# Checks for library functions.

# These are needed by libjnlib - fixme: we should have a macros for them
AC_CHECK_FUNCS(memicmp stpcpy strlwr strtoul memmove stricmp strtol)
AC_CHECK_FUNCS(getrusage setrlimit stat setlocale)
AC_CHECK_FUNCS(flockfile funlockfile)

AC_CHECK_FUNCS(sigaction sigprocmask)

AC_REPLACE_FUNCS(vasprintf)
AC_REPLACE_FUNCS(fopencookie)
# FIXME: Print a warning when fopencookie is not available.
AC_REPLACE_FUNCS(mkdtemp)
AC_REPLACE_FUNCS(fseeko ftello)
AC_REPLACE_FUNCS(isascii)
AC_REPLACE_FUNCS(putc_unlocked)

# We use jnlib, so tell other modules about it
AC_DEFINE(HAVE_JNLIB_LOGGING, 1,
        [Defined if jnlib style logging fucntions are available])


#
# Decide what to build
#
if test $have_ksba = no; then
  build_gpgsm=no
  build_scdaemon=no
fi

build_agent_threaded=""
if test "$build_agent" = "yes"; then
  if test $have_pth = no; then
     build_agent_threaded="(not multi-threaded)"
  fi
fi

build_scdaemon_extra=""
if test "$build_scdaemon" = "yes"; then
  tmp=""
  if test $have_pth = no; then
     build_scdaemon_extra="not multi-threaded"
     tmp=", "
  fi
  if test $have_opensc = no; then
     build_scdaemon_extra="${build_scdaemon_extra}${tmp}no pkcs#15"
     tmp=", "
  fi      
  if test -n "$build_scdaemon_extra"; then
     build_scdaemon_extra="(${build_scdaemon_extra})"
  fi
fi


AM_CONDITIONAL(BUILD_GPG,   test "$build_gpg" = "yes")
AM_CONDITIONAL(BUILD_GPGSM, test "$build_gpgsm" = "yes")
AM_CONDITIONAL(BUILD_AGENT, test "$build_agent" = "yes")
AM_CONDITIONAL(BUILD_SCDAEMON, test "$build_scdaemon" = "yes")


AC_CONFIG_FILES([ m4/Makefile 
Makefile
po/Makefile.in
intl/Makefile
jnlib/Makefile
common/Makefile
kbx/Makefile
g10/Makefile
sm/Makefile
agent/Makefile
scd/Makefile
doc/Makefile
tests/Makefile
])
AC_OUTPUT


echo "
        GnuPG v${VERSION} has been configured as follows:
        
        OpenPGP:   $build_gpg
        S/MIME:    $build_gpgsm
        Agent:     $build_agent $build_agent_threaded
        Smartcard: $build_scdaemon $build_scdaemon_extra

        Protect tool:     $gnupg_protect_tool
        Default agent:    $gnupg_agent_pgm
        Default pinentry: $gnupg_pinentry_pgm
        Default scdaemon: $gnupg_scdaemon_pgm
        Default dirmngr:  $gnupg_dirmngr_pgm
"

