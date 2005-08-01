# configure.ac - for GnuPG 1.9
# Copyright (C) 1998, 1999, 2000, 2001, 2002,
#               2003, 2004, 2005 Free Software Foundation, Inc.
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
min_automake_version="1.9.3"

# Version number: Remember to change it immediately *after* a release.
#                 Add a "-cvs" prefix for non-released code.
AC_INIT(gnupg, 1.9.18, gnupg-devel@gnupg.org)
# Set development_version to yes if the minor number is odd or you
# feel that the default check for a development version is not
# sufficient.
development_version=yes
NEED_GPG_ERROR_VERSION=1.0

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.1.94

NEED_LIBASSUAN_VERSION=0.6.10

NEED_KSBA_VERSION=0.9.12


PACKAGE=$PACKAGE_NAME
PACKAGE_GT=${PACKAGE_NAME}2
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR(scripts)
AC_CONFIG_SRCDIR(sm/gpgsm.c)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

AC_GNU_SOURCE

# Some status variables to give feedback at the end of a configure run
have_gpg_error=no
have_libgcrypt=no 
have_libassuan=no
have_ksba=no
have_pth=no

GNUPG_BUILD_PROGRAM(gpg, no)
GNUPG_BUILD_PROGRAM(gpgsm, yes)
GNUPG_BUILD_PROGRAM(agent, yes)
GNUPG_BUILD_PROGRAM(scdaemon, yes)
GNUPG_BUILD_PROGRAM(symcryptrun, no)


AC_SUBST(PACKAGE)
AC_SUBST(PACKAGE_GT)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(PACKAGE_GT, "$PACKAGE_GT",
                                [Name of this package for gettext])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",
                                        [Bug report address])
AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION, "$NEED_LIBGCRYPT_VERSION",
                                       [Required version of Libgcrypt])
AC_DEFINE_UNQUOTED(NEED_KSBA_VERSION, "$NEED_KSBA_VERSION",
                                       [Required version of Libksba])



# The default is to use the modules from this package and the few
# other packages in a standard place; i.e where this package gets
# installed.  With these options it is possible to override these
# ${prefix} depended values with fixed paths, which can't be replaced
# at make time.  See also am/cmacros.am and the defaults in AH_BOTTOM.
AC_ARG_WITH(agent-pgm,
    [  --with-agent-pgm=PATH  Use PATH as the default for the agent)],
          GNUPG_AGENT_PGM="$withval", GNUPG_AGENT_PGM="" )
AC_SUBST(GNUPG_AGENT_PGM)
AM_CONDITIONAL(GNUPG_AGENT_PGM, test -n "$GNUPG_AGENT_PGM")
show_gnupg_agent_pgm="(default)"
test -n "$GNUPG_AGENT_PGM" && show_gnupg_agent_pgm="$GNUPG_AGENT_PGM"

AC_ARG_WITH(pinentry-pgm,
    [  --with-pinentry-pgm=PATH  Use PATH as the default for the pinentry)],
          GNUPG_PINENTRY_PGM="$withval", GNUPG_PINENTRY_PGM="" )
AC_SUBST(GNUPG_PINENTRY_PGM)
AM_CONDITIONAL(GNUPG_PINENTRY_PGM, test -n "$GNUPG_PINENTRY_PGM")
show_gnupg_pinentry_pgm="(default)"
test -n "$GNUPG_PINENTRY_PGM" && show_gnupg_pinentry_pgm="$GNUPG_PINENTRY_PGM"


AC_ARG_WITH(scdaemon-pgm,
    [  --with-scdaemon-pgm=PATH  Use PATH as the default for the scdaemon)],
          GNUPG_SCDAEMON_PGM="$withval", GNUPG_SCDAEMON_PGM="" )
AC_SUBST(GNUPG_SCDAEMON_PGM)
AM_CONDITIONAL(GNUPG_SCDAEMON_PGM, test -n "$GNUPG_SCDAEMON_PGM")
show_gnupg_scdaemon_pgm="(default)"
test -n "$GNUPG_SCDAEMON_PGM" && show_gnupg_scdaemon_pgm="$GNUPG_SCDAEMON_PGM"


AC_ARG_WITH(dirmngr-pgm,
    [  --with-dirmngr-pgm=PATH  Use PATH as the default for the dirmngr)],
          GNUPG_DIRMNGR_PGM="$withval", GNUPG_DIRMNGR_PGM="" )
AC_SUBST(GNUPG_DIRMNGR_PGM)
AM_CONDITIONAL(GNUPG_DIRMNGR_PGM, test -n "$GNUPG_DIRMNGR_PGM")
show_gnupg_dirmngr_pgm="(default)"
test -n "$GNUPG_DIRMNGR_PGM" && show_gnupg_dirmngr_pgm="$GNUPG_DIRMNGR_PGM"

AC_ARG_WITH(protect-tool-pgm,
    [  --with-protect-tool-pgm=PATH  Use PATH as the default for the protect-tool)],
          GNUPG_PROTECT_TOOL_PGM="$withval", GNUPG_PROTECT_TOOL_PGM="" )
AC_SUBST(GNUPG_PROTECT_TOOL_PGM)
AM_CONDITIONAL(GNUPG_PROTECT_TOOL_PGM, test -n "$GNUPG_PROTECT_TOOL_PGM")
show_gnupg_protect_tool_pgm="(default)"
test -n "$GNUPG_PROTECT_TOOL_PGM" \
      && show_gnupg_protect_tool_pgm="$GNUPG_PROTECT_TOOL_PGM"



# Some folks want to use only the agent form this packet.  Make it
# easier for them by providing the configure option
# --enable-only-agent.
AC_ARG_ENABLE(agent-only,
    AC_HELP_STRING([--enable-agent-only],[build only the gpg-agent]),
    build_agent_only=$enableval)


# Configure option to allow or disallow execution of external
# programs, like a photo viewer.
AC_MSG_CHECKING([whether to enable external program execution])
AC_ARG_ENABLE(exec,
    AC_HELP_STRING([--disable-exec],[disable all external program execution]),
    use_exec=$enableval)
AC_MSG_RESULT($use_exec)
if test "$use_exec" = no ; then
    AC_DEFINE(NO_EXEC,1,[Define to disable all external program execution])
fi

if test "$use_exec" = yes ; then
  AC_MSG_CHECKING([whether to enable photo ID viewing])
  AC_ARG_ENABLE(photo-viewers,
      [  --disable-photo-viewers disable photo ID viewers],
      [if test "$enableval" = no ; then
         AC_DEFINE(DISABLE_PHOTO_VIEWER,1,[define to disable photo viewing])
      fi],enableval=yes)
  gnupg_cv_enable_photo_viewers=$enableval
  AC_MSG_RESULT($enableval)

  if test "$gnupg_cv_enable_photo_viewers" = yes ; then
    AC_MSG_CHECKING([whether to use a fixed photo ID viewer])
    AC_ARG_WITH(photo-viewer,
        [  --with-photo-viewer=FIXED_VIEWER  set a fixed photo ID viewer],
        [if test "$withval" = yes ; then
           withval=no
        elif test "$withval" != no ; then
           AC_DEFINE_UNQUOTED(FIXED_PHOTO_VIEWER,"$withval",
  	                    [if set, restrict photo-viewer to this])
        fi],withval=no)
    AC_MSG_RESULT($withval)
  fi

  AC_MSG_CHECKING([whether to enable external keyserver helpers])
  AC_ARG_ENABLE(keyserver-helpers,
      [  --disable-keyserver-helpers  disable all external keyserver support],
      [if test "$enableval" = no ; then
         AC_DEFINE(DISABLE_KEYSERVER_HELPERS,1,
                  [define to disable keyserver helpers])
      fi],enableval=yes)
  gnupg_cv_enable_keyserver_helpers=$enableval
  AC_MSG_RESULT($enableval)

  if test "$gnupg_cv_enable_keyserver_helpers" = yes ; then
    AC_MSG_CHECKING([whether LDAP keyserver support is requested])
    AC_ARG_ENABLE(ldap,
    [  --disable-ldap          disable LDAP keyserver interface],
        try_ldap=$enableval, try_ldap=yes)
    AC_MSG_RESULT($try_ldap)

    AC_MSG_CHECKING([whether HKP keyserver support is requested])
    AC_ARG_ENABLE(hkp,
    [  --disable-hkp           disable HKP keyserver interface],
        try_hkp=$enableval, try_hkp=yes)
    AC_MSG_RESULT($try_hkp)

    if test "$try_hkp" = yes ; then
      AC_SUBST(GPGKEYS_HKP,"gpgkeys_hkp$EXEEXT")
    fi

    AC_MSG_CHECKING([whether email keyserver support is requested])
    AC_ARG_ENABLE(mailto,
    [  --disable-mailto        disable email keyserver interface],
        try_mailto=$enableval, try_mailto=yes)
    AC_MSG_RESULT($try_mailto)
    fi

    AC_MSG_CHECKING([whether keyserver exec-path is enabled])
    AC_ARG_ENABLE(keyserver-path,
        [  --disable-keyserver-path disable the exec-path option for keyserver helpers],
        [if test "$enableval" = no ; then
  	 AC_DEFINE(DISABLE_KEYSERVER_PATH,1,[define to disable exec-path for keyserver helpers])
        fi],enableval=yes)
    AC_MSG_RESULT($enableval)
  fi

dnl
dnl Check whether we want to use Linux capabilities
dnl
AC_MSG_CHECKING([whether use of capabilities is requested])
AC_ARG_WITH(capabilities,
    [  --with-capabilities     use linux capabilities [default=no]],
[use_capabilities="$withval"],[use_capabilities=no])
AC_MSG_RESULT($use_capabilities)


AH_BOTTOM([
/* Some global constants. */
#ifdef HAVE_DRIVE_LETTERS
#define GNUPG_DEFAULT_HOMEDIR "c:/gnupg"
#elif defined(__VMS)
#define GNUPG_DEFAULT_HOMEDIR "/SYS\$LOGIN/gnupg" 
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.gnupg"
#endif 
#define GNUPG_PRIVATE_KEYS_DIR "private-keys-v1.d"

/* Tell libgcrypt not to use its own libgpg-error implementation. */
#define USE_LIBGPG_ERROR 1

/* This is the major version number of GnuPG so that
   source included files can test for this.  Note, that\
   we use 2 here even for GnuPG 1.9.x. */
#define GNUPG_MAJOR_VERSION 2

/* Now to separate file name parts.
   Please note that the string version must not contain more
   than one character because the code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\'
#define DIRSEP_S "\\"
#define EXTSEP_C '.'
#define EXTSEP_S "."
#define PATHSEP_C ';'
#define PATHSEP_S ";"
#define EXEEXT_S ".exe"
#else
#define DIRSEP_C '/'
#define DIRSEP_S "/"
#define EXTSEP_C '.'
#define EXTSEP_S "."
#define PATHSEP_C ':'
#define PATHSEP_S ":"
#define EXEEXT_S ""
#endif

/* This is the same as VERSION, but should be overridden if the
   platform cannot handle things like dots '.' in filenames. Set
   SAFE_VERSION_DOT and SAFE_VERSION_DASH to whatever SAFE_VERSION
   uses for dots and dashes. */
#define SAFE_VERSION VERSION
#define SAFE_VERSION_DOT  '.'
#define SAFE_VERSION_DASH '-'

/* For some systems (DOS currently), we hardcode the path here.  For
   POSIX systems the values are constructed by the Makefiles, so that
   the values may be overridden by the make invocations; this is to
   comply with the GNU coding standards. */
#ifdef HAVE_DRIVE_LETTERS
#define GNUPG_BINDIR      "c:\\gnupg"
#define GNUPG_LIBEXECDIR  "c:\\gnupg"
#define GNUPG_LIBDIR      "c:\\gnupg"
#define GNUPG_DATADIR     "c:\\gnupg"
#endif

/* Setup the hardwired names of modules. */
#ifndef GNUPG_DEFAULT_AGENT
#define GNUPG_DEFAULT_AGENT    ( GNUPG_BINDIR DIRSEP_S "gpg-agent" EXEEXT_S )
#endif
#ifndef GNUPG_DEFAULT_PINENTRY
#define GNUPG_DEFAULT_PINENTRY ( GNUPG_BINDIR DIRSEP_S "pinentry" EXEEXT_S )
#endif
#ifndef GNUPG_DEFAULT_SCDAEMON
#define GNUPG_DEFAULT_SCDAEMON ( GNUPG_BINDIR DIRSEP_S "scdaemon" EXEEXT_S )
#endif
#ifndef GNUPG_DEFAULT_DIRMNGR
#define GNUPG_DEFAULT_DIRMNGR  ( GNUPG_BINDIR DIRSEP_S "dirmngr" EXEEXT_S )
#endif
#ifndef GNUPG_DEFAULT_PROTECT_TOOL
#define GNUPG_DEFAULT_PROTECT_TOOL \
                    ( GNUPG_LIBEXECDIR DIRSEP_S "gpg-protect-tool" EXEEXT_S )
#endif


/* Derive some other constants. */
#if !(defined(HAVE_FORK) && defined(HAVE_PIPE) && defined(HAVE_WAITPID))
#define EXEC_TEMPFILE_ONLY
#endif

/* Temporary hacks to avoid requring a libgpg-error update. */
#if !HAVE_DECL_GPG_ERR_LOCKED
#define GPG_ERR_LOCKED  173
#endif

])

AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_MAKE_SET
AM_SANITY_CHECK
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
AC_CHECK_TOOL(AR, ar, :)
AC_PATH_PROG(PERL,"perl")
AC_ISC_POSIX
gl_EARLY
AC_SYS_LARGEFILE
AC_CHECK_PROG(DOCBOOK_TO_MAN, docbook-to-man, yes, no)
AM_CONDITIONAL(HAVE_DOCBOOK_TO_MAN, test "$ac_cv_prog_DOCBOOK_TO_MAN" = yes)
GNUPG_CHECK_FAQPROG
GNUPG_CHECK_DOCBOOK_TO_TEXI


try_gettext=yes
have_dosish_system=no
have_w32_system=no
case "${host}" in
    *-mingw32*)
        # special stuff for Windoze NT
        ac_cv_have_dev_random=no
        AC_DEFINE(USE_ONLY_8DOT3,1,
                  [set this to limit filenames to the 8.3 format])
        AC_DEFINE(HAVE_DRIVE_LETTERS,1,
                  [defined if we must run on a stupid file system])
        AC_DEFINE(USE_SIMPLE_GETTEXT,1,
                  [because the Unix gettext has too much overhead on
                   MingW32 systems and these systems lack Posix functions,
                   we use a simplified version of gettext])
        have_dosish_system=yes
        have_w32_system=yes
        try_gettext="no"
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        # OS/2 with the EMX environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        have_dosish_system=yes
        try_gettext="no"
        ;;

    i?86-*-msdosdjgpp*)
        # DOS with the DJGPP environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        have_dosish_system=yes
        try_gettext="no"
        ;;

    *-*-freebsd*)
       # FreeBSD
       CPPFLAGS="$CPPFLAGS -I/usr/local/include"
       LDFLAGS="$LDFLAGS -L/usr/local/lib"
       ;;

    *-*-hpux*)
        if test -z "$GCC" ; then
            CFLAGS="$CFLAGS -Ae -D_HPUX_SOURCE"
        fi
        ;;
    *-dec-osf4*)
        if test -z "$GCC" ; then
            # Suppress all warnings
            # to get rid of the unsigned/signed char mismatch warnings.
            CFLAGS="$CFLAGS -w"
        fi
        ;;
    *-dec-osf5*)
        if test -z "$GCC" ; then
            # Use the newer compiler `-msg_disable ptrmismatch' to
            # get rid of the unsigned/signed char mismatch warnings.
            # Using this may hide other pointer mismatch warnings, but
	    # it at least lets other warning classes through
            CFLAGS="$CFLAGS -msg_disable ptrmismatch"
        fi
        ;;
    m68k-atari-mint)
        ;;
    *)
       ;;
esac

if test "$have_dosish_system" = yes; then
   AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
             [Defined if we run on some of the PCDOS like systems 
              (DOS, Windoze. OS/2) with special properties like
              no file modes])
fi
AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = yes)

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)



#
# Checks for libraries.
#


#
# libgpg-error is a library with error codes shared between GnuPG
# related projects.
#
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)
_tmp_gpg_error_save_cflags="$CFLAGS"
CFLAGS="$CFLAGS $GPG_ERROR_CFLAGS"
AC_CHECK_DECLS(GPG_ERR_LOCKED,,,[#include <gpg-error.h>])
CFLAGS="${_tmp_gpg_error_save_cflags}"


#
# Libgcrypt is our generic crypto library
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
        have_libgcrypt=yes,have_libgcrypt=no)


#
# libassuan is used for IPC
#
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_VERSION",
                  have_libassuan=yes,have_libassuan=no)


#
# libksba is our X.509 support library
#
AM_PATH_KSBA("$NEED_KSBA_VERSION",have_ksba=yes,have_ksba=no)

#
# libusb allows us to use the integrated CCID smartcard reader driver.
#
AC_CHECK_LIB(usb, usb_bulk_write,
              [ LIBUSB_LIBS="$LIBUSB_LIBS -lusb"
                AC_DEFINE(HAVE_LIBUSB,1,
                         [defined if libusb is available])
             ])
AC_SUBST(LIBUSB_LIBS)
AC_CHECK_FUNCS(usb_create_match)

#
# Check wether it is necessary to link against libdl.
#
LIBS=""
AC_SEARCH_LIBS(dlopen, c dl,,,)
DL_LIBS=$LIBS
AC_SUBST(DL_LIBS)

#
# Checks for symcryptrun:
#

# libutil has openpty() and login_tty().
AC_CHECK_LIB(util, openpty,
              [ LIBUTIL_LIBS="$LIBUTIL_LIBS -lutil"
                AC_DEFINE(HAVE_LIBUTIL,1,
                         [defined if libutil is available])
             ])
AC_SUBST(LIBUTIL_LIBS)

# shred is used to clean temporary plain text files.
AC_PATH_PROG(SHRED, shred, /usr/bin/shred)
AC_DEFINE_UNQUOTED(SHRED,
	"${SHRED}", [defines the filename of the shred program])


#
# Check whether the (highly desirable) GNU Pth library is available
# Note, that we include a Pth emulation for W32.
#
AC_ARG_WITH(pth-prefix,
            AC_HELP_STRING([--with-pth-prefix=PFX],
                           [prefix where GNU Pth is installed (optional)]),
     pth_config_prefix="$withval", pth_config_prefix="")
if test x$pth_config_prefix != x ; then
   PTH_CONFIG="$pth_config_prefix/bin/pth-config"
fi
AC_PATH_PROG(PTH_CONFIG, pth-config, no)
if test "$have_w32_system" = no; then
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
     AC_DEFINE(HAVE_PTH, 1,
              [Defined if the GNU Pth is available])
  fi
 fi
else 
 have_pth=yes
 PTH_CFLAGS=""
 PTH_LIBS=""
 AC_DEFINE(USE_GNU_PTH, 1)
 AC_DEFINE(HAVE_PTH, 1)
fi
AC_SUBST(PTH_CFLAGS)
AC_SUBST(PTH_LIBS)


dnl Must check for network library requirements before doing link tests
dnl for ldap, for example. If ldap libs are static (or dynamic and without
dnl ELF runtime link paths), then link will fail and LDAP support won't
dnl be detected.

AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))

dnl Now try for the resolver functions so we can use DNS SRV

AC_ARG_ENABLE(dns-srv,
   AC_HELP_STRING([--disable-dns-srv],[disable the use of DNS SRV in HKP]),
   use_dns_srv=$enableval,use_dns_srv=yes)

if test x"$try_hkp" = xyes && test x"$use_dns_srv" = xyes ; then
  _srv_save_libs=$LIBS
  LIBS=""
  # the double underscore thing is a glibc-ism?
  AC_SEARCH_LIBS(res_query,resolv bind,,
                 AC_SEARCH_LIBS(__res_query,resolv bind,,use_dns_srv=no))
  AC_SEARCH_LIBS(dn_expand,resolv bind,,
                 AC_SEARCH_LIBS(__dn_expand,resolv bind,,use_dns_srv=no))
  AC_SEARCH_LIBS(dn_skipname,resolv bind,,
                 AC_SEARCH_LIBS(__dn_skipname,resolv bind,,use_dns_srv=no))

  if test x"$use_dns_srv" = xyes ; then
     AC_DEFINE(USE_DNS_SRV,1,[define to use DNS SRV])
     SRVLIBS=$LIBS
  else
     AC_MSG_WARN([Resolver functions not found.  Disabling DNS SRV.])
  fi
  LIBS=$_srv_save_libs
fi

AC_SUBST(SRVLIBS)

# Try and link a LDAP test program to weed out unusable LDAP
# libraries.  -lldap [-llber [-lresolv]] is for OpenLDAP.  OpenLDAP in
# general is terrible with creating weird dependencies.  If all else
# fails, the user can play guess-the-dependency by using something
# like ./configure LDAPLIBS="-Lfoo -lbar"

if test "$try_ldap" = yes ; then
  for MY_LDAPLIBS in ${LDAPLIBS+"$LDAPLIBS"} "-lldap" "-lldap -llber" "-lldap -llber -lresolv"; do
    _ldap_save_libs=$LIBS
    LIBS="$MY_LDAPLIBS $NETLIBS $LIBS"

    AC_MSG_CHECKING([whether LDAP via \"$MY_LDAPLIBS\" is present and sane])
    AC_TRY_LINK([#include <ldap.h>],[ldap_open("foobar",1234);],
                [gnupg_cv_func_ldap_init=yes],[gnupg_cv_func_ldap_init=no])
    AC_MSG_RESULT([$gnupg_cv_func_ldap_init])

    if test $gnupg_cv_func_ldap_init = no; then
      AC_MSG_CHECKING([whether I can make LDAP be sane with lber.h])
      AC_TRY_LINK([#include <lber.h>
#include <ldap.h>],[ldap_open("foobar",1234);],
         [gnupg_cv_func_ldaplber_init=yes],[gnupg_cv_func_ldaplber_init=no])
      AC_MSG_RESULT([$gnupg_cv_func_ldaplber_init])
    fi

    if test "$gnupg_cv_func_ldaplber_init" = yes ; then
       AC_DEFINE(NEED_LBER_H,1,[Define if the LDAP library requires including lber.h before ldap.h])
    fi

    if test "$gnupg_cv_func_ldap_init" = yes || \
  	test "$gnupg_cv_func_ldaplber_init" = yes ; then
       LDAPLIBS=$MY_LDAPLIBS
       GPGKEYS_LDAP="gpgkeys_ldap$EXEEXT"

       AC_MSG_CHECKING([whether LDAP supports ldap_get_option])

       if test "$gnupg_cv_func_ldap_init" = yes ; then
	  AC_TRY_LINK([#include <ldap.h>],
	     [ldap_get_option((void *)0,0,(void *)0);],
	     [gnupg_cv_func_ldap_get_option=yes],
	     [gnupg_cv_func_ldap_get_option=no])
	else
	  AC_TRY_LINK([#include <lber.h>
#include <ldap.h>],[ldap_get_option((void *)0,0,(void *)0);],
	     [gnupg_cv_func_ldap_get_option=yes],
	     [gnupg_cv_func_ldap_get_option=no])
       fi

       AC_MSG_RESULT([$gnupg_cv_func_ldap_get_option])

       if test "$gnupg_cv_func_ldap_get_option" = yes ; then
          AC_DEFINE(HAVE_LDAP_GET_OPTION,1,[Define if the LDAP library has ldap_get_option])
       else
          AC_MSG_CHECKING([whether LDAP supports ld_errno])

	  if test "$gnupg_cv_func_ldap_init" = yes ; then
	    AC_TRY_COMPILE([#include <ldap.h>],
	       [LDAP *ldap; ldap->ld_errno;],
	       [gnupg_cv_func_ldap_ld_errno=yes],
	       [gnupg_cv_func_ldap_ld_errno=no])
	   else
	    AC_TRY_LINK([#include <lber.h>
#include <ldap.h>],[LDAP *ldap; ldap->ld_errno;],
	       [gnupg_cv_func_ldap_ld_errno=yes],
	       [gnupg_cv_func_ldap_ld_errno=no])
          fi

          AC_MSG_RESULT([$gnupg_cv_func_ldap_ld_errno])

	  if test "$gnupg_cv_func_ldap_ld_errno" = yes ; then
	     AC_DEFINE(HAVE_LDAP_LD_ERRNO,1,[Define if the LDAP library supports ld_errno])
          fi
       fi
    fi

    LIBS=$_ldap_save_libs

    if test "$GPGKEYS_LDAP" != "" ; then break; fi
  done
fi

AC_SUBST(GPGKEYS_LDAP)
AC_SUBST(LDAPLIBS)

dnl This isn't necessarily sendmail itself, but anything that gives a
dnl sendmail-ish interface to the outside world.  That includes qmail,
dnl postfix, etc.  Basically, anything that can handle "sendmail -t".

if test "$try_mailto" = yes ; then
  AC_ARG_WITH(mailprog,[  --with-mailprog=NAME    use "NAME -t" for mail transport],,with_mailprog=yes)

  if test "$with_mailprog" = yes ; then
    AC_PATH_PROG(SENDMAIL,sendmail,,$PATH:/usr/sbin:/usr/libexec:/usr/lib)
    if test "$ac_cv_path_SENDMAIL" ; then
      GPGKEYS_MAILTO="gpgkeys_mailto"
    fi
  elif test "$with_mailprog" != no ; then
    AC_MSG_CHECKING([for a mail transport program])
    AC_SUBST(SENDMAIL,$with_mailprog)
    AC_MSG_RESULT($with_mailprog)
    GPGKEYS_MAILTO="gpgkeys_mailto"
  fi
fi

AC_SUBST(GPGKEYS_MAILTO)

case "${host}" in
    *-mingw32*)
        PRINTABLE_OS_NAME="MingW32"
        ;;
    *-*-cygwin*)
        PRINTABLE_OS_NAME="Cygwin"
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
    *)
        PRINTABLE_OS_NAME=`uname -s || echo "Unknown"`
        ;;
esac
AC_DEFINE_UNQUOTED(PRINTABLE_OS_NAME, "$PRINTABLE_OS_NAME",
                   [A human readable text with the name of the OS])


AM_GNU_GETTEXT_VERSION(0.14.1)
if test "$try_gettext" = yes; then
  AM_GNU_GETTEXT(,[need-ngettext])

  # gettext requires some extra checks.  These really should be part of
  # the basic AM_GNU_GETTEXT macro.  TODO: move other gettext-specific
  # function checks to here.

  AC_CHECK_FUNCS(strchr)
else
  USE_NLS=no
  USE_INCLUDED_LIBINTL=no
  BUILD_INCLUDED_LIBINTL=no
  AC_SUBST(USE_NLS)
  AC_SUBST(USE_INCLUDED_LIBINTL)
  AC_SUBST(BUILD_INCLUDED_LIBINTL)
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(string.h unistd.h langinfo.h termio.h locale.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

GNUPG_CHECK_ENDIAN

GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)

AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)
# Ensure that we have UINT64_C before we bother to check for uint64_t
# fixme: really needed in gnupg?  I think it is only useful in libcgrypt.
AC_CACHE_CHECK([for UINT64_C],[gnupg_cv_uint64_c_works],
   AC_COMPILE_IFELSE(AC_LANG_PROGRAM([#include <inttypes.h>
uint64_t foo=UINT64_C(42);]),gnupg_cv_uint64_c_works=yes,gnupg_cv_uint64_c_works=no))
if test "$gnupg_cv_uint64_c_works" = "yes" ; then
   AC_CHECK_SIZEOF(uint64_t)
fi
 



if test "$ac_cv_sizeof_unsigned_short" = "0" \
   || test "$ac_cv_sizeof_unsigned_int" = "0" \
   || test "$ac_cv_sizeof_unsigned_long" = "0"; then
    AC_MSG_WARN([Hmmm, something is wrong with the sizes - using defaults]);
fi

dnl Do we have any 64-bit data types?
if test "$ac_cv_sizeof_unsigned_int" != "8" \
   && test "$ac_cv_sizeof_unsigned_long" != "8" \
   && test "$ac_cv_sizeof_unsigned_long_long" != "8" \
   && test "$ac_cv_sizeof_uint64_t" != "8"; then
    AC_MSG_WARN([No 64-bit types.  Disabling SHA-384, and SHA-512])
else
  if test x"$use_sha512" = xyes ; then
     AC_SUBST(SHA512_O,sha512.o)
     AC_DEFINE(USE_SHA512,1,[Define to include the SHA-384 and SHA-512 digests])
  fi
fi

# fixme: do we really need this - it should be encapsulated in libassuan
GNUPG_SYS_SO_PEERCRED

# Checks for library functions.
AC_FUNC_FSEEKO
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_CHECK_FUNCS(strerror stpcpy strsep strlwr tcgetattr strtoul mmap)
AC_CHECK_FUNCS(strcasecmp strncasecmp ctermid times gmtime_r)
AC_CHECK_FUNCS(memmove gettimeofday getrusage setrlimit clock_gettime)
AC_CHECK_FUNCS(atexit raise getpagesize strftime nl_langinfo setlocale)
AC_CHECK_FUNCS(waitpid wait4 sigaction sigprocmask rand pipe stat getaddrinfo)
AC_CHECK_FUNCS(fseeko ftello ttyname isascii)

AC_CHECK_TYPES([struct sigaction, sigset_t],,,[#include <signal.h>])

# gnulib checks
gl_SOURCE_BASE(gl)
gl_M4_BASE(gl/m4)
gl_MODULES(setenv strsep mkdtemp vasprintf xsize)
gl_INIT

# These are needed by libjnlib - fixme: we should have macros for them
AC_CHECK_FUNCS(memicmp stpcpy strlwr strtoul memmove stricmp strtol)
AC_CHECK_FUNCS(getrusage setrlimit stat setlocale)
AC_CHECK_FUNCS(flockfile funlockfile fopencookie funopen)


#
# check for gethrtime and run a testprogram to see whether
# it is broken.  It has been reported that some Solaris and HP UX systems 
# raise an SIGILL
#
#  fixme: Do we need this - iirc, this is only used by libgcrypt.
#
AC_CACHE_CHECK([for gethrtime], 
               [gnupg_cv_func_gethrtime],
               [AC_TRY_LINK([#include <sys/times.h>],[
                   hrtime_t tv;
                   tv = gethrtime();
                 ],
                 [gnupg_cv_func_gethrtime=yes],
                 [gnupg_cv_func_gethrtime=no])
               ])
if test $gnupg_cv_func_gethrtime = yes; then
     AC_DEFINE([HAVE_GETHRTIME], 1,
               [Define if you have the `gethrtime(2)' function.])
     AC_CACHE_CHECK([whether gethrtime is broken], 
               [gnupg_cv_func_broken_gethrtime],
               [AC_TRY_RUN([
                   #include <sys/times.h>
                   int main () {
                   hrtime_t tv;
                   tv = gethrtime(); 
                 }
                 ],
                 [gnupg_cv_func_broken_gethrtime=no],
                 [gnupg_cv_func_broken_gethrtime=yes],
                 [gnupg_cv_func_broken_gethrtime=assume-no])
                ])
    if test $gnupg_cv_func_broken_gethrtime = yes; then
      AC_DEFINE([HAVE_BROKEN_GETHRTIME], 1,
      [Define if `gethrtime(2)' does not work correctly i.e. issues a SIGILL.])
    fi
fi
     

GNUPG_CHECK_MLOCK
GNUPG_FUNC_MKDIR_TAKES_ONE_ARG

dnl
dnl Check whether we can use Linux capabilities as requested
dnl
#  fixme: Still required?
#
if test "$use_capabilities" = "yes" ; then
use_capabilities=no
AC_CHECK_HEADERS(sys/capability.h)
if test "$ac_cv_header_sys_capability_h" = "yes" ; then
  AC_CHECK_LIB(cap, cap_init, ac_need_libcap=1)
  if test "$ac_cv_lib_cap_cap_init" = "yes"; then
     AC_DEFINE(USE_CAPABILITIES,1,
               [define if capabilities should be used])
     AC_SUBST(CAPLIBS,"-lcap")
     use_capabilities=yes
  fi
fi
if test "$use_capabilities" = "no" ; then
    AC_MSG_WARN([[
***
*** The use of capabilities on this system is not possible.
*** You need a recent Linux kernel and some patches:
***   fcaps-2.2.9-990610.patch      (kernel patch for 2.2.9)
***   fcap-module-990613.tar.gz     (kernel module)
***   libcap-1.92.tar.gz            (user mode library and utilities)
*** And you have to configure the kernel with CONFIG_VFS_CAP_PLUGIN
*** set (filesystems menu). Be warned: This code is *really* ALPHA.
***]])
fi
fi


# Sanity check regex.  Tests adapted from mutt.

AC_MSG_CHECKING([whether regular expression support is requested])
AC_ARG_ENABLE(regex,
[  --disable-regex         do not handle regular expressions in trust sigs],
     use_regex=$enableval, use_regex=yes)
AC_MSG_RESULT($use_regex)

if test "$use_regex" = yes ; then
  AC_MSG_CHECKING([whether the included regex lib is requested])
  AC_ARG_WITH(included-regex,
      [  --with-included-regex   use the included GNU regex library],
      [gnupg_cv_included_regex="$withval"],[gnupg_cv_included_regex=no])
  AC_MSG_RESULT($gnupg_cv_included_regex)

  if test $gnupg_cv_included_regex = no ; then
     # Does the system have regex functions at all?
     AC_CHECK_FUNC(regcomp,gnupg_cv_included_regex=no,
			   gnupg_cv_included_regex=yes)
  fi

  if test $gnupg_cv_included_regex = no ; then
     AC_CACHE_CHECK([whether your system's regexp library is broken],
       [gnupg_cv_regex_broken],
       AC_TRY_RUN([
#include <unistd.h>
#include <regex.h>
main() { regex_t blah ; regmatch_t p; p.rm_eo = p.rm_eo; return regcomp(&blah, "foo.*bar", REG_NOSUB) || regexec (&blah, "foobar", 0, NULL, 0); }],
       gnupg_cv_regex_broken=no, gnupg_cv_regex_broken=yes, gnupg_cv_regex_broken=yes))

     if test $gnupg_cv_regex_broken = yes ; then
      AC_MSG_WARN(your regex is broken - using the included GNU regex instead.)
      gnupg_cv_included_regex=yes
     fi
  fi

  if test $gnupg_cv_included_regex = yes; then
     AC_DEFINE(USE_GNU_REGEX,1,[ Define if you want to use the included regex lib ])
     AC_SUBST(REGEX_O,regex.o)
  fi
else

  AC_DEFINE(DISABLE_REGEX,1,[ Define to disable regular expression support ])
fi

dnl Do we have zlib? Must do it here because Solaris failed
dnl when compiling a conftest (due to the "-lz" from LIBS).
_cppflags="${CPPFLAGS}"
_ldflags="${LDFLAGS}"

AC_ARG_WITH(zlib,
  [  --with-zlib=DIR         use libz in DIR],[
    if test -d "$withval"; then
      CPPFLAGS="${CPPFLAGS} -I$withval/include"
      LDFLAGS="${LDFLAGS} -L$withval/lib"
    fi
  ])

AC_CHECK_HEADER(zlib.h,
      AC_CHECK_LIB(z, deflateInit2_,
       LIBS="$LIBS -lz",
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})
 


# See wether we want to run the long test suite.
AC_ARG_WITH(pkits-tests,
    AC_HELP_STRING([--with-pkits-tests],[run the PKITS based tests]),
    [run_pkits_tests=$withval], [run_pkits_tests=no])
AM_CONDITIONAL(RUN_PKITS_TESTS, test "$run_pkits_tests" = "yes")


# Allow users to append something to the version string without
# flagging it as development version.  The user version parts is
# considered everything after a dash. 
if test "$development_version" != yes; then
  changequote(,)dnl
  tmp_pat='[a-zA-Z]'
  changequote([,])dnl
  if echo "$VERSION" | sed 's/-.*//' | grep "$tmp_pat" >/dev/null ; then
    development_version=yes
  fi
fi
if test "$development_version" = yes; then
    AC_DEFINE(IS_DEVELOPMENT_VERSION,1,
            [Defined if this is not a regular release])
fi

AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

GNUPG_CHECK_GNUMAKE

# Add some extra libs here so that previous tests don't fail for
# mysterious reasons - the final link step should bail out. 
if test "$have_w32_system" = yes; then
   W32LIBS="-lwsock32"
fi


if test "$GCC" = yes; then
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wno-format-y2k -Wformat-security"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

AC_SUBST(NETLIBS)
AC_SUBST(W32LIBS)


# We use jnlib, so tell other modules about it
AC_DEFINE(HAVE_JNLIB_LOGGING, 1,
          [Defined if jnlib style logging functions are available])

# For W32 we need to use our Pth emulation code
if test "$have_w32_system" = yes; then
  AC_CONFIG_LINKS(pth.h:jnlib/w32-pth.h)
fi


#
# Decide what to build
#
missing_pth=no
if test $have_ksba = no; then
  build_gpgsm=no
  build_scdaemon=no
fi

build_agent_threaded=""
if test "$build_agent" = "yes"; then
  if test $have_pth = no; then
     build_agent_threaded="(not multi-threaded)"
     missing_pth=yes
  fi
fi

build_scdaemon_extra=""
if test "$build_scdaemon" = "yes"; then
  tmp=""
  if test $have_pth = no; then
     build_scdaemon_extra="not multi-threaded"
     tmp=", "
     missing_pth=yes
  fi
  if test -n "$build_scdaemon_extra"; then
     build_scdaemon_extra="(${build_scdaemon_extra})"
  fi
fi


if test "$build_agent_only" = "yes" ; then
  build_gpg=no
  build_gpgsm=no
  build_scdaemon=no
fi


AM_CONDITIONAL(BUILD_GPG,   test "$build_gpg" = "yes")
AM_CONDITIONAL(BUILD_GPGSM, test "$build_gpgsm" = "yes")
AM_CONDITIONAL(BUILD_AGENT, test "$build_agent" = "yes")
AM_CONDITIONAL(BUILD_SCDAEMON, test "$build_scdaemon" = "yes")
AM_CONDITIONAL(BUILD_SYMCRYPTRUN, test "$build_symcryptrun" = "yes")



#
# Print errors here so that they are visible all
# together and the user can acquire them all together.
#
die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgpg-error to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libgcrypt" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgcrypt to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION using API $NEED_LIBGCRYPT_API) is required.)
***]])
fi
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/alpha/libassuan/
*** (at least version $NEED_LIBASSUAN_VERSION is required).
***]])
fi
if test "$have_ksba" = "no"; then
    AC_MSG_NOTICE([[
***
*** You need libksba to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/alpha/libksba/
*** (at least version $NEED_KSBA_VERSION is required).
***]])
fi
if test "$missing_pth" = "yes"; then
    AC_MSG_NOTICE([[
***
*** It is now required to build with support for the
*** GNU Portable Threads Library (Pth). Please install this
*** library first.  The library is for example available at
***   ftp://ftp.gnu.org/gnu/pth/
*** On a Debian GNU/Linux system you can install it using 
***   apt-get install libpth-dev
***]])
   die=yes
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi



AC_CONFIG_FILES([ m4/Makefile 
Makefile
po/Makefile.in
intl/Makefile
gl/Makefile
jnlib/Makefile
common/Makefile
kbx/Makefile
g10/Makefile
sm/Makefile
agent/Makefile
scd/Makefile
tools/Makefile
doc/Makefile
tests/Makefile
])
AC_OUTPUT

#tests/pkits/Makefile




echo "
        GnuPG v${VERSION} has been configured as follows:
        
        Platform:  $PRINTABLE_OS_NAME ($host)

        OpenPGP:   $build_gpg
        S/MIME:    $build_gpgsm
        Agent:     $build_agent $build_agent_threaded
        Smartcard: $build_scdaemon $build_scdaemon_extra

        Protect tool:      $show_gnupg_protect_tool_pgm
        Default agent:     $show_gnupg_agent_pgm
        Default pinentry:  $show_gnupg_pinentry_pgm
        Default scdaemon:  $show_gnupg_scdaemon_pgm
        Default dirmngr:   $show_gnupg_dirmngr_pgm

        PKITS based tests: $run_pkits_tests
"

