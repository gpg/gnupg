dnl Configure.ac script for GnuPG
dnl Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
dnl
dnl This file is part of GnuPG.
dnl
dnl GnuPG is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl 
dnl GnuPG is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
dnl
dnl (Process this file with autoconf to produce a configure script.)
dnlAC_REVISION($Revision$)dnl

AC_PREREQ(2.52)

# Please enter the version number here and set development_version to
# yes if the minor number is odd or you feel that the default check 
# for a development version is not sufficient.
AC_INIT(gnupg, 1.1.91, bug-gnupg@gnu.org)
development_version=yes

ALL_LINGUAS="cs da de eo el es et fr gl id it ja nl pl pt_BR pt sv tr"
static_modules="sha1 md5 rmd160"
static_random_module=""

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR(scripts)
AC_CONFIG_SRCDIR(g10/g10.c)
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER(config.h)

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE(_GNU_SOURCE,1,[Some tests rely on this (stpcpy) and it should be used for new programs anyway])

AC_PROG_AWK

MODULES_IN_CIPHER=`$AWK '/^EXTRA_PROGRAMS/ { for(i=3;i<=NF;i++) print $i}' \
                                              $srcdir/cipher/Makefile.am`

dnl
dnl  Check for random module options
dnl
dnl  Fixme: get the list of available modules from MODULES_IN_CIPHER
dnl         and check against this list

AC_MSG_CHECKING([which static random module to use])
AC_ARG_ENABLE(static-rnd,
    [  --enable-static-rnd=[egd|unix|linux|none]  ],
[use_static_rnd=$enableval], [use_static_rnd=default] )

if test "$use_static_rnd" = no; then
    use_static_rnd=default
fi

case "$use_static_rnd" in
    egd | linux | unix | none | default )
      AC_MSG_RESULT($use_static_rnd)
      ;;
    * )
      AC_MSG_RESULT(invalid argument)
      AC_MSG_ERROR(there is no random module rnd$use_static_rnd)
      ;;
esac

AC_ARG_WITH(egd-socket,
    [  --with-egd-socket=NAME  use NAME for the EGD socket],
            egd_socket_name="$withval", egd_socket_name="" )
AC_DEFINE_UNQUOTED(EGD_SOCKET_NAME, "$egd_socket_name",
                   [Define if you don't want the default EGD socket name.
                    For details see cipher/rndegd.c])


dnl
dnl See whether the user wants to disable checking for /dev/random

AC_MSG_CHECKING([whether use of /dev/random is requested])
AC_ARG_ENABLE(dev-random,
[  --disable-dev-random    disable the use of dev random],
    try_dev_random=$enableval, try_dev_random=yes)
AC_MSG_RESULT($try_dev_random)


dnl
dnl  Check other options
dnl

AC_MSG_CHECKING([whether use of extensions is requested])
AC_ARG_ENABLE(dynload,
[  --disable-dynload       disable use of extensions],
    try_dynload=$enableval, try_dynload=yes)
AC_MSG_RESULT($try_dynload)

AC_MSG_CHECKING([whether assembler modules are requested])
AC_ARG_ENABLE(asm,
[  --disable-asm           do not use assembler modules],
     try_asm_modules=$enableval, try_asm_modules=yes)
AC_MSG_RESULT($try_asm_modules)

AC_MSG_CHECKING([whether memory guard is requested])
AC_ARG_ENABLE(m-guard,
    [  --enable-m-guard        enable memory guard facility],
    use_m_guard=$enableval, use_m_guard=no)
AC_MSG_RESULT($use_m_guard)
if test "$use_m_guard" = yes ; then
    AC_DEFINE(M_GUARD,1,[Define to use the (obsolete) malloc guarding feature])
fi

AC_MSG_CHECKING([whether to enable external program execution])
AC_ARG_ENABLE(exec,
    [  --disable-exec          disable all external program execution],
    use_exec=$enableval, use_exec=yes)
AC_MSG_RESULT($use_exec)
if test "$use_exec" = no ; then
    AC_DEFINE(NO_EXEC,1,[Define to disable all external program execution])
fi

if test "$use_exec" = yes ; then
  AC_MSG_CHECKING([whether to use a restricted exec-path])
  AC_ARG_WITH(exec-path,
      [  --with-exec-path=PATH   restrict exec-path to PATH],
      [if test "$withval" = yes ; then
         withval=no
      elif test "$withval" != no ; then
         AC_DEFINE_UNQUOTED(FIXED_EXEC_PATH,"$withval",
	                    [if set, restrict exec-path to this value])
      fi],withval=no)
  AC_MSG_RESULT($withval)

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

    AC_MSG_CHECKING([whether experimental external hkp keyserver support is requested])
    AC_ARG_ENABLE(external-hkp,
    [  --enable-external-hkp   enable experimental external HKP keyserver interface],
        try_hkp=$enableval, try_hkp=no)
    AC_MSG_RESULT($try_hkp)

    if test "$try_hkp" = yes ; then
      GPGKEYS_HKP="gpgkeys_hkp"
      AC_DEFINE(USE_EXTERNAL_HKP,1,[define to use the experimental external HKP keyserver interface])
    fi

    AC_MSG_CHECKING([whether email keyserver support is requested])
    AC_ARG_ENABLE(mailto,
    [  --disable-mailto        disable email keyserver interface],
        try_mailto=$enableval, try_mailto=yes)
    AC_MSG_RESULT($try_mailto)
    fi
  fi

AC_MSG_CHECKING([whether included zlib is requested])
AC_ARG_WITH(included-zlib,
    [  --with-included-zlib    use the zlib code included here],
[g10_force_zlib=yes], [g10_force_zlib=no] )
AC_MSG_RESULT($g10_force_zlib)


dnl
dnl Check whether we want to use Linux capabilities
dnl
AC_MSG_CHECKING([whether use of capabilities is requested])
AC_ARG_WITH(capabilities,
    [  --with-capabilities     use linux capabilities [default=no]],
[use_capabilities="$withval"],[use_capabilities=no])
AC_MSG_RESULT($use_capabilities)


AH_BOTTOM([
#if !(defined(HAVE_FORK) && defined(HAVE_PIPE) && defined(HAVE_WAITPID))
#define EXEC_TEMPFILE_ONLY
#endif

#include "g10defs.h"
])


AM_MAINTAINER_MODE

dnl Checks for programs.

dnl
dnl Setup some stuff depending on host/target.
dnl
case "${target}" in
    *-*-mingw32*)
        disallowed_modules="rndunix rndlinux rndegd"
        ;;
    *-*-cygwin*)
        disallowed_modules="rndunix rndlinux rndegd tiger"
        ;;
    *)
        disallowed_modules="rndw32"
       ;;
esac

AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_CC
AC_PROG_CPP
AC_PATH_PROG(PERL,"perl")
AC_ISC_POSIX
AC_SYS_LARGEFILE
AC_PROG_INSTALL
AC_PROG_AWK
AC_CHECK_PROG(DOCBOOK_TO_MAN, docbook-to-man, yes, no)
AM_CONDITIONAL(HAVE_DOCBOOK_TO_MAN, test "$ac_cv_prog_DOCBOOK_TO_MAN" = yes)
GNUPG_CHECK_FAQPROG
GNUPG_CHECK_DOCBOOK_TO_TEXI

MPI_OPT_FLAGS=""


try_gettext=yes
case "${target}" in
    *-*-mingw32*|*-*-cygwin*)
        # special stuff for Windoze NT
        ac_cv_have_dev_random=no
        AC_DEFINE(USE_ONLY_8DOT3,1,
                  [set this to limit filenames to the 8.3 format])
        AC_DEFINE(HAVE_DRIVE_LETTERS,1,
                  [defined if we must run on a stupid file system])
        AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
                  [defined if we run on some of the PCDOS like systems 
                   (DOS, Windoze. OS/2) with special properties like
                    no file modes])
        AC_DEFINE(USE_SIMPLE_GETTEXT,1,
                  [because the Unix gettext has too much overhead on
                   MingW32 systems and these systems lack Posix functions,
                   we use a simplified version of gettext])
        try_gettext="no"
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        # OS/2 with the EMX environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
        try_gettext="no"
        ;;

    i?86-*-msdosdjgpp*)
        # DOS with the DJGPP environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
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

AC_SUBST(MPI_OPT_FLAGS)
GNUPG_SYS_SYMBOL_UNDERSCORE
GNUPG_CHECK_PIC
GNUPG_CHECK_EXPORTDYNAMIC
if test "$NO_PIC" = yes; then
    try_dynload=no
fi

dnl Must check for network library requirements before doing link tests
dnl for ldap, for example. If ldap libs are static (or dynamic and without
dnl ELF runtime link paths), then link will fail and LDAP support won't
dnl be detected.

AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))

# Try and link a LDAP test program to weed out unusable LDAP
# libraries.  -lldap -llber -lresolv is for OpenLDAP.  -lldapssl41 is
# for Mozilla LDAP.

if test "$try_ldap" = yes ; then
  for LDAPLIBS in "-lldap -llber -lresolv" "-lldapssl41"; do
    _ldap_save_libs=$LIBS
    LIBS="$LDAPLIBS $NETLIBS $LIBS"

    AC_MSG_CHECKING([whether LDAP via \"$LDAPLIBS\" is present and sane])
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
       GPGKEYS_LDAP="gpgkeys_ldap"
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
AC_SUBST(GPGKEYS_HKP)

case "${target}" in
    *-*-mingw32*)
        PRINTABLE_OS_NAME="MingW32"
        ;;
    *-*-cygwin*)
        PRINTABLE_OS_NAME="Cygwin32"
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


#
# 1. Set flags to be used for the extension modules
# 2. Set names of random devices
#
NAME_OF_DEV_RANDOM="/dev/random"
NAME_OF_DEV_URANDOM="/dev/urandom"
case "${target}" in
    *-openbsd* | *-netbsd*)
        NAME_OF_DEV_RANDOM="/dev/srandom"
        NAME_OF_DEV_URANDOM="/dev/urandom"
        DYNLINK_MOD_CFLAGS="-shared -rdynamic $CFLAGS_PIC -Wl,-Bshareable -Wl,-x"
        ;;

     hpux*)
	# if using the vendor (ANSI) compiler, arrange to have `-b' passed
	# to the linker.  If using gcc, it supports `-shared' to do the same.
        if test -n "$GCC" ; then
           DYNLINK_MOD_CFLAGS="-shared $CFLAGS_PIC"
        else
           DYNLINK_MOD_CFLAGS='-Wl,-b'
        fi
        ;;

    *-irix6.5*)
        # Irix 6.5 (and probably a lot earlier, but I only still have
	# access to 6.5.x) doesn't require any additional flags, as `-KPIC'
	# is the default.  Also, `-shared' works with the vendor compiler
	DYNLINK_MOD_CFLAGS="-shared"
        ;;

    alpha*-dec-osf*)
	# osf (i.e. OSF/1, Digital UNIX, or Tru64 UNIX, pick any one...)
	# on alpha doesn't require any PIC flags, everything is PIC.
	# This may not be the case for osf ports to other machines, so
	# hence the more specific match for target.
	#
	# Also, `-shared' works with the vendor compiler or gcc.
	# -expect_unresolved turns off warnings about unresolved symbols.
	DYNLINK_MOD_CFLAGS='-shared -Wl,-expect_unresolved,\*'
         ;;

    *-solaris*)
	# -shared is a gcc-ism.  Find pic flags from GNUPG_CHECK_PIC.
	if test -n "$GCC" ; then
	   DYNLINK_MOD_CFLAGS="-shared $CFLAGS_PIC"
	else
	   DYNLINK_MOD_CFLAGS="-G $CFLAGS_PIC"
	fi
	;;

    *-irix* | *-dec-osf* )
	DYNLINK_MOD_CFLAGS="-shared $CFLAGS_PIC"
	;;

    *)
        # -shared is a gcc-ism.  Find pic flags from GNUPG_CHECK_PIC.
        if test -n "$GCC" ; then
           DYNLINK_MOD_CFLAGS="-shared $CFLAGS_PIC"                            
        else
           DYNLINK_MOD_CFLAGS="$CFLAGS_PIC"
        fi
        ;;
esac
AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, "$NAME_OF_DEV_RANDOM",
                   [defined to the name of the strong random device])
AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, "$NAME_OF_DEV_URANDOM",
                   [defined to the name of the weaker random device])
AC_SUBST(MPI_OPT_FLAGS)


dnl Checks for libraries.

if test "$try_gettext" = yes; then
AM_GNU_GETTEXT
else
USE_NLS=no
USE_INCLUDED_LIBINTL=no
BUILD_INCLUDED_LIBINTL=no
AC_SUBST(USE_NLS)
AC_SUBST(USE_INCLUDED_LIBINTL)
AC_SUBST(BUILD_INCLUDED_LIBINTL)
fi


if test "$try_dynload" = yes ; then
  AC_CHECK_LIB(dl,dlopen)
  if test "$ac_cv_lib_dl_dlopen" = "yes"; then
    AC_DEFINE(USE_DYNAMIC_LINKING,1,
              [define to enable the use of extensions])
    AC_DEFINE(HAVE_DL_DLOPEN,1,
              [Defined when the dlopen function family is available])
    DYNLINK_LDFLAGS="$CFLAGS_EXPORTDYNAMIC"
    use_gnupg_extensions=yes
  else
    AC_CHECK_FUNCS(dlopen)
    if test "$ac_cv_func_dlopen" = "yes"; then
      AC_DEFINE(USE_DYNAMIC_LINKING)
      AC_DEFINE(HAVE_DL_DLOPEN)
      DYNLINK_LDFLAGS="$CFLAGS_EXPORTDYNAMIC"
      use_gnupg_extensions=yes
    else
      AC_CHECK_LIB(dld,shl_load)
      if test "$ac_cv_lib_dld_shl_load" = "yes"; then
        AC_DEFINE(USE_DYNAMIC_LINKING)
        AC_DEFINE(HAVE_DL_SHL_LOAD,1,
                  [Defined if the shl_load function family is available])
        DYNLINK_LDFLAGS="$CFLAGS_EXPORTDYNAMIC"
        use_gnupg_extensions=yes
dnl -----------------
dnl  DLD is not ready for use. So I better disable this test
dnl
dnl    AC_CHECK_LIB(dld,dld_link)
dnl    if test "$ac_cv_lib_dld_dld_link" = "yes"; then
dnl      AC_DEFINE(USE_DYNAMIC_LINKING)
dnl      AC_DEFINE(HAVE_DLD_DLD_LINK)
dnl      DYNLINK_LDFLAGS="$CFLAGS_EXPORTDYNAMIC"
dnl      use_gnupg_extensions=yes
dnl ---------------
      fi
    fi
  fi
else
  AC_MSG_CHECKING(for dynamic loading)
  DYNLINK_LDFLAGS=
  DYNLINK_MOD_CFLAGS=
  use_gnupg_extensions=no
  AC_MSG_RESULT(has been disabled)
fi

AM_CONDITIONAL(ENABLE_GNUPG_EXTENSIONS, test "$use_gnupg_extensions" = yes )
AC_SUBST(DYNLINK_LDFLAGS)
AC_SUBST(DYNLINK_MOD_CFLAGS)


dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h langinfo.h termio.h locale.h)

dnl Checks for typedefs, structures, and compiler characteristics.
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

AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)
AC_CHECK_SIZEOF(unsigned long long, 0)

if test "$ac_cv_sizeof_unsigned_short" = "0" \
   || test "$ac_cv_sizeof_unsigned_int" = "0" \
   || test "$ac_cv_sizeof_unsigned_long" = "0"; then
    AC_MSG_WARN([Hmmm, something is wrong with the sizes - using defaults]);
fi

dnl Checks for library functions.
AC_FUNC_FSEEKO
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_CHECK_FUNCS(strerror stpcpy strsep strlwr tcgetattr strtoul mmap)
AC_CHECK_FUNCS(strcasecmp strncasecmp)
AC_CHECK_FUNCS(memmove gettimeofday getrusage setrlimit clock_gettime)
AC_CHECK_FUNCS(atexit raise getpagesize strftime nl_langinfo setlocale)
AC_CHECK_FUNCS(waitpid wait4 sigaction sigprocmask rand pipe stat)
AC_REPLACE_FUNCS(mkdtemp)

#
# check for gethrtime and run a testprogram to see whether
# it is broken.  It has been reported that some Solaris and HP UX systems 
# raise an SIGILL
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
if test "$use_capabilities" = "yes" ; then
use_capabilities=no
AC_CHECK_HEADERS(sys/capability.h)
if test "$ac_cv_header_sys_capability_h" = "yes" ; then
  AC_CHECK_LIB(cap, cap_init, ac_need_libcap=1)
  if test "$ac_cv_lib_cap_cap_init" = "yes"; then
     AC_DEFINE(USE_CAPABILITIES,1,
               [define if capabilities should be used])
     LIBS="$LIBS -lcap"
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


GNUPG_CHECK_IPC
if test "$ac_cv_header_sys_shm_h" = "yes"; then
  AC_DEFINE(USE_SHM_COPROCESSING,1,
            [define if the shared memory interface should be made available])
fi

dnl
dnl check whether we have a random device
dnl
if test "$try_dev_random" = yes ; then
    AC_CACHE_CHECK(for random device, ac_cv_have_dev_random,
    [if test -r "$NAME_OF_DEV_RANDOM" && test -r "$NAME_OF_DEV_URANDOM" ; then
      ac_cv_have_dev_random=yes; else ac_cv_have_dev_random=no; fi])
    if test "$ac_cv_have_dev_random" = yes; then
        AC_DEFINE(HAVE_DEV_RANDOM,1,
                 [defined if the system supports a random device] )
    fi
else
    AC_MSG_CHECKING(for random device)
    ac_cv_have_dev_random=no
    AC_MSG_RESULT(has been disabled)
fi


dnl
dnl Figure out the default linkage mode for random modules
dnl
print_egd_notice=no
if test "$use_static_rnd" = default; then
  if test "$ac_cv_have_dev_random" = yes; then
      static_random_module="rndlinux"
  else
      case "${target}" in
          *-*-mingw32*|*-*-cygwin*)
              static_random_module="rndw32"
              AC_DEFINE(USE_STATIC_RNDW32,1,
                       [At some point in the code we need to know that
                        we use the Windows random module.])
              ;;
          i?86-emx-os2|i?86-*-os2*emx)
              static_random_module="rndos2"
              ;;
          m68k-atari-mint)
              static_random_module="rndatari"
              ;;
          i?86-*-msdosdjgpp*)
              :
              ;;
          *)
              static_random_module="rndunix"
              print_egd_notice=yes
             ;;
      esac
  fi
else
  if test "$use_static_rnd" = none; then
    :
  else
    static_random_module="rnd$use_static_rnd"
    if test "$use_static_rnd" = "unix"; then
        print_egd_notice=yes
    fi
  fi
fi


if test "$print_egd_notice" = "yes"; then
    AC_MSG_WARN([[
***
*** The performance of the UNIX random gatherer module is not very good
*** and it does not keep the entropy pool over multiple invocations of
*** GnuPG.  The suggested way to overcome this problem is to use the
***
***               Entropy Gathering Daemon (EGD)
***
*** which provides a entropy source for the whole system.  It is written
*** in Perl and available at the GnuPG FTP servers.  For more information
*** consult the GnuPG webpages:
***
***           http://www.gnupg.org/download.html#egd
***
*** You may want to run ./configure with --enable-static-rnd=none to be
*** able to load the EGD client code dynamically; this way you can choose
*** between RNDUNIX and RNDEGD without recompilation.
***]])
fi

dnl
dnl Parse the modules list and build the list
dnl of static and dynamically linked modules
dnl
dnl (We always need a static rmd160)
static_modules="$static_modules rmd160 $static_random_module"
STATIC_CIPHER_NAMES=""
STATIC_CIPHER_OBJS=""
DYNAMIC_CIPHER_MODS=""
show_dynlink=""
for name in $MODULES_IN_CIPHER; do
    x="yes"
    for i in $disallowed_modules; do
        if test "$name" = "$i" ; then x="no" ; fi
    done;
    if test $x = yes; then
        x="no"
        for i in $static_modules; do
            if test "$name" = "$i" ; then
                x="yes"
            fi
        done;
        if test $x = yes; then
            STATIC_CIPHER_NAMES="$STATIC_CIPHER_NAMES $name"
            STATIC_CIPHER_OBJS="$STATIC_CIPHER_OBJS $name.o"
        else
            DYNAMIC_CIPHER_MODS="$DYNAMIC_CIPHER_MODS $name"
            show_dynlink="$show_dynlink $name"
        fi
    fi
done
AC_SUBST(STATIC_CIPHER_OBJS)
AC_SUBST(STATIC_CIPHER_NAMES)
AC_SUBST(DYNAMIC_CIPHER_MODS)

dnl
dnl And build the constructor file
dnl

test -d cipher || mkdir cipher
cat <<G10EOF >cipher/construct.c
/* automatically generated by configure - do not edit */

G10EOF
show_statlink=""
for name in $STATIC_CIPHER_NAMES; do
    echo "void ${name}_constructor(void);" >>cipher/construct.c
    show_statlink="$show_statlink $name"
done

cat <<G10EOF >>cipher/construct.c

void
cipher_modules_constructor(void)
{
    static int done = 0;
    if( done )
        return;
    done = 1;

G10EOF
for name in $STATIC_CIPHER_NAMES; do
    echo "   ${name}_constructor();" >>cipher/construct.c
done
echo '}' >>cipher/construct.c




dnl
dnl Figure how to link the cipher modules
dnl
AC_SUBST(STATIC_CIPHER_OBJS)
AC_SUBST(DYNAMIC_CIPHER_MODS)


dnl setup assembler stuff
AC_MSG_CHECKING(for mpi assembler functions)
if test -f $srcdir/mpi/config.links ; then
    . $srcdir/mpi/config.links
    AC_CONFIG_LINKS("$mpi_ln_list")
    ac_cv_mpi_extra_asm_modules="$mpi_extra_modules"
    ac_cv_mpi_sflags="$mpi_sflags"
    ac_cv_mpi_config_done="yes"
    AC_MSG_RESULT(done)
else
    AC_MSG_RESULT(failed)
    AC_MSG_ERROR([mpi/config.links missing!])
fi
MPI_EXTRA_ASM_OBJS=""
show_extraasm=""
if test "$ac_cv_mpi_extra_asm_modules" != ""; then
for i in $ac_cv_mpi_extra_asm_modules; do
    show_extraasm="$show_extraasm $i"
    MPI_EXTRA_ASM_OBJS="$MPI_EXTRA_ASM_OBJS $i.o"
done
fi
AC_SUBST(MPI_EXTRA_ASM_OBJS)
MPI_SFLAGS="$ac_cv_mpi_sflags"
AC_SUBST(MPI_SFLAGS)

dnl Do we have zlib? Must do it here because Solaris failed
dnl when compiling a conftest (due to the "-lz" from LIBS).
use_local_zlib=yes
if test "$g10_force_zlib" = "yes"; then
  :
else
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
       use_local_zlib=no
       LIBS="$LIBS -lz",
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})
fi
 
if test "$use_local_zlib" = yes ; then
    AM_CONDITIONAL(ENABLE_LOCAL_ZLIB, true)
    AC_CONFIG_LINKS(zlib.h:zlib/zlib.h zconf.h:zlib/zconf.h )
    ZLIBS="../zlib/libzlib.a"
else
    AM_CONDITIONAL(ENABLE_LOCAL_ZLIB, false)
    ZLIBS=
fi
AC_SUBST(ZLIBS)


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

# add some extra libs here so that previous tests don't fail for
# mysterious reasons - the final link step should bail out. 
case "${target}" in
    *-*-mingw32*)
        LIBS="$LIBS -lwsock32"
        ;;
    *)
       ;;
esac


if test "$GCC" = yes; then
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

AC_SUBST(NETLIBS)

# Note the \\\\ for backslashes.  Autoconf eats one layer, leaving \\

AC_CONFIG_COMMANDS(g10defs.h,[[
cat >g10defs.tmp <<G10EOF
/* Generated automatically by configure */
#ifdef HAVE_DRIVE_LETTERS
  #define G10_LOCALEDIR     "c:\\\\lib\\\\gnupg\\\\locale"
  #define GNUPG_LIBDIR      "c:\\\\lib\\\\gnupg"
  #define GNUPG_LIBEXECDIR  "c:\\\\lib\\\\gnupg"
  #define GNUPG_DATADIR     "c:\\\\lib\\\\gnupg"
  #define GNUPG_HOMEDIR     "c:\\\\gnupg"
#else
  #define G10_LOCALEDIR     "${datadir}/locale"
  #define GNUPG_LIBDIR      "${libdir}/gnupg"
  #define GNUPG_LIBEXECDIR  "${libexecdir}/gnupg"
  #define GNUPG_DATADIR     "${datadir}/gnupg"
  #ifdef __VMS
    #define GNUPG_HOMEDIR "/SYS\$LOGIN/gnupg" 
  #else
    #define GNUPG_HOMEDIR "~/.gnupg" 
  #endif
#endif
/* those are here to be redefined by handcrafted g10defs.h.
   Please note that the string version must not contain more
   than one character because the using code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\\\'
#define EXTSEP_C '.'
#define DIRSEP_S "\\\\"
#define EXTSEP_S "."
#else
#define DIRSEP_C '/'
#define EXTSEP_C '.'
#define DIRSEP_S "/"
#define EXTSEP_S "."
#endif
G10EOF
cat mpi/mpi-asm-defs.h >>g10defs.tmp 
if cmp -s g10defs.h g10defs.tmp 2>/dev/null; then
    echo "g10defs.h is unchanged"
    rm -f g10defs.tmp
else
    rm -f g10defs.h
    mv g10defs.tmp g10defs.h
    echo "g10defs.h created"
fi
]],[[
prefix=$prefix
exec_prefix=$exec_prefix
libdir=$libdir
libexecdir=$libexecdir
datadir=$datadir
DATADIRNAME=$DATADIRNAME
]])


AC_CONFIG_FILES([
Makefile
intl/Makefile
po/Makefile.in
util/Makefile
mpi/Makefile
cipher/Makefile
g10/Makefile
keyserver/Makefile
keyserver/gpgkeys_mailto
keyserver/gpgkeys_test
doc/Makefile
tools/Makefile
zlib/Makefile
checks/Makefile
])
AC_OUTPUT

# Give some feedback
echo
echo   "                Configured for: $PRINTABLE_OS_NAME ($target)"
if test -n "$show_dynlink"; then
  echo "    Dynamically linked modules:$show_dynlink"
fi
if test -n "$show_statlink"; then
  echo "     Statically linked modules:$show_statlink"
fi
if test -n "$show_extraasm"; then
  echo "  Extra cpu specific functions:$show_extraasm"
fi
echo

