# configure.ac - for GnuPG 2.0
# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
#               2006, 2007, 2008, 2010, 2011,
#               2012 Free Software Foundation, Inc.
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
min_automake_version="1.10"

# Remember to change the version number immediately *after* a release.
# Set my_issvn to "yes" for non-released code.  Remember to run an
# "svn up" and "autogen.sh" right before creating a distribution.
m4_define([my_version], [2.0.19])
m4_define([my_issvn], [no])

m4_define([svn_revision], m4_esyscmd([printf "%d" $(svn info 2>/dev/null \
          | sed -n '/^Revision:/ s/[^0-9]//gp'|head -1)]))
m4_define([git_revision], m4_esyscmd([git branch -v 2>/dev/null \
          | awk '/^\* / {printf "%s",$3}']))
m4_define([my_full_version], [my_version[]m4_if(my_issvn,[yes],
          [m4_if(git_revision,[],[-svn[]svn_revision],[-git[]git_revision])])])

AC_INIT([gnupg],[my_full_version],[http://bugs.gnupg.org])
# Set development_version to yes if the minor number is odd or you
# feel that the default check for a development version is not
# sufficient.
development_version=no

NEED_GPG_ERROR_VERSION=1.7

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.4.0

NEED_LIBASSUAN_API=2
NEED_LIBASSUAN_VERSION=2.0.0

NEED_KSBA_API=1
NEED_KSBA_VERSION=1.0.7


PACKAGE=$PACKAGE_NAME
PACKAGE_GT=${PACKAGE_NAME}2
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR(scripts)
AC_CONFIG_SRCDIR(sm/gpgsm.c)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AC_CANONICAL_HOST
AB_INIT

AC_GNU_SOURCE

# Some status variables.
have_gpg_error=no
have_libgcrypt=no
have_libassuan=no
have_ksba=no
have_pth=no
have_libusb=no
have_adns=no

use_bzip2=yes
use_exec=yes
disable_keyserver_path=no
use_ccid_driver=yes
use_standard_socket=no

GNUPG_BUILD_PROGRAM(gpg, yes)
GNUPG_BUILD_PROGRAM(gpgsm, yes)
GNUPG_BUILD_PROGRAM(agent, yes)
GNUPG_BUILD_PROGRAM(scdaemon, yes)
GNUPG_BUILD_PROGRAM(tools, yes)
GNUPG_BUILD_PROGRAM(doc, yes)
GNUPG_BUILD_PROGRAM(symcryptrun, no)
GNUPG_BUILD_PROGRAM(gpgtar, no)


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


# Some folks want to use only the agent from this packet.  Make it
# easier for them by providing the configure option
# --enable-only-agent.
AC_ARG_ENABLE(agent-only,
    AC_HELP_STRING([--enable-agent-only],[build only the gpg-agent]),
    build_agent_only=$enableval)

# SELinux support includes tracking of sensitive files to avoid
# leaking their contents through processing these files by gpg itself
AC_MSG_CHECKING([whether SELinux support is requested])
AC_ARG_ENABLE(selinux-support,
              AC_HELP_STRING([--enable-selinux-support],
                             [enable SELinux support]),
              selinux_support=$enableval, selinux_support=no)
AC_MSG_RESULT($selinux_support)

# Allow disabling of bzib2 support.
# It is defined only after we confirm the library is available later
AC_MSG_CHECKING([whether to enable the BZIP2 compression algorithm])
AC_ARG_ENABLE(bzip2,
   AC_HELP_STRING([--disable-bzip2],[disable the BZIP2 compression algorithm]),
   use_bzip2=$enableval)
AC_MSG_RESULT($use_bzip2)

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
    # LDAP is defined only after we confirm the library is available later
    AC_MSG_CHECKING([whether LDAP keyserver support is requested])
    AC_ARG_ENABLE(ldap,
      AC_HELP_STRING([--disable-ldap],[disable LDAP keyserver interface only]),
      try_ldap=$enableval, try_ldap=yes)
    AC_MSG_RESULT($try_ldap)

    AC_MSG_CHECKING([whether HKP keyserver support is requested])
    AC_ARG_ENABLE(hkp,
      AC_HELP_STRING([--disable-hkp],[disable HKP keyserver interface only]),
      try_hkp=$enableval, try_hkp=yes)
    AC_MSG_RESULT($try_hkp)

    AC_MSG_CHECKING([whether finger key fetching support is requested])
    AC_ARG_ENABLE(finger,
      AC_HELP_STRING([--disable-finger],
        [disable finger key fetching interface only]),
      try_finger=$enableval, try_finger=yes)
    AC_MSG_RESULT($try_finger)

    AC_MSG_CHECKING([whether generic object key fetching support is requested])
    AC_ARG_ENABLE(generic,
      AC_HELP_STRING([--disable-generic],
        [disable generic object key fetching interface only]),
      try_generic=$enableval, try_generic=yes)
    AC_MSG_RESULT($try_generic)

    AC_MSG_CHECKING([whether email keyserver support is requested])
    AC_ARG_ENABLE(mailto,
      AC_HELP_STRING([--enable-mailto],
	[enable email keyserver interface only]),
      try_mailto=$enableval, try_mailto=no)
    AC_MSG_RESULT($try_mailto)
  fi

  AC_MSG_CHECKING([whether keyserver exec-path is enabled])
  AC_ARG_ENABLE(keyserver-path,
      AC_HELP_STRING([--disable-keyserver-path],
           [disable the exec-path option for keyserver helpers]),
           [if test "$enableval" = no ; then
              disable_keyserver_path=yes
           fi],enableval=yes)
  AC_MSG_RESULT($enableval)
fi


#
# Check for the key/uid cache size.  This can't be zero, but can be
# pretty small on embedded systems.  This is used for the gpg part.
#
AC_MSG_CHECKING([for the size of the key and uid cache])
AC_ARG_ENABLE(key-cache,
        AC_HELP_STRING([--enable-key-cache=SIZE],
                       [Set key cache to SIZE (default 4096)]),,enableval=4096)
if test "$enableval" = "no"; then
   enableval=5
elif test "$enableval" = "yes" || test "$enableval" = ""; then
   enableval=4096
fi
changequote(,)dnl
key_cache_size=`echo "$enableval" | sed 's/[A-Za-z]//g'`
changequote([,])dnl
if test "$enableval" != "$key_cache_size" || test "$key_cache_size" -lt 5; then
   AC_MSG_ERROR([invalid key-cache size])
fi
AC_MSG_RESULT($key_cache_size)
AC_DEFINE_UNQUOTED(PK_UID_CACHE_SIZE,$key_cache_size,
                  [Size of the key and UID caches])



#
# Check whether we want to use Linux capabilities
#
AC_MSG_CHECKING([whether use of capabilities is requested])
AC_ARG_WITH(capabilities,
    [  --with-capabilities     use linux capabilities [default=no]],
[use_capabilities="$withval"],[use_capabilities=no])
AC_MSG_RESULT($use_capabilities)


#
# Allow disabling of internal CCID support.
# It is defined only after we confirm the library is available later
#
AC_MSG_CHECKING([whether to enable the internal CCID driver])
AC_ARG_ENABLE(ccid-driver,
              AC_HELP_STRING([--disable-ccid-driver],
                             [disable the internal CCID driver]),
              use_ccid_driver=$enableval)
AC_MSG_RESULT($use_ccid_driver)


#
# To avoid double inclusion of config.h which might happen at some
# places, we add the usual double inclusion protection at the top of
# config.h.
#
AH_TOP([
#ifndef GNUPG_CONFIG_H_INCLUDED
#define GNUPG_CONFIG_H_INCLUDED
])

#
# Stuff which goes at the bottom of config.h.
#
AH_BOTTOM([
/* This is the major version number of GnuPG so that
   source included files can test for this.  Note, that
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

/* Some global constants. */
#ifdef HAVE_DRIVE_LETTERS
#define GNUPG_DEFAULT_HOMEDIR "c:/gnupg"
#elif defined(__VMS)
#define GNUPG_DEFAULT_HOMEDIR "/SYS\$LOGIN/gnupg"
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.gnupg"
#endif
#define GNUPG_PRIVATE_KEYS_DIR "private-keys-v1.d"

/* For some systems (DOS currently), we hardcode the path here.  For
   POSIX systems the values are constructed by the Makefiles, so that
   the values may be overridden by the make invocations; this is to
   comply with the GNU coding standards. */
#ifdef HAVE_DRIVE_LETTERS
 /* FIXME: We need to use a function to determine these values depending
    on the actual installation directory. */
#define GNUPG_BINDIR      "c:\\gnupg"
#define GNUPG_LIBEXECDIR  "c:\\gnupg"
#define GNUPG_LIBDIR      "c:\\gnupg"
#define GNUPG_DATADIR     "c:\\gnupg"
#define GNUPG_SYSCONFDIR  "c:\\gnupg"
#endif

/* Derive some other constants. */
#if !(defined(HAVE_FORK) && defined(HAVE_PIPE) && defined(HAVE_WAITPID))
#define EXEC_TEMPFILE_ONLY
#endif


/* We didn't define endianness above, so get it from OS macros.  This
   is intended for making fat binary builds on OS X. */
#if !defined(BIG_ENDIAN_HOST) && !defined(LITTLE_ENDIAN_HOST)
#if defined(__BIG_ENDIAN__)
#define BIG_ENDIAN_HOST 1
#elif defined(__LITTLE_ENDIAN__)
#define LITTLE_ENDIAN_HOST 1
#else
#error "No endianness found"
#endif
#endif


/* Hack used for W32: ldap.m4 also tests for the ASCII version of
   ldap_start_tls_s because that is the actual symbol used in the
   library.  winldap.h redefines it to our commonly used value,
   thus we define our usual macro here.  */
#ifdef HAVE_LDAP_START_TLS_SA
# ifndef HAVE_LDAP_START_TLS_S
#  define HAVE_LDAP_START_TLS_S 1
# endif
#endif


/* Tell libgcrypt not to use its own libgpg-error implementation. */
#define USE_LIBGPG_ERROR 1

/* We use jnlib, so tell other modules about it.  */
#define HAVE_JNLIB_LOGGING 1

/* Our HTTP code is used in estream mode.  */
#define HTTP_USE_ESTREAM 1

/* Under W32 we do an explicit socket initialization, thus we need to
   avoid the on-demand initialization which would also install an atexit
   handler.  */
#define HTTP_NO_WSASTARTUP

/* We always include support for the OpenPGP card.  */
#define ENABLE_CARD_SUPPORT 1

/* We don't want the old assuan codes anymore. */
#define _ASSUAN_ONLY_GPG_ERRORS 1

/* We explicitly need to disable PTH's soft mapping as Debian
   currently enables it by default for no reason. */
#define PTH_SYSCALL_SOFT 0

/* We want to use the libgcrypt provided memory allocation for
   asprintf.  */
#define _ESTREAM_PRINTF_MALLOC        gcry_malloc
#define _ESTREAM_PRINTF_FREE          gcry_free
#define _ESTREAM_PRINTF_EXTRA_INCLUDE "util.h"

#endif /*GNUPG_CONFIG_H_INCLUDED*/
])


AM_MAINTAINER_MODE

# Checks for programs.
AC_MSG_NOTICE([checking for programs])
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
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AC_CHECK_TOOL(AR, ar, :)
AC_PATH_PROG(PERL,"perl")
AC_CHECK_TOOL(WINDRES, windres, :)
AC_ISC_POSIX
gl_EARLY
AC_SYS_LARGEFILE
GNUPG_CHECK_FAQPROG
GNUPG_CHECK_USTAR

# We need to compile and run a program on the build machine.  A
# comment in libgpg-error says that the AC_PROG_CC_FOR_BUILD macro in
# the AC archive is broken for autoconf 2.57.  Given that tehre is no
# newer version of that macro, we assume that it is also broken for
# autoconf 2.61 and thus we use a simple but usually sufficient
# approach.
AC_MSG_CHECKING(for cc for build)
if test "$cross_compiling" = "yes"; then
  CC_FOR_BUILD="${CC_FOR_BUILD-cc}"
else
  CC_FOR_BUILD="${CC_FOR_BUILD-$CC}"
fi
AC_MSG_RESULT($CC_FOR_BUILD)
AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])



try_gettext=yes
have_dosish_system=no
have_w32_system=no
use_simple_gettext=no
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
        disable_keyserver_path=yes
        have_dosish_system=yes
        have_w32_system=yes
        try_gettext="no"
	use_simple_gettext=yes
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
            # Use the newer compiler `-msg_disable ptrmismatch1' to
            # get rid of the unsigned/signed char mismatch warnings.
            # Using this may hide other pointer mismatch warnings, but
	    # it at least lets other warning classes through
            CFLAGS="$CFLAGS -msg_disable ptrmismatch1"
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

AM_CONDITIONAL(USE_SIMPLE_GETTEXT, test x"$use_simple_gettext" = xyes)

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)

if test "$disable_keyserver_path" = yes; then
    AC_DEFINE(DISABLE_KEYSERVER_PATH,1,
              [Defined to disable exec-path for keyserver helpers])
fi

#
# Allows enabling the use of a standard socket by default This is
# gpg-agent's option --[no-]use-standard-socket.  For Windows we force
# the use of this.
#
AC_MSG_CHECKING([whether to use a standard socket by default])
AC_ARG_ENABLE(standard-socket,
              AC_HELP_STRING([--enable-standard-socket],
                             [use a standard socket for the agent by default]),
              use_standard_socket=$enableval)
tmp=""
if test "$use_standard_socket" != yes; then
  if test "$have_w32_system" = yes; then
    use_standard_socket=yes
    tmp=" (forced)"
  fi
fi
AC_MSG_RESULT($use_standard_socket$tmp)
if test "$use_standard_socket" = yes; then
  AC_DEFINE(USE_STANDARD_SOCKET,1,
            [Use a standard socket for the agent by default])
fi


# (These need to go after AC_PROG_CC so that $EXEEXT is defined)
AC_DEFINE_UNQUOTED(EXEEXT,"$EXEEXT",[The executable file extension, if any])

if test x"$try_hkp" = xyes ; then
  AC_SUBST(GPGKEYS_HKP,"gpg2keys_hkp$EXEEXT")
fi

if test x"$try_finger" = xyes ; then
  AC_SUBST(GPGKEYS_FINGER,"gpg2keys_finger$EXEEXT")
fi



#
# Checks for libraries.
#
AC_MSG_NOTICE([checking for libraries])


#
# libgpg-error is a library with error codes shared between GnuPG
# related projects.
#
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)


#
# Libgcrypt is our generic crypto library
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
        have_libgcrypt=yes,have_libgcrypt=no)


#
# libassuan is used for IPC
#
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_API:$NEED_LIBASSUAN_VERSION",
                  have_libassuan=yes,have_libassuan=no)
if test "$have_libassuan" = "yes"; then
  AC_DEFINE_UNQUOTED(GNUPG_LIBASSUAN_VERSION, "$libassuan_version",
            [version of the libbassuan library])
fi



#
# libksba is our X.509 support library
#
AM_PATH_KSBA("$NEED_KSBA_API:$NEED_KSBA_VERSION",have_ksba=yes,have_ksba=no)


#
# libusb allows us to use the integrated CCID smartcard reader driver.
#
# FiXME: Use GNUPG_CHECK_LIBUSB and modify to use separate AC_SUBSTs.
if test "$use_ccid_driver" = yes ; then
  AC_CHECK_LIB(usb, usb_bulk_write,
                [ LIBUSB_LIBS="$LIBUSB_LIBS -lusb"
                  AC_DEFINE(HAVE_LIBUSB,1,
                           [defined if libusb is available])
                  have_libusb=yes
               ])
  AC_CHECK_FUNCS(usb_create_match)
fi
AC_SUBST(LIBUSB_LIBS)

#
# Check wether it is necessary to link against libdl.
#
gnupg_dlopen_save_libs="$LIBS"
LIBS=""
AC_SEARCH_LIBS(dlopen, c dl,,,)
DL_LIBS=$LIBS
AC_SUBST(DL_LIBS)
LIBS="$gnupg_dlopen_save_libs"

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
# Check whether the GNU Pth library is available
# Note, that we include a Pth emulation for W32.
#
GNUPG_PATH_PTH
if test "$have_pth" = "yes"; then
  AC_DEFINE(USE_GNU_PTH, 1,
              [Defined if the GNU Portable Thread Library should be used])
else
  AC_MSG_WARN([[
***
*** To support concurrent access to the gpg-agent and the SCdaemon
*** we need the support of the GNU Portable Threads Library.
*** Download it from ftp://ftp.gnu.org/gnu/pth/
*** On a Debian GNU/Linux system you might want to try
***   apt-get install libpth-dev
***]])
fi


AC_MSG_NOTICE([checking for networking options])

#
# Must check for network library requirements before doing link tests
# for ldap, for example. If ldap libs are static (or dynamic and without
# ELF runtime link paths), then link will fail and LDAP support won't
# be detected.
#
AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))


#
# Check for ADNS.
#
_cppflags="${CPPFLAGS}"
_ldflags="${LDFLAGS}"
AC_ARG_WITH(adns,
            AC_HELP_STRING([--with-adns=DIR],
                           [look for the adns library in DIR]),
            [if test -d "$withval"; then
               CPPFLAGS="${CPPFLAGS} -I$withval/include"
               LDFLAGS="${LDFLAGS} -L$withval/lib"
             fi])
if test "$with_adns" != "no"; then
  AC_CHECK_HEADERS(adns.h,
                AC_CHECK_LIB(adns, adns_init,
                             [have_adns=yes],
                             [CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}]),
                [CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}])
fi
if test "$have_adns" = "yes"; then
  ADNSLIBS="-ladns"
fi
AC_SUBST(ADNSLIBS)
# Newer adns versions feature a free function to be used under W32.
AC_CHECK_FUNCS(adns_free)


#
# Now try for the resolver functions so we can use DNS for SRV, PA and CERT.
#
if test x"$try_hkp" = xyes || test x"$try_http" = xyes ; then
  AC_ARG_ENABLE(dns-srv,
     AC_HELP_STRING([--disable-dns-srv],
                    [disable the use of DNS SRV in HKP and HTTP]),
                use_dns_srv=$enableval,use_dns_srv=yes)
fi

AC_ARG_ENABLE(dns-pka,
   AC_HELP_STRING([--disable-dns-pka],
	[disable the use of PKA records in DNS]),
   use_dns_pka=$enableval,use_dns_pka=yes)

AC_ARG_ENABLE(dns-cert,
   AC_HELP_STRING([--disable-dns-cert],
	[disable the use of CERT records in DNS]),
   use_dns_cert=$enableval,use_dns_cert=yes)

if test x"$use_dns_pka" = xyes || test x"$use_dns_srv" = xyes \
   || test x"$use_dns_cert" = xyes; then
  _dns_save_libs=$LIBS
  LIBS=""
  # the double underscore thing is a glibc-ism?
  AC_SEARCH_LIBS(res_query,resolv bind,,
                 AC_SEARCH_LIBS(__res_query,resolv bind,,have_resolver=no))
  AC_SEARCH_LIBS(dn_expand,resolv bind,,
                 AC_SEARCH_LIBS(__dn_expand,resolv bind,,have_resolver=no))
  AC_SEARCH_LIBS(dn_skipname,resolv bind,,
                 AC_SEARCH_LIBS(__dn_skipname,resolv bind,,have_resolver=no))

  if test x"$have_resolver" != xno ; then

    # Make sure that the BIND 4 resolver interface is workable before
    # enabling any code that calls it.  At some point I'll rewrite the
    # code to use the BIND 8 resolver API.
    # We might also want to use adns instead.  Problem with ADNS is that
    # it does not support v6.

    AC_MSG_CHECKING([whether the resolver is usable])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>]],
[[unsigned char answer[PACKETSZ];
  res_query("foo.bar",C_IN,T_A,answer,PACKETSZ);
  dn_skipname(0,0);
  dn_expand(0,0,0,0,0);
]])],have_resolver=yes,have_resolver=no)
    AC_MSG_RESULT($have_resolver)

    # This is Apple-specific and somewhat bizarre as they changed the
    # define in bind 8 for some reason.

    if test x"$have_resolver" != xyes ; then
       AC_MSG_CHECKING(
             [whether I can make the resolver usable with BIND_8_COMPAT])
       AC_LINK_IFELSE([AC_LANG_PROGRAM([[#define BIND_8_COMPAT
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>]],
[[unsigned char answer[PACKETSZ];
  res_query("foo.bar",C_IN,T_A,answer,PACKETSZ);
  dn_skipname(0,0); dn_expand(0,0,0,0,0);
]])],[have_resolver=yes ; need_compat=yes])
       AC_MSG_RESULT($have_resolver)
    fi
  fi

  if test x"$have_resolver" = xyes ; then
     DNSLIBS=$LIBS

     if test x"$use_dns_srv" = xyes ; then
        AC_DEFINE(USE_DNS_SRV,1,[define to use DNS SRV])
     fi

     if test x"$use_dns_pka" = xyes ; then
        AC_DEFINE(USE_DNS_PKA,1,[define to use our experimental DNS PKA])
     fi

     if test x"$use_dns_cert" = xyes ; then
        AC_DEFINE(USE_DNS_CERT,1,[define to use DNS CERT])
     fi

     if test x"$need_compat" = xyes ; then
        AC_DEFINE(BIND_8_COMPAT,1,[an Apple OSXism])
     fi
  else
     # If we have no resolver library but ADNS (e.g. under W32) enable the
     # code parts which can be used with ADNS.
     if test x"$have_adns" = xyes ; then
        DNSLIBS="$ADNSLIBS"
        AC_DEFINE(USE_ADNS,1,[Use ADNS as resolver library.])

        if test x"$use_dns_srv" = xyes ; then
           AC_DEFINE(USE_DNS_SRV,1)
        fi

        if test x"$use_dns_pka" = xyes ; then
           AC_DEFINE(USE_DNS_PKA,1)
        fi

        if test x"$use_dns_cert" = xyes ; then
           AC_DEFINE(USE_DNS_CERT,1,[define to use DNS CERT])
        fi
     else
        use_dns_srv=no
        use_dns_pka=no
        use_dns_cert=no
     fi
  fi

  LIBS=$_dns_save_libs
fi

AC_SUBST(DNSLIBS)

AM_CONDITIONAL(USE_DNS_SRV, test x"$use_dns_srv" = xyes)


#
# Check for LDAP
#
if test "$try_ldap" = yes ; then
   GNUPG_CHECK_LDAP($NETLIBS)
fi

#
# Check for curl.  We fake the curl API if libcurl isn't installed.
# We require 7.10 or later as we use curl_version_info().
#
LIBCURL_CHECK_CONFIG([yes],[7.10],,[fake_curl=yes])
AM_CONDITIONAL(FAKE_CURL,test x"$fake_curl" = xyes)

# Generic, for us, means curl

if test x"$try_generic" = xyes ; then
   AC_SUBST(GPGKEYS_CURL,"gpg2keys_curl$EXEEXT")
fi

#
# Check for sendmail
#
# This isn't necessarily sendmail itself, but anything that gives a
# sendmail-ish interface to the outside world.  That includes Exim,
# Postfix, etc.  Basically, anything that can handle "sendmail -t".
if test "$try_mailto" = yes ; then
  AC_ARG_WITH(mailprog,
      AC_HELP_STRING([--with-mailprog=NAME],
                     [use "NAME -t" for mail transport]),
             ,with_mailprog=yes)

  if test x"$with_mailprog" = xyes ; then
    AC_PATH_PROG(SENDMAIL,sendmail,,$PATH:/usr/sbin:/usr/libexec:/usr/lib)
    if test "$ac_cv_path_SENDMAIL" ; then
      GPGKEYS_MAILTO="gpg2keys_mailto"
    fi
  elif test x"$with_mailprog" != xno ; then
    AC_MSG_CHECKING([for a mail transport program])
    AC_SUBST(SENDMAIL,$with_mailprog)
    AC_MSG_RESULT($with_mailprog)
    GPGKEYS_MAILTO="gpg2keys_mailto"
  fi
fi

AC_SUBST(GPGKEYS_MAILTO)

#
# Construct a printable name of the OS
#
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


#
# Checking for iconv
#
AM_ICONV


#
# Check for gettext
#
# This is "GNU gnupg" - The project-id script from gettext
#                       needs this string
#
AC_MSG_NOTICE([checking for gettext])
AM_PO_SUBDIRS
AM_GNU_GETTEXT_VERSION([0.17])
if test "$try_gettext" = yes; then
  AM_GNU_GETTEXT([external],[need-ngettext])

  # gettext requires some extra checks.  These really should be part of
  # the basic AM_GNU_GETTEXT macro.  TODO: move other gettext-specific
  # function checks to here.

  AC_CHECK_FUNCS(strchr)
else
  USE_NLS=no
  USE_INCLUDED_LIBINTL=no
  BUILD_INCLUDED_LIBINTL=no
  POSUB=po
  AC_SUBST(USE_NLS)
  AC_SUBST(USE_INCLUDED_LIBINTL)
  AC_SUBST(BUILD_INCLUDED_LIBINTL)
  AC_SUBST(POSUB)
fi

# We use HAVE_LANGINFO_CODESET in a couple of places.
AM_LANGINFO_CODESET

# Checks required for our use locales
gt_LC_MESSAGES


#
# SELinux support
#
if test "$selinux_support" = yes ; then
  AC_DEFINE(ENABLE_SELINUX_HACKS,1,[Define to enable SELinux support])
fi


#
# Checks for header files.
#
AC_MSG_NOTICE([checking for header files])
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h unistd.h langinfo.h termio.h locale.h getopt.h])
AC_CHECK_HEADERS([pty.h utmp.h pwd.h inttypes.h])
AC_HEADER_TIME


#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_MSG_NOTICE([checking for system characteristics])
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

gl_HEADER_SYS_SOCKET
gl_TYPE_SOCKLEN_T

AC_ARG_ENABLE(endian-check,
              AC_HELP_STRING([--disable-endian-check],
	      [disable the endian check and trust the OS provided macros]),
	      endiancheck=$enableval,endiancheck=yes)

if test x"$endiancheck" = xyes ; then
  GNUPG_CHECK_ENDIAN
fi

# fixme: we should get rid of the byte type
GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)

AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)
AC_CHECK_SIZEOF(time_t,,[[
#include <stdio.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
]])


# Ensure that we have UINT64_C before we bother to check for uint64_t
# Fixme: really needed in gnupg?  I think it is only useful in libcgrypt.
AC_CACHE_CHECK([for UINT64_C],[gnupg_cv_uint64_c_works],
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <inttypes.h>]],
                                      [[uint64_t foo=UINT64_C(42);]])],
                                      [gnupg_cv_uint64_c_works=yes],
                                      [gnupg_cv_uint64_c_works=no]   ))
if test "$gnupg_cv_uint64_c_works" = "yes" ; then
   AC_CHECK_SIZEOF(uint64_t)
fi

if test "$ac_cv_sizeof_unsigned_short" = "0" \
   || test "$ac_cv_sizeof_unsigned_int" = "0" \
   || test "$ac_cv_sizeof_unsigned_long" = "0"; then
    AC_MSG_WARN([Hmmm, something is wrong with the sizes - using defaults]);
fi


#
# Checks for library functions.
#
AC_MSG_NOTICE([checking for library functions])
AC_CHECK_DECLS(getpagesize)
AC_FUNC_FSEEKO
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_CHECK_FUNCS([strerror strlwr tcgetattr mmap])
AC_CHECK_FUNCS([strcasecmp strncasecmp ctermid times gmtime_r])
AC_CHECK_FUNCS([unsetenv fcntl ftruncate])
AC_CHECK_FUNCS([gettimeofday getrusage getrlimit setrlimit clock_gettime])
AC_CHECK_FUNCS([atexit raise getpagesize strftime nl_langinfo setlocale])
AC_CHECK_FUNCS([waitpid wait4 sigaction sigprocmask pipe stat getaddrinfo])
AC_CHECK_FUNCS([ttyname rand ftello fsync stat])

AC_CHECK_TYPES([struct sigaction, sigset_t],,,[#include <signal.h>])

#
# These are needed by libjnlib - fixme: we should use a jnlib.m4
# Note:  We already checked pwd.h.
AC_CHECK_FUNCS([memicmp stpcpy strsep strlwr strtoul memmove stricmp strtol])
AC_CHECK_FUNCS([memrchr isascii timegm getrusage setrlimit stat setlocale])
AC_CHECK_FUNCS([flockfile funlockfile fopencookie funopen getpwnam getpwuid])

#
# gnulib checks
#
gl_SOURCE_BASE([gl])
gl_M4_BASE([gl/m4])
gl_MODULES([setenv mkdtemp xsize strpbrk])
gl_INIT


#
# W32 specific test
#
GNUPG_FUNC_MKDIR_TAKES_ONE_ARG

#
# Sanity check regex.  Tests adapted from mutt.
#
AC_MSG_CHECKING([whether regular expression support is requested])
AC_ARG_ENABLE(regex,
  AC_HELP_STRING([--disable-regex],
    [do not handle regular expressions in trust signatures]),
  use_regex=$enableval, use_regex=yes)
AC_MSG_RESULT($use_regex)

if test "$use_regex" = yes ; then
  _cppflags="${CPPFLAGS}"
  _ldflags="${LDFLAGS}"
  AC_ARG_WITH(regex,
     AC_HELP_STRING([--with-regex=DIR],[look for regex in DIR]),
      [
      if test -d "$withval" ; then
        CPPFLAGS="${CPPFLAGS} -I$withval/include"
        LDFLAGS="${LDFLAGS} -L$withval/lib"
      fi
      ],withval="")

  # Does the system have regex functions at all?
  AC_SEARCH_LIBS([regcomp], [regex])
  AC_CHECK_FUNC(regcomp, gnupg_cv_have_regex=yes, gnupg_cv_have_regex=no)

  if test $gnupg_cv_have_regex = no; then
    use_regex=no
  else
    if test x"$cross_compiling" = xyes; then
      AC_MSG_WARN([cross compiling; assuming regexp libray is not broken])
    else
      AC_CACHE_CHECK([whether your system's regexp library is broken],
       [gnupg_cv_regex_broken],
       AC_TRY_RUN([
#include <unistd.h>
#include <regex.h>
main() { regex_t blah ; regmatch_t p; p.rm_eo = p.rm_eo; return regcomp(&blah, "foo.*bar", REG_NOSUB) || regexec (&blah, "foobar", 0, NULL, 0); }],
       gnupg_cv_regex_broken=no, gnupg_cv_regex_broken=yes, gnupg_cv_regex_broken=yes))

      if test $gnupg_cv_regex_broken = yes; then
        AC_MSG_WARN([your regex is broken - disabling regex use])
        use_regex=no
      fi
    fi
  fi
  CPPFLAGS="${_cppflags}"
  LDFLAGS="${_ldflags}"
fi

if test "$use_regex" != yes ; then
  AC_DEFINE(DISABLE_REGEX,1, [Define to disable regular expression support])
fi
AM_CONDITIONAL(DISABLE_REGEX, test x"$use_regex" != xyes)



#
# Do we have zlib? Must do it here because Solaris failed
# when compiling a conftest (due to the "-lz" from LIBS).
# Note that we combine zlib and bzlib2 in ZLIBS.
#
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
       ZLIBS="-lz",
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})

#
# Check whether we can support bzip2
#
if test "$use_bzip2" = yes ; then
  _cppflags="${CPPFLAGS}"
  _ldflags="${LDFLAGS}"
  AC_ARG_WITH(bzip2,
     AC_HELP_STRING([--with-bzip2=DIR],[look for bzip2 in DIR]),
      [
      if test -d "$withval" ; then
        CPPFLAGS="${CPPFLAGS} -I$withval/include"
        LDFLAGS="${LDFLAGS} -L$withval/lib"
      fi
      ],withval="")

  # Checking alongside stdio.h as an early version of bzip2 (1.0)
  # required stdio.h to be included before bzlib.h, and Solaris 9 is
  # woefully out of date.
  if test "$withval" != no ; then
     AC_CHECK_HEADER(bzlib.h,
        AC_CHECK_LIB(bz2,BZ2_bzCompressInit,
  	  [
	  have_bz2=yes
	  ZLIBS="$ZLIBS -lbz2"
	  AC_DEFINE(HAVE_BZIP2,1,
		  [Defined if the bz2 compression library is available])
	  ],
	  CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
	  CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags},[#include <stdio.h>])
  fi
fi
AM_CONDITIONAL(ENABLE_BZIP2_SUPPORT,test x"$have_bz2" = "xyes")
AC_SUBST(ZLIBS)


# Check for readline support
GNUPG_CHECK_READLINE

#
# Allow users to append something to the version string without
# flagging it as development version.  The user version parts is
# considered everything after a dash.
#
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
# W32SOCKLIBS is also defined so that if can be used for tools not
# requiring any network stuff but linking to code in libcommon which
# tracks in winsock stuff (e.g. init_common_subsystems.
if test "$have_w32_system" = yes; then
   W32SOCKLIBS="-lws2_32"
   NETLIBS="${NETLIBS} ${W32SOCKLIBS}"
fi

AC_SUBST(NETLIBS)
AC_SUBST(W32SOCKLIBS)

#
# Setup gcc specific options
#
AC_MSG_NOTICE([checking for cc features])
if test "$GCC" = yes; then
    # Note that it is okay to use CFLAGS here because this are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wformat -Wno-format-y2k -Wformat-security"
        AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wno-missing-field-initializers"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                          [_gcc_wopt=yes],[_gcc_wopt=no])
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -W -Wno-sign-compare -Wno-missing-field-initializers"
        fi
        AC_MSG_CHECKING([if gcc supports -Wdeclaration-after-statement])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wdeclaration-after-statement"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                          [_gcc_wopt=yes],[_gcc_wopt=no])
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -Wdeclaration-after-statement"
        fi
    else
        CFLAGS="$CFLAGS -Wall"
    fi

    AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wno-pointer-sign"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],[_gcc_psign=yes],[_gcc_psign=no])
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],[_gcc_psign=yes],[_gcc_psign=no])
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi
fi


#
# This is handy for debugging so the compiler doesn't rearrange
# things and eliminate variables.
#
AC_ARG_ENABLE(optimization,
   AC_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
                   fi])

#
# Prepare building of estream
#
estream_INIT


#
# Decide what to build
#
if test "$have_adns" = "yes"; then
  AC_SUBST(GPGKEYS_KDNS, "gpg2keys_kdns$EXEEXT")
fi


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
  if test $have_libusb = no; then
     build_scdaemon_extra="${tmp}without internal CCID driver"
     tmp=", "
  fi
  if test -n "$build_scdaemon_extra"; then
     build_scdaemon_extra="(${build_scdaemon_extra})"
  fi
fi


if test "$build_agent_only" = "yes" ; then
  build_gpg=no
  build_gpgsm=no
  build_scdaemon=no
  build_tools=no
  build_doc=no
fi


AM_CONDITIONAL(BUILD_GPG,   test "$build_gpg" = "yes")
AM_CONDITIONAL(BUILD_GPGSM, test "$build_gpgsm" = "yes")
AM_CONDITIONAL(BUILD_AGENT, test "$build_agent" = "yes")
AM_CONDITIONAL(BUILD_SCDAEMON, test "$build_scdaemon" = "yes")
AM_CONDITIONAL(BUILD_TOOLS, test "$build_tools" = "yes")
AM_CONDITIONAL(BUILD_DOC,   test "$build_doc" = "yes")
AM_CONDITIONAL(BUILD_SYMCRYPTRUN, test "$build_symcryptrun" = "yes")
AM_CONDITIONAL(BUILD_GPGTAR,      test "$build_gpgtar" = "yes")

AM_CONDITIONAL(RUN_GPG_TESTS,
	test x$cross_compiling = xno -a "$build_gpg" = yes )


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
*** (at least version $NEED_LIBGCRYPT_VERSION using API $NEED_LIBGCRYPT_API is required.)
***]])
fi
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libassuan/
*** (at least version $NEED_LIBASSUAN_VERSION (API $NEED_LIBASSUAN_API) is required).
***]])
fi
if test "$have_ksba" = "no"; then
    AC_MSG_NOTICE([[
***
*** You need libksba to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libksba/
*** (at least version $NEED_KSBA_VERSION using API $NEED_KSBA_API is required).
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
*** To build GnuPG for Windows you need to use the W32PTH
*** package; available at:
***   ftp://ftp.g10code.com/g10code/w32pth/
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
gl/Makefile
include/Makefile
jnlib/Makefile
common/Makefile
kbx/Makefile
g10/Makefile
sm/Makefile
agent/Makefile
scd/Makefile
keyserver/Makefile
keyserver/gpg2keys_mailto
keyserver/gpg2keys_test
tools/gpg-zip
tools/Makefile
doc/Makefile
tests/Makefile
tests/openpgp/Makefile
tests/pkits/Makefile
])
AC_OUTPUT


echo "
        GnuPG v${VERSION} has been configured as follows:

        Platform:  $PRINTABLE_OS_NAME ($host)

        OpenPGP:   $build_gpg
        S/MIME:    $build_gpgsm
        Agent:     $build_agent $build_agent_threaded
        Smartcard: $build_scdaemon $build_scdaemon_extra
        Gpgtar:    $build_gpgtar

        Protect tool:      $show_gnupg_protect_tool_pgm
        Default agent:     $show_gnupg_agent_pgm
        Default pinentry:  $show_gnupg_pinentry_pgm
        Default scdaemon:  $show_gnupg_scdaemon_pgm
        Default dirmngr:   $show_gnupg_dirmngr_pgm
"
if test x"$use_regex" != xyes ; then
echo "
        Warning: No regular expression support available.
                 OpenPGP trust signatures won't work.
                 gpg-check-pattern will not be build.
"
fi
