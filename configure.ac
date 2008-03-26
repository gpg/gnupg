# configure.ac script for GnuPG
# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
#               2008 Free Software Foundation, Inc.
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
#
# (Process this file with autoconf to produce a configure script.)

AC_PREREQ(2.59)
min_automake_version="1.9.3"

# Remember to change the version number immediately *after* a release.
# Set my_issvn to "yes" for non-released code.  Remember to run an
# "svn up" and "autogen.sh --force" right before creating a distribution.
m4_define([my_version], [1.4.9])
m4_define([my_issvn], [no])

m4_define([svn_revision], m4_esyscmd([echo $((svn info 2>/dev/null \
          || echo 'Revision: 0')|sed -n '/^Revision:/ s/[^0-9]//gp'|head -1)| \
          tr -d '\n']))
AC_INIT([gnupg], my_version[]m4_if(my_issvn,[yes],[-svn[]svn_revision]),
        [bug-gnupg@gnu.org])
# Set development_version to yes if the minor number is odd or you
# feel that the default check for a development version is not
# sufficient.
development_version=no

AC_CONFIG_AUX_DIR(scripts)
AC_CONFIG_SRCDIR(g10/gpg.c)
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([std-options])
AB_INIT
AM_CONFIG_HEADER(config.h)

AC_GNU_SOURCE

dnl
dnl  Check for random module options
dnl
AC_MSG_CHECKING([which random module to use])
AC_ARG_ENABLE(static-rnd,
    AC_HELP_STRING([[--enable-static-rnd=[egd|unix|linux|auto]]],
                   [specify a random number source]),
    [use_static_rnd=$enableval], [use_static_rnd=default])

if test "$use_static_rnd" = no; then
    use_static_rnd=default
fi

case "$use_static_rnd" in
    egd | linux | unix | default )
      AC_MSG_RESULT($use_static_rnd)
      ;;
    auto )
      AC_MSG_RESULT(automagically selected at runtime)
      ;;
    * )
      AC_MSG_RESULT(invalid argument)
      AC_MSG_ERROR(there is no random module rnd$use_static_rnd)
      ;;
esac

AC_ARG_WITH(egd-socket,
    AC_HELP_STRING([--with-egd-socket=NAME],[use NAME for the EGD socket]),
            egd_socket_name="$withval", egd_socket_name="" )
AC_DEFINE_UNQUOTED(EGD_SOCKET_NAME, "$egd_socket_name",
                   [Define if you don't want the default EGD socket name.
                    For details see cipher/rndegd.c])


dnl
dnl See whether the user wants to disable checking for /dev/random

AC_MSG_CHECKING([whether use of /dev/random is requested])
AC_ARG_ENABLE(dev-random,
   AC_HELP_STRING([--disable-dev-random],[disable the use of dev random]),
   try_dev_random=$enableval, try_dev_random=yes)
AC_MSG_RESULT($try_dev_random)


dnl
dnl  Check other options
dnl

AC_MSG_CHECKING([whether assembler modules are requested])
AC_ARG_ENABLE(asm,
   AC_HELP_STRING([--disable-asm],[do not use assembler modules]),
     try_asm_modules=$enableval, try_asm_modules=yes)
AC_MSG_RESULT($try_asm_modules)

dnl AC_MSG_CHECKING([whether memory guard is requested])
dnl AC_ARG_ENABLE(m-guard,
dnl     [  --enable-m-guard        enable memory guard facility],
dnl     use_m_guard=$enableval, use_m_guard=no)
dnl AC_MSG_RESULT($use_m_guard)
dnl if test "$use_m_guard" = yes ; then
dnl     AC_DEFINE(M_GUARD,1,[Define to use the (obsolete) malloc guarding feature])
dnl fi

# SELinux support includes tracking of sensitive files to avoid
# leaking their contents through processing these files by gpg itself
AC_MSG_CHECKING([whether SELinux support is requested])
AC_ARG_ENABLE(selinux-support,
              AC_HELP_STRING([--enable-selinux-support],
                             [enable SELinux support]),
              selinux_support=$enableval, selinux_support=no)
AC_MSG_RESULT($selinux_support)


AC_MSG_CHECKING([whether the new iconv based code is requested])
AC_ARG_ENABLE(gnupg-iconv,
              AC_HELP_STRING([--disable-gnupg-iconv],
                             [disable the new iconv code]),
              gnupg_use_iconv=$enableval, gnupg_use_iconv=yes)
AC_MSG_RESULT($gnupg_use_iconv)

dnl See if we are disabling any algorithms or features for a smaller
dnl binary

try_extensions=no

try_gettext=yes
try_dns=yes
use_rsa=yes
use_idea=yes
use_cast5=yes
use_blowfish=yes
use_aes=yes
use_twofish=yes
use_camellia=no
use_sha256=yes
use_sha512=yes
use_bzip2=yes
use_exec=yes
card_support=yes
agent_support=yes
disable_keyserver_path=no

AC_ARG_ENABLE(minimal,
   AC_HELP_STRING([--enable-minimal],[build the smallest gpg binary possible]),
   try_gettext=no
   try_dns=no
   use_rsa=no
   use_idea=no
   use_cast5=no
   use_blowfish=no
   use_aes=no
   use_twofish=no
   use_camellia=no
   use_sha256=no
   use_sha512=no
   use_bzip2=no
   use_exec=no
   card_support=no
   agent_support=no)


AC_MSG_CHECKING([whether OpenPGP card support is requested])
AC_ARG_ENABLE(card-support,
              AC_HELP_STRING([--disable-card-support],
                             [disable OpenPGP card support]),
              card_support=$enableval)
AC_MSG_RESULT($card_support)


# Note that we may later disable the agent support based on the platform.
AC_MSG_CHECKING([whether gpg-agent support is requested])
AC_ARG_ENABLE(agent-support,
              AC_HELP_STRING([--disable-agent-support],
                             [disable gpg-agent support]),
              agent_support=$enableval)
AC_MSG_RESULT($agent_support)


AC_MSG_CHECKING([whether to enable the RSA public key algorithm])
AC_ARG_ENABLE(rsa,
   AC_HELP_STRING([--disable-rsa],[disable the RSA public key algorithm]),
   use_rsa=$enableval)
AC_MSG_RESULT($use_rsa)
if test x"$use_rsa" = xyes ; then
   AC_DEFINE(USE_RSA,1,[Define to include the RSA public key algorithm])
fi

AC_MSG_CHECKING([whether to enable the IDEA cipher])
AC_ARG_ENABLE(idea,
   AC_HELP_STRING([--disable-idea],[disable the IDEA cipher]),
   use_idea=$enableval)
AC_MSG_RESULT($use_idea)
if test x"$use_idea" = xyes ; then
   AC_DEFINE(USE_IDEA,1,[Define to include the IDEA cipher])

# We don't need idea but some people claim that they need it for
# research etc., so we allow to place an idea source code into the
# cipher directory and statically link it if available, otherwise we
# link to a stub.  We don't use AC_CHECK_FILE to avoid caching.

   AC_MSG_CHECKING([for idea cipher module])
   tmp=""
   if test -f $srcdir/cipher/idea.c; then 
      IDEA_O=idea.o
      tmp=idea
   else
      IDEA_O=idea-stub.o
      tmp=no
      try_extensions=yes
   fi
   AC_SUBST(IDEA_O)
   AC_MSG_RESULT($tmp)
fi

AC_MSG_CHECKING([whether to enable the CAST5 cipher])
AC_ARG_ENABLE(cast5,
   AC_HELP_STRING([--disable-cast5],[disable the CAST5 cipher]),
   use_cast5=$enableval)
AC_MSG_RESULT($use_cast5)
if test x"$use_cast5" = xyes ; then
   AC_DEFINE(USE_CAST5,1,[Define to include the CAST5 cipher])
fi

AC_MSG_CHECKING([whether to enable the BLOWFISH cipher])
AC_ARG_ENABLE(blowfish,
   AC_HELP_STRING([--disable-blowfish],[disable the BLOWFISH cipher]),
   use_blowfish=$enableval)
AC_MSG_RESULT($use_blowfish)
if test x"$use_blowfish" = xyes ; then
   AC_DEFINE(USE_BLOWFISH,1,[Define to include the BLOWFISH cipher])
fi

AC_MSG_CHECKING([whether to enable the AES ciphers])
AC_ARG_ENABLE(aes,
   AC_HELP_STRING([--disable-aes],[disable the AES, AES192, and AES256 ciphers]),
   use_aes=$enableval)
AC_MSG_RESULT($use_aes)
if test x"$use_aes" = xyes ; then
   AC_DEFINE(USE_AES,1,[Define to include the AES, AES192, and AES256 ciphers])
fi

AC_MSG_CHECKING([whether to enable the TWOFISH cipher])
AC_ARG_ENABLE(twofish,
   AC_HELP_STRING([--disable-twofish],[disable the TWOFISH cipher]),
   use_twofish=$enableval)
AC_MSG_RESULT($use_twofish)
if test x"$use_twofish" = xyes ; then
   AC_DEFINE(USE_TWOFISH,1,[Define to include the TWOFISH cipher])
fi

AC_MSG_CHECKING([whether to enable the CAMELLIA cipher])
AC_ARG_ENABLE(camellia,
   AC_HELP_STRING([--enable-camellia],[enable the CAMELLIA cipher]),
   use_camellia=$enableval)
AC_MSG_RESULT($use_camellia)
if test x"$use_camellia" = xyes ; then
   AC_DEFINE(USE_CAMELLIA,1,[Define to include the CAMELLIA cipher])
   AC_MSG_WARN([[
***
*** The Camellia cipher is for testing only and is NOT for production use!
***]])
fi

AC_MSG_CHECKING([whether to enable the SHA-224 and SHA-256 digests])
AC_ARG_ENABLE(sha256,
   AC_HELP_STRING([--disable-sha256],[disable the SHA-224 and SHA-256 digests]),
   use_sha256=$enableval)
AC_MSG_RESULT($use_sha256)
if test x"$use_sha256" = xyes ; then
   AC_DEFINE(USE_SHA256,1,[Define to include the SHA-224 and SHA-256 digests])
fi

dnl SHA512 is defined only after we confirm 64-bit support later
AC_MSG_CHECKING([whether to enable the SHA-384 and SHA-512 digests])
AC_ARG_ENABLE(sha512,
   AC_HELP_STRING([--disable-sha512],[disable the SHA-384 and SHA-512 digests]),
   use_sha512=$enableval)
AC_MSG_RESULT($use_sha512)

dnl BZLIB is defined only after we confirm the library is available later
AC_MSG_CHECKING([whether to enable the BZIP2 compression algorithm])
AC_ARG_ENABLE(bzip2,
   AC_HELP_STRING([--disable-bzip2],[disable the BZIP2 compression algorithm]),
   use_bzip2=$enableval)
AC_MSG_RESULT($use_bzip2)

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
      AC_HELP_STRING([--disable-photo-viewers],[disable photo ID viewers]),
      [if test "$enableval" = no ; then
         AC_DEFINE(DISABLE_PHOTO_VIEWER,1,[define to disable photo viewing])
      fi],enableval=yes)
  gnupg_cv_enable_photo_viewers=$enableval
  AC_MSG_RESULT($enableval)

  if test "$gnupg_cv_enable_photo_viewers" = yes ; then
    AC_MSG_CHECKING([whether to use a fixed photo ID viewer])
    AC_ARG_WITH(photo-viewer,
        AC_HELP_STRING([--with-photo-viewer=FIXED_VIEWER],
                       [set a fixed photo ID viewer]),
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
      AC_HELP_STRING([--disable-keyserver-helpers],
                     [disable all external keyserver support]),
      [if test "$enableval" = no ; then
         AC_DEFINE(DISABLE_KEYSERVER_HELPERS,1,
                  [define to disable keyserver helpers])
      fi],enableval=yes)
  gnupg_cv_enable_keyserver_helpers=$enableval
  AC_MSG_RESULT($enableval)

  if test "$gnupg_cv_enable_keyserver_helpers" = yes ; then
dnl LDAP is defined only after we confirm the library is available later
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

AC_MSG_CHECKING([whether the included zlib is requested])
AC_ARG_WITH(included-zlib,
    AC_HELP_STRING([--with-included-zlib],[use the zlib code included here]),
[g10_force_zlib="$withval"], [g10_force_zlib=no] )
AC_MSG_RESULT($g10_force_zlib)

dnl
dnl Check for the key/uid cache size.  This can't be zero, but can be
dnl pretty small on embedded systems.
dnl
AC_MSG_CHECKING([for the size of the key and uid cache])
AC_ARG_ENABLE(key-cache,
	AC_HELP_STRING([--enable-key-cache=SIZE],[Set key cache to SIZE (default 4096)]),,enableval=4096)

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
AC_DEFINE_UNQUOTED(PK_UID_CACHE_SIZE,$key_cache_size,[Size of the key and UID caches])

dnl
dnl Check whether we want to use Linux capabilities
dnl
AC_MSG_CHECKING([whether use of capabilities is requested])
AC_ARG_WITH(capabilities,
    AC_HELP_STRING([--with-capabilities],
                   [use linux capabilities [default=no]]),
[use_capabilities="$withval"],[use_capabilities=no])
AC_MSG_RESULT($use_capabilities)

# To avoid double inclusion of config.h which might happen at some
# places, we add the usual double inclusion protection.
AH_TOP([
#ifndef GNUPG_CONFIG_H_INCLUDED
#define GNUPG_CONFIG_H_INCLUDED
])

AH_BOTTOM([
/* We didn't define endianness above, so get it from OS macros.  This
is intended for making fat binary builds on OS X. */
#if !defined(BIG_ENDIAN_HOST) && !defined(LITTLE_ENDIAN_HOST)
# if defined(__BIG_ENDIAN__)
#  define BIG_ENDIAN_HOST 1
# elif defined(__LITTLE_ENDIAN__)
#  define LITTLE_ENDIAN_HOST 1
# else
#  error "No endianness found"
# endif
#endif

#if !(defined(HAVE_FORK) && defined(HAVE_PIPE) && defined(HAVE_WAITPID))
# define EXEC_TEMPFILE_ONLY
#endif

/* Please note that the string version must not contain more
   than one character because the using code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
# define DIRSEP_C '\\'
# define EXTSEP_C '.'
# define DIRSEP_S "\\"
# define EXTSEP_S "."
# define PATHSEP_C ';'
# define PATHSEP_S ";"
#else
# define DIRSEP_C '/'
# define EXTSEP_C '.'
# define DIRSEP_S "/"
# define EXTSEP_S "."
# define PATHSEP_C ':'
# define PATHSEP_S ":"
#endif


/* For some OSes we need to use fixed strings for certain directories.  */
#ifdef HAVE_DRIVE_LETTERS
# define LOCALEDIR         "c:\\\\lib\\\\gnupg\\\\locale"
# define GNUPG_LIBDIR      "c:\\\\lib\\\\gnupg"
# define GNUPG_LIBEXECDIR  "c:\\\\lib\\\\gnupg"
# define GNUPG_DATADIR     "c:\\\\lib\\\\gnupg"
# define GNUPG_HOMEDIR     "c:\\\\gnupg"
#else
# ifdef __VMS
#  define GNUPG_HOMEDIR "/SYS\$LOGIN/gnupg" 
# else
#  define GNUPG_HOMEDIR "~/.gnupg" 
# endif
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

/* This is the major version number of GnuPG so that
   source included files can test for this. */
#define GNUPG_MAJOR_VERSION 1

/* This is the same as VERSION, but should be overridden if the
   platform cannot handle things like dots'.' in filenames.  Set
   SAFE_VERSION_DOT and SAFE_VERSION_DASH to whatever SAFE_VERSION
   uses for dots and dashes. */
#define SAFE_VERSION      VERSION
#define SAFE_VERSION_DOT  '.'
#define SAFE_VERSION_DASH '-'

#endif /*GNUPG_CONFIG_H_INCLUDED*/
])

AM_MAINTAINER_MODE

dnl Checks for programs.

AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB
AC_CHECK_TOOL(AR, ar, :)
AC_PATH_PROG(PERL,"perl")
AC_ISC_POSIX
AC_SYS_LARGEFILE
AC_PROG_INSTALL
AC_PROG_AWK
AC_CHECK_PROG(DOCBOOK_TO_MAN, docbook-to-man, yes, no)
AM_CONDITIONAL(HAVE_DOCBOOK_TO_MAN, test "$ac_cv_prog_DOCBOOK_TO_MAN" = yes)
GNUPG_CHECK_FAQPROG
GNUPG_CHECK_DOCBOOK_TO_TEXI
GNUPG_CHECK_USTAR


# According to a comment by Marcus Brinkman in libgpg-error, the
# AC_PROG_CC_FOR_BUILD macro in the AC archive is broken for autoconf
# 2.57.  Thus we use a simply use "cc" if we are cross-compiling.
AC_MSG_CHECKING(for cc for build)
if test "$cross_compiling" = "yes"; then
  CC_FOR_BUILD="${CC_FOR_BUILD-cc}"
else
  CC_FOR_BUILD="${CC_FOR_BUILD-$CC}"
fi
AC_MSG_RESULT($CC_FOR_BUILD)
AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])



MPI_OPT_FLAGS=""

have_dosish_system=no
need_dlopen=yes
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
        AC_DEFINE(HAVE_W32_SYSTEM,1,
                  [Defined if we run on a W32 API based system])
        disable_keyserver_path=yes
        have_dosish_system=yes
        need_dlopen=no
        try_gettext="no"
        agent_support=no
	use_simple_gettext=yes
	have_w32_system=yes
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        # OS/2 with the EMX environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        have_dosish_system=yes
        try_gettext="no"
        agent_support=no
        ;;

    i?86-*-msdosdjgpp*)
        # DOS with the DJGPP environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        have_dosish_system=yes
        try_gettext="no"
        agent_support=no
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
             [defined if we run on some of the PCDOS like systems 
              (DOS, Windoze. OS/2) with special properties like
              no file modes])
fi
AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = yes)

AM_CONDITIONAL(USE_SIMPLE_GETTEXT, test x"$use_simple_gettext" = xyes)
AM_CONDITIONAL(HAVE_W32_SYSTEM, test x"$have_w32_system" = xyes)

if test "$disable_keyserver_path" = yes; then
    AC_DEFINE(DISABLE_KEYSERVER_PATH,1,
              [define to disable exec-path for keyserver helpers])
fi

AC_SUBST(MPI_OPT_FLAGS)
GNUPG_SYS_SYMBOL_UNDERSCORE

dnl These need to go after AC_PROG_CC so that $EXEEXT is defined

AC_DEFINE_UNQUOTED(EXEEXT,"$EXEEXT",[The executable file extension, if any])

if test x"$try_hkp" = xyes ; then
  AC_SUBST(GPGKEYS_HKP,"gpgkeys_hkp$EXEEXT")
fi

if test x"$try_finger" = xyes ; then
  AC_SUBST(GPGKEYS_FINGER,"gpgkeys_finger$EXEEXT")
fi

dnl Must check for network library requirements before doing link tests
dnl for ldap, for example. If ldap libs are static (or dynamic and without
dnl ELF runtime link paths), then link will fail and LDAP support won't
dnl be detected.

AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))

dnl Now try for the resolver functions so we can use DNS for SRV, PKA,
dnl and CERT.

if test x"$try_dns" = xyes ; then
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
fi

if test x"$use_dns_pka" = xyes || test x"$use_dns_srv" = xyes || test x"$use_dns_cert" = xyes; then
  _dns_save_libs=$LIBS
  LIBS=""
  # the double underscore thing is a glibc-ism?
  AC_SEARCH_LIBS(res_query,resolv bind socket,,
            AC_SEARCH_LIBS(__res_query,resolv bind socket,,have_resolver=no))
  AC_SEARCH_LIBS(dn_expand,resolv bind socket,,
            AC_SEARCH_LIBS(__dn_expand,resolv bind socket,,have_resolver=no))
  AC_SEARCH_LIBS(dn_skipname,resolv bind socket,,
            AC_SEARCH_LIBS(__dn_skipname,resolv bind socket,,have_resolver=no))

  if test x"$have_resolver" != xno ; then

    # Make sure that the BIND 4 resolver interface is workable before
    # enabling any code that calls it.  At some point I'll rewrite the
    # code to use the BIND 8 resolver API.

    AC_MSG_CHECKING([whether the resolver is usable])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>],
[[unsigned char answer[PACKETSZ]; res_query("foo.bar",C_IN,T_A,answer,PACKETSZ); dn_skipname(0,0); dn_expand(0,0,0,0,0);]])],have_resolver=yes,have_resolver=no)
    AC_MSG_RESULT($have_resolver)

    # This is Apple-specific and somewhat bizarre as they changed the
    # define in bind 8 for some reason.

    if test x"$have_resolver" != xyes ; then
       AC_MSG_CHECKING([whether I can make the resolver usable with BIND_8_COMPAT])
       AC_LINK_IFELSE([AC_LANG_PROGRAM([#define BIND_8_COMPAT
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>],
[[unsigned char answer[PACKETSZ]; res_query("foo.bar",C_IN,T_A,answer,PACKETSZ); dn_skipname(0,0); dn_expand(0,0,0,0,0);]])],[have_resolver=yes ; need_compat=yes])
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
     use_dns_srv=no
     use_dns_pka=no
     use_dns_cert=no
  fi

  LIBS=$_dns_save_libs
fi

AC_SUBST(DNSLIBS)

AM_CONDITIONAL(USE_DNS_SRV, test x"$use_dns_srv" = xyes)

# Check for LDAP

if test "$try_ldap" = yes ; then
   GNUPG_CHECK_LDAP($NETLIBS)
fi

# Check for curl.  We fake the curl API if libcurl isn't installed.

LIBCURL_CHECK_CONFIG([yes],,,[fake_curl=yes])
AM_CONDITIONAL(FAKE_CURL,test x"$fake_curl" = xyes)

# Generic, for us, means curl

if test x"$try_generic" = xyes ; then
   AC_SUBST(GPGKEYS_CURL,"gpgkeys_curl$EXEEXT")
fi

dnl This isn't necessarily sendmail itself, but anything that gives a
dnl sendmail-ish interface to the outside world.  That includes qmail,
dnl postfix, etc.  Basically, anything that can handle "sendmail -t".

if test "$try_mailto" = yes ; then
  AC_ARG_WITH(mailprog,
     AC_HELP_STRING([--with-mailprog=NAME],
                    [use "NAME -t" for mail transport]),,with_mailprog=yes)

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
        try_extensions=no
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
# 1. Set names of random devices
#
NAME_OF_DEV_RANDOM="/dev/random"
NAME_OF_DEV_URANDOM="/dev/urandom"
case "${host}" in
    *-openbsd*)
        NAME_OF_DEV_RANDOM="/dev/srandom"
        NAME_OF_DEV_URANDOM="/dev/urandom"
        ;;
esac
AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, "$NAME_OF_DEV_RANDOM",
                   [defined to the name of the strong random device])
AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, "$NAME_OF_DEV_URANDOM",
                   [defined to the name of the weaker random device])
AC_SUBST(MPI_OPT_FLAGS)


dnl Checks for libraries.

AM_PO_SUBDIRS
AM_GNU_GETTEXT_VERSION([0.16.1])
if test "$try_gettext" = yes; then
  AM_GNU_GETTEXT(,[need-ngettext])
  # gettext requires some extra checks.  These really should be part of
  # the basic AM_GNU_GETTEXT macro.  TODO: move other gettext-specific
  # function checks to here.
  AC_CHECK_FUNCS(strchr)
else
  enable_nls=no
  USE_NLS=no
  USE_INCLUDED_LIBINTL=no
  BUILD_INCLUDED_LIBINTL=no
  POSUB=po
  AC_SUBST(USE_NLS)
  AC_SUBST(USE_INCLUDED_LIBINTL)
  AC_SUBST(BUILD_INCLUDED_LIBINTL)
  AC_SUBST(POSUB)
fi


if test "$try_extensions" = yes || test x"$card_support" = xyes ; then
  if test "$need_dlopen" = yes; then
    _dl_save_libs=$LIBS
    LIBS=""
    AC_SEARCH_LIBS(dlopen,dl,found_dlopen=yes)
    if test x"$found_dlopen" = "xyes" ; then
      AC_DEFINE(HAVE_DL_DLOPEN,1,
                [Defined when the dlopen function family is available])
      DLLIBS=$LIBS
    else
      if test "$try_extensions" = yes ; then
         AC_MSG_NOTICE([dlopen not found.  Disabling extensions.])
	 try_extensions=no
      fi
  
      if test "$card_support" = yes ; then
         AC_MSG_WARN([dlopen not found.  Disabling OpenPGP card support.])
         card_support=no
      fi
    fi
    LIBS=$_dl_save_libs
  fi
fi

AC_SUBST(DLLIBS)

if test "$card_support" = yes ; then
  AC_DEFINE(ENABLE_CARD_SUPPORT,1,[Define to include OpenPGP card support])
fi

if test "$agent_support" = yes ; then
  AC_DEFINE(ENABLE_AGENT_SUPPORT,1,[Define to include gpg-agent support])
fi

if test "$try_extensions" = yes ; then
  AC_DEFINE(USE_DYNAMIC_LINKING,1,[Define to enable the use of extensions])
fi

if test "$selinux_support" = yes ; then
  AC_DEFINE(ENABLE_SELINUX_HACKS,1,[Define to enable SELinux support])
fi

if test "$gnupg_use_iconv" = yes ; then
  AC_DEFINE(USE_GNUPG_ICONV,1,[Define to use the new iconv based code])
fi

AM_CONDITIONAL(ENABLE_CARD_SUPPORT, test "$card_support" = yes)
AM_CONDITIONAL(ENABLE_AGENT_SUPPORT, test "$agent_support" = yes)

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([unistd.h langinfo.h termio.h locale.h getopt.h pwd.h])

# Note that we do not check for iconv here because this is done anyway
# by the gettext checks and thus it allows us to disable the use of
# iconv by using --disable-nls.

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

AC_ARG_ENABLE(endian-check,
              AC_HELP_STRING([--disable-endian-check],
	      [disable the endian check and trust the OS provided macros]),
	      endiancheck=$enableval,endiancheck=yes)

if test x"$endiancheck" = xyes ; then
   GNUPG_CHECK_ENDIAN
fi

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
AC_CHECK_HEADERS([inttypes.h])
AC_CACHE_CHECK([for UINT64_C], [gnupg_cv_uint64_c_works],
               AC_LINK_IFELSE(AC_LANG_PROGRAM([#include <inttypes.h>],[
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
if test x"$use_sha512" = xyes \
   && test "$ac_cv_sizeof_unsigned_int" != "8" \
   && test "$ac_cv_sizeof_unsigned_long" != "8" \
   && test "$ac_cv_sizeof_unsigned_long_long" != "8" \
   && test x"$ac_cv_sizeof_uint64_t" != "x8"; then
    AC_MSG_NOTICE([No 64-bit types.  Disabling SHA-384 and SHA-512.])
    use_sha512=no
fi

if test x"$use_sha512" = xyes ; then
    AC_DEFINE(USE_SHA512,1,[Define to include the SHA-384 and SHA-512 digests])
fi

AM_CONDITIONAL(USE_SHA512, test x"$use_sha512" = xyes)

dnl Checks for library functions.
AC_CHECK_DECLS(getpagesize)
AC_FUNC_FSEEKO
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_CHECK_FUNCS(strerror stpcpy strlwr tcgetattr strtoul mmap sysconf)
AC_CHECK_FUNCS(strcasecmp strncasecmp ctermid times unsetenv getpwnam getpwuid)
AC_CHECK_FUNCS(memmove gettimeofday getrusage setrlimit clock_gettime)
AC_CHECK_FUNCS(atexit raise getpagesize strftime nl_langinfo setlocale)
AC_CHECK_FUNCS(waitpid wait4 sigaction sigprocmask rand pipe stat getaddrinfo)
AC_CHECK_FUNCS(fcntl ftruncate)
AC_REPLACE_FUNCS(mkdtemp timegm isascii memrchr strsep)

AC_CHECK_TYPES([struct sigaction, sigset_t],,,[#include <signal.h>])

# See if getopt is in libiberty.  This is of course not optimal since
# it might be somewhere other than libiberty, but does cover the
# mingw32 case.

AC_CHECK_FUNC(getopt,,AC_CHECK_LIB(iberty,getopt,AC_SUBST(GETOPT,"-liberty")))

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

AC_MSG_WARN([[
***
*** WARNING: using capabilities with GnuPG is experimental code!
***]])

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


GNUPG_CHECK_IPC
if test "$ac_cv_header_sys_shm_h" = "yes"; then
  AC_DEFINE(USE_SHM_COPROCESSING,1,
            [define if the shared memory interface should be made available])
fi

AM_CONDITIONAL(HAVE_SHM, test "$ac_cv_header_sys_shm_h" = yes)

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
dnl Figure out the default random module.
dnl
random_modules=""
if test "$use_static_rnd" = default; then
     if test "$ac_cv_have_dev_random" = yes; then
        random_modules="rndlinux"
     else
         case "${host}" in
            *-mingw32*|*-*-cygwin*)
                random_modules="rndw32"
                ;;
            i?86-emx-os2|i?86-*-os2*emx)
                random_modules="rndos2"
                ;;
            m68k-atari-mint)
                random_modules="rndatari"
                ;;
            i?86-*-msdosdjgpp*)
                :
                ;;
            *)
                random_modules="rndlinux rndegd rndunix"
                AC_DEFINE(USE_ALL_RANDOM_MODULES, 1, 
                          [Allow to select random modules at runtime.])
                ;;
         esac
     fi
else
  if test "$use_static_rnd" = auto; then
     random_modules="rndlinux rndegd rndunix"
     AC_DEFINE(USE_ALL_RANDOM_MODULES, 1)
  else
     random_modules="rnd$use_static_rnd";
  fi
fi

if test -z "$random_modules"; then
   AC_MSG_ERROR(no random module available)
fi
print_egd_warning=no
for rndmod in $random_modules "" ; do
  case "$rndmod" in
    rndlinux)
         AC_DEFINE(USE_RNDLINUX,1, 
                  [Defined if the /dev/random based RNG should be used.])
         use_rndlinux=yes
         ;;
    rndunix)
         AC_DEFINE(USE_RNDUNIX,1, 
                  [Defined if the default Unix RNG should be used.])
         print_egd_warning=yes
         use_rndunix=yes
          ;;
    rndegd)
         AC_DEFINE(USE_RNDEGD,1, 
                  [Defined if the EGD based RNG should be used.])
         use_rndegd=yes
         ;;
    rndw32)
         AC_DEFINE(USE_RNDW32,1, 
                  [Defined if the Windows specific RNG should be used.])
         use_rndw32=yes
        ;;
   esac
done

AM_CONDITIONAL(USE_RNDLINUX, test "$use_rndlinux" = yes)
AM_CONDITIONAL(USE_RNDUNIX,  test "$use_rndunix" = yes)
AM_CONDITIONAL(USE_RNDEGD,   test "$use_rndegd" = yes)
AM_CONDITIONAL(USE_RNDW32,   test "$use_rndw32" = yes)

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

# Sanity check regex.  Tests adapted from mutt.

AC_MSG_CHECKING([whether regular expression support is requested])
AC_ARG_ENABLE(regex,
  AC_HELP_STRING([--disable-regex],
    [do not handle regular expressions in trust signatures]),
  use_regex=$enableval, use_regex=yes)
AC_MSG_RESULT($use_regex)

if test "$use_regex" = yes ; then
  AC_MSG_CHECKING([whether the included regex lib is requested])
  AC_ARG_WITH(included-regex,
      AC_HELP_STRING([--with-included-regex],
                     [use the included GNU regex library]),
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
     AC_DEFINE(USE_INTERNAL_REGEX,1,[ Define if you want to use the included regex lib ])
  fi
else
  AC_DEFINE(DISABLE_REGEX,1,[ Define to disable regular expression support ])
fi

AM_CONDITIONAL(USE_INTERNAL_REGEX, test x"$gnupg_cv_included_regex" = xyes)

dnl Do we have zlib? Must do it here because Solaris failed
dnl when compiling a conftest (due to the "-lz" from LIBS).
use_local_zlib=yes
if test "$g10_force_zlib" = "yes"; then
  :
else
  _cppflags="${CPPFLAGS}"
  _ldflags="${LDFLAGS}"

  AC_ARG_WITH(zlib,
     AC_HELP_STRING([--with-zlib=DIR],[use libz in DIR]),[
    if test -d "$withval"; then
      CPPFLAGS="${CPPFLAGS} -I$withval/include"
      LDFLAGS="${LDFLAGS} -L$withval/lib"
    fi
  ])

  AC_CHECK_HEADER(zlib.h,
      AC_CHECK_LIB(z, deflateInit2_,
       use_local_zlib=no
       ZLIBS="-lz",
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})
fi

if test "$use_local_zlib" = yes ; then
    AC_CONFIG_LINKS(zlib.h:zlib/zlib.h zconf.h:zlib/zconf.h )
    ZLIBS="../zlib/libzlib.a"
fi

AM_CONDITIONAL(ENABLE_LOCAL_ZLIB, test "$use_local_zlib" = yes)

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

# libusb allows us to use the integrated CCID smartcard reader driver.
# We don't need it if we don't have card support though.
if test "$card_support" = yes ; then
   GNUPG_CHECK_LIBUSB
fi

# Check for readline support
GNUPG_CHECK_READLINE

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


# add some extra libs here so that previous tests don't fail for
# mysterious reasons - the final link step should bail out. 
case "${host}" in
    *-mingw32*)
dnl      NETLIBS="$NETLIBS -lwsock32"
	W32LIBS="-lwsock32"
        ;;
    *)
       ;;
esac

AC_SUBST(NETLIBS)
AC_SUBST(W32LIBS)

# Special options used with gcc.
if test "$GCC" = yes; then
    # Note that it is okay to use CFLAGS here because this are just
    # warning options and the user should have a chance of overriding
    #them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wformat-nonliteral"
    else
        CFLAGS="$CFLAGS -Wall"
    fi

    # This is handy for debugging so the compiler doesn't rearrange
    # things and eliminate variables.
    AC_ARG_ENABLE(optimization,
       AC_HELP_STRING([--disable-optimization],
		      [disable compiler optimization]),
                      [if test $enableval = no ; then
                         CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
                       fi])

    AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])

    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wno-pointer-sign"

    AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)

    CFLAGS=$_gcc_cflags_save;

    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi
fi

CL_AS_NOEXECSTACK

if test "$print_egd_warning" = yes; then
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
***           http://www.gnupg.org/download/#EGD
***
*** You may want to run ./configure with --enable-static-rnd=egd or
*** --enable-static-rnd=auto to use it.
***]])
fi

AC_CONFIG_FILES([
Makefile
m4/Makefile
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
tools/gpg-zip
zlib/Makefile
checks/Makefile
])
AC_OUTPUT

# Give some feedback
echo
echo   "                Version info:   $PACKAGE_STRING"             
echo   "                Configured for: $PRINTABLE_OS_NAME ($host)"
if test -n "$show_extraasm"; then
  echo "  Extra cpu specific functions:$show_extraasm"
fi
echo

if test  x"$use_camellia" = xyes ; then
  echo "WARNING: The Camellia cipher is for testing only and is NOT for production use!"
  echo
fi

