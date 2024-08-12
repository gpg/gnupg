# configure.ac - for GnuPG 2.2
# Copyright (C) 1998-2019 Free Software Foundation, Inc.
# Copyright (C) 1998-2019 Werner Koch
# Copyright (C) 2003-2024 g10 Code GmbH
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

# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
min_automake_version="1.16.3"

# To build a release you need to create a tag with the version number
# (git tag -s gnupg-2.n.m) and run "./autogen.sh --force".  Please
# bump the version number immediately *after* the release and do
# another commit and push so that the git magic is able to work.
m4_define([mym4_package],[gnupg])
m4_define([mym4_major], [2])
m4_define([mym4_minor], [2])
m4_define([mym4_micro], [44])

# To start a new development series, i.e a new major or minor number
# you need to mark an arbitrary commit before the first beta release
# with an annotated tag.  For example the 2.1 branch starts off with
# the tag "gnupg-2.1-base".  This is used as the base for counting
# beta numbers before the first release of a series.

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isbeta).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_verslist], m4_split(m4_esyscmd([./autogen.sh --find-version] \
                           mym4_package mym4_major mym4_minor mym4_micro),[:]))
m4_define([mym4_isbeta],       m4_argn(2, mym4_verslist))
m4_define([mym4_version],      m4_argn(4, mym4_verslist))
m4_define([mym4_revision],     m4_argn(7, mym4_verslist))
m4_define([mym4_revision_dec], m4_argn(8, mym4_verslist))
m4_define([mym4_commitid],     m4_argn(9, mym4_verslist))
m4_esyscmd([echo ]mym4_version[>VERSION])
m4_esyscmd([echo ]mym4_commitid[>>VERSION])
AC_INIT([mym4_package],[mym4_version],[https://bugs.gnupg.org])

# When changing the SWDB tag please also adjust the hard coded tags in
# build-aux/speedo.mk and Makefile.am
AC_DEFINE_UNQUOTED(GNUPG_SWDB_TAG, "gnupg22", [swdb tag for this branch])

NEED_GPG_ERROR_VERSION=1.38

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.8.0

NEED_LIBASSUAN_API=2
NEED_LIBASSUAN_VERSION=2.5.0

NEED_KSBA_API=1
NEED_KSBA_VERSION=1.4.0

NEED_NTBTLS_API=1
NEED_NTBTLS_VERSION=0.2.0

NEED_NPTH_API=1
NEED_NPTH_VERSION=1.2


NEED_GNUTLS_VERSION=3.2

NEED_SQLITE_VERSION=3.7

development_version=mym4_isbeta
PACKAGE=$PACKAGE_NAME
PACKAGE_GT=${PACKAGE_NAME}2
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([sm/gpgsm.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AC_CANONICAL_HOST
AB_INIT

AC_USE_SYSTEM_EXTENSIONS


# Some status variables.
have_gpg_error=no
have_libgcrypt=no
have_libassuan=no
have_ksba=no
have_ntbtls=no
have_gnutls=no
have_sqlite=no
have_npth=no
have_libusb=no
have_system_resolver=no
gnupg_have_ldap="n/a"

use_zip=yes
use_bzip2=yes
use_exec=yes
use_trust_models=yes
use_tofu=yes
use_libdns=yes
card_support=yes
use_ccid_driver=auto
dirmngr_auto_start=yes
use_tls_library=no
large_secmem=no
show_tor_support=no

GNUPG_BUILD_PROGRAM(gpg, yes)
GNUPG_BUILD_PROGRAM(gpgsm, yes)
# The agent is a required part and can't be disabled anymore.
build_agent=yes
GNUPG_BUILD_PROGRAM(scdaemon, yes)
GNUPG_BUILD_PROGRAM(g13, no)
GNUPG_BUILD_PROGRAM(dirmngr, yes)
GNUPG_BUILD_PROGRAM(doc, yes)
# We use gpgtar to unpack test data, hence we always build it.  If the
# user opts out, we simply don't install it.
GNUPG_BUILD_PROGRAM(gpgtar, yes)
# We also install the gpg-wks-server tool by default but disable it
# later for platforms where it can't be build.
GNUPG_BUILD_PROGRAM(wks-tools, yes)


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
AC_DEFINE_UNQUOTED(NEED_NTBTLS_VERSION, "$NEED_NTBTLS_VERSION",
                                       [Required version of NTBTLS])



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

AC_ARG_WITH(dirmngr-ldap-pgm,
    [  --with-dirmngr-ldap-pgm=PATH  Use PATH as the default for the dirmngr ldap wrapper)],
          GNUPG_DIRMNGR_LDAP_PGM="$withval", GNUPG_DIRMNGR_LDAP_PGM="" )
AC_SUBST(GNUPG_DIRMNGR_LDAP_PGM)
AM_CONDITIONAL(GNUPG_DIRMNGR_LDAP_PGM, test -n "$GNUPG_DIRMNGR_LDAP_PGM")
show_gnupg_dirmngr_ldap_pgm="(default)"
test -n "$GNUPG_DIRMNGR_LDAP_PGM" \
      && show_gnupg_dirmngr_ldap_pgm="$GNUPG_DIRMNGR_LDAP_PGM"


#
# For a long time gpg 2.x was installed as gpg2.  This changed with
# 2.2.  This option can be used to install gpg under the name gpg2.
#
AC_ARG_ENABLE(gpg-is-gpg2,
    AS_HELP_STRING([--enable-gpg-is-gpg2],[Set installed name of gpg to gpg2]),
    gpg_is_gpg2=$enableval)
if test "$gpg_is_gpg2" = "yes"; then
   AC_DEFINE(USE_GPG2_HACK, 1, [Define to install gpg as gpg2])
fi
AM_CONDITIONAL(USE_GPG2_HACK, test "$gpg_is_gpg2" = "yes")


# SELinux support includes tracking of sensitive files to avoid
# leaking their contents through processing these files by gpg itself
AC_MSG_CHECKING([whether SELinux support is requested])
AC_ARG_ENABLE(selinux-support,
              AS_HELP_STRING([--enable-selinux-support],
                             [enable SELinux support]),
              selinux_support=$enableval, selinux_support=no)
AC_MSG_RESULT($selinux_support)


AC_MSG_CHECKING([whether to allocate extra secure memory])
AC_ARG_ENABLE(large-secmem,
              AS_HELP_STRING([--enable-large-secmem],
                             [allocate extra secure memory]),
              large_secmem=$enableval, large_secmem=no)
AC_MSG_RESULT($large_secmem)
if test "$large_secmem" = yes ; then
   SECMEM_BUFFER_SIZE=65536
else
   SECMEM_BUFFER_SIZE=32768
fi
AC_DEFINE_UNQUOTED(SECMEM_BUFFER_SIZE,$SECMEM_BUFFER_SIZE,
                   [Size of secure memory buffer])

AC_MSG_CHECKING([calibrated passphrase-stretching (s2k) duration])
AC_ARG_WITH(agent-s2k-calibration,
              AS_HELP_STRING([--with-agent-s2k-calibration=MSEC],
                             [calibrate passphrase stretching (s2k) to MSEC milliseconds]),
              agent_s2k_calibration=$withval, agent_s2k_calibration=100)
AC_MSG_RESULT($agent_s2k_calibration milliseconds)
AC_DEFINE_UNQUOTED(AGENT_S2K_CALIBRATION, $agent_s2k_calibration,
                   [Agent s2k calibration time (ms)])

AC_MSG_CHECKING([whether to enable trust models])
AC_ARG_ENABLE(trust-models,
              AS_HELP_STRING([--disable-trust-models],
                             [disable all trust models except "always"]),
              use_trust_models=$enableval)
AC_MSG_RESULT($use_trust_models)
if test "$use_trust_models" = no ; then
    AC_DEFINE(NO_TRUST_MODELS, 1,
             [Define to include only trust-model always])
fi

AC_MSG_CHECKING([whether to enable TOFU])
AC_ARG_ENABLE(tofu,
                AS_HELP_STRING([--disable-tofu],
                               [disable the TOFU trust model]),
              use_tofu=$enableval, use_tofu=$use_trust_models)
AC_MSG_RESULT($use_tofu)
if test "$use_trust_models" = no && test "$use_tofu" = yes; then
    AC_MSG_ERROR([both --disable-trust-models and --enable-tofu given])
fi

AC_MSG_CHECKING([whether to enable libdns])
AC_ARG_ENABLE(libdns,
                AS_HELP_STRING([--disable-libdns],
                               [do not build with libdns support]),
              use_libdns=$enableval, use_libdns=yes)
AC_MSG_RESULT($use_libdns)
if test x"$use_libdns" = xyes ; then
    AC_DEFINE(USE_LIBDNS, 1, [Build with integrated libdns support])
fi
AM_CONDITIONAL(USE_LIBDNS, test "$use_libdns" = yes)


#
# Options to disable algorithm
#

GNUPG_GPG_DISABLE_ALGO([rsa],[RSA public key])
# Elgamal is a MUST algorithm
# DSA is a MUST algorithm
GNUPG_GPG_DISABLE_ALGO([ecdh],[ECDH public key])
GNUPG_GPG_DISABLE_ALGO([ecdsa],[ECDSA public key])
GNUPG_GPG_DISABLE_ALGO([eddsa],[EdDSA public key])

GNUPG_GPG_DISABLE_ALGO([idea],[IDEA cipher])
# 3DES is a MUST algorithm
GNUPG_GPG_DISABLE_ALGO([cast5],[CAST5 cipher])
GNUPG_GPG_DISABLE_ALGO([blowfish],[BLOWFISH cipher])
GNUPG_GPG_DISABLE_ALGO([aes128],[AES128 cipher])
GNUPG_GPG_DISABLE_ALGO([aes192],[AES192 cipher])
GNUPG_GPG_DISABLE_ALGO([aes256],[AES256 cipher])
GNUPG_GPG_DISABLE_ALGO([twofish],[TWOFISH cipher])
GNUPG_GPG_DISABLE_ALGO([camellia128],[CAMELLIA128 cipher])
GNUPG_GPG_DISABLE_ALGO([camellia192],[CAMELLIA192 cipher])
GNUPG_GPG_DISABLE_ALGO([camellia256],[CAMELLIA256 cipher])

GNUPG_GPG_DISABLE_ALGO([md5],[MD5 hash])
# SHA1 is a MUST algorithm
GNUPG_GPG_DISABLE_ALGO([rmd160],[RIPE-MD160 hash])
GNUPG_GPG_DISABLE_ALGO([sha224],[SHA-224 hash])
# SHA256 is a MUST algorithm for GnuPG.
GNUPG_GPG_DISABLE_ALGO([sha384],[SHA-384 hash])
GNUPG_GPG_DISABLE_ALGO([sha512],[SHA-512 hash])


# Allow disabling of zip support.
# This is in general not a good idea because according to rfc4880 OpenPGP
# implementations SHOULD support ZLIB.
AC_MSG_CHECKING([whether to enable the ZIP and ZLIB compression algorithm])
AC_ARG_ENABLE(zip,
   AS_HELP_STRING([--disable-zip],
                  [disable the ZIP and ZLIB compression algorithm]),
   use_zip=$enableval)
AC_MSG_RESULT($use_zip)

# Allow disabling of bzib2 support.
# It is defined only after we confirm the library is available later
AC_MSG_CHECKING([whether to enable the BZIP2 compression algorithm])
AC_ARG_ENABLE(bzip2,
   AS_HELP_STRING([--disable-bzip2],[disable the BZIP2 compression algorithm]),
   use_bzip2=$enableval)
AC_MSG_RESULT($use_bzip2)

# Configure option to allow or disallow execution of external
# programs, like a photo viewer.
AC_MSG_CHECKING([whether to enable external program execution])
AC_ARG_ENABLE(exec,
    AS_HELP_STRING([--disable-exec],[disable all external program execution]),
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
fi


#
# Check for the key/uid cache size.  This can't be zero, but can be
# pretty small on embedded systems.  This is used for the gpg part.
#
AC_MSG_CHECKING([for the size of the key and uid cache])
AC_ARG_ENABLE(key-cache,
        AS_HELP_STRING([--enable-key-cache=SIZE],
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
# Check whether to disable the card support
AC_MSG_CHECKING([whether smartcard support is requested])
AC_ARG_ENABLE(card-support,
              AS_HELP_STRING([--disable-card-support],
                             [disable smartcard support]),
              card_support=$enableval)
AC_MSG_RESULT($card_support)
if test "$card_support" = yes ; then
  AC_DEFINE(ENABLE_CARD_SUPPORT,1,[Define to include smartcard support])
else
  build_scdaemon=no
fi

#
# Allow disabling of internal CCID support.
# It is defined only after we confirm the library is available later
#
AC_MSG_CHECKING([whether to enable the internal CCID driver])
AC_ARG_ENABLE(ccid-driver,
              AS_HELP_STRING([--disable-ccid-driver],
                             [disable the internal CCID driver]),
              use_ccid_driver=$enableval)
AC_MSG_RESULT($use_ccid_driver)

AC_MSG_CHECKING([whether to auto start dirmngr])
AC_ARG_ENABLE(dirmngr-auto-start,
              AS_HELP_STRING([--disable-dirmngr-auto-start],
                             [disable auto starting of the dirmngr]),
              dirmngr_auto_start=$enableval)
AC_MSG_RESULT($dirmngr_auto_start)
if test "$dirmngr_auto_start" = yes ; then
    AC_DEFINE(USE_DIRMNGR_AUTO_START,1,
              [Define to enable auto starting of the dirmngr])
fi


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

/* Some global constants.
 * Note that the homedir must not end in a slash.  */
#ifdef HAVE_DOSISH_SYSTEM
# ifdef HAVE_DRIVE_LETTERS
#  define GNUPG_DEFAULT_HOMEDIR "c:/gnupg"
# else
#  define GNUPG_DEFAULT_HOMEDIR "/gnupg"
# endif
#elif defined(__VMS)
#define GNUPG_DEFAULT_HOMEDIR "/SYS$LOGIN/gnupg"
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.gnupg"
#endif
#define GNUPG_PRIVATE_KEYS_DIR  "private-keys-v1.d"
#define GNUPG_OPENPGP_REVOC_DIR "openpgp-revocs.d"

#define GNUPG_DEF_COPYRIGHT_LINE "Copyright (C) 2024 g10 Code GmbH"


/* For some systems (DOS currently), we hardcode the path here.  For
   POSIX systems the values are constructed by the Makefiles, so that
   the values may be overridden by the make invocations; this is to
   comply with the GNU coding standards.  Note that these values are
   only defaults.  */
#ifdef HAVE_DOSISH_SYSTEM
# ifdef HAVE_DRIVE_LETTERS
#  define GNUPG_BINDIR      "c:\\gnupg"
#  define GNUPG_LIBEXECDIR  "c:\\gnupg"
#  define GNUPG_LIBDIR      "c:\\gnupg"
#  define GNUPG_DATADIR     "c:\\gnupg"
#  define GNUPG_SYSCONFDIR  "c:\\gnupg"
# else
#  define GNUPG_BINDIR      "\\gnupg"
#  define GNUPG_LIBEXECDIR  "\\gnupg"
#  define GNUPG_LIBDIR      "\\gnupg"
#  define GNUPG_DATADIR     "\\gnupg"
#  define GNUPG_SYSCONFDIR  "\\gnupg"
# endif
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

/* Provide the es_ macro for estream.  */
#define GPGRT_ENABLE_ES_MACROS 1

/* We want the argparse macros from gpgrt.  */
#define GPGRT_ENABLE_ARGPARSE_MACROS 1

/* Tell libgcrypt not to use its own libgpg-error implementation. */
#define USE_LIBGPG_ERROR 1

/* Tell Libgcrypt not to include deprecated definitions.  */
#define GCRYPT_NO_DEPRECATED 1

/* Our HTTP code is used in estream mode.  */
#define HTTP_USE_ESTREAM 1

/* Under W32 we do an explicit socket initialization, thus we need to
   avoid the on-demand initialization which would also install an atexit
   handler.  */
#define HTTP_NO_WSASTARTUP

/* Under Windows we use the gettext code from libgpg-error.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS

/* Under WindowsCE we use the strerror replacement from libgpg-error.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS

#endif /*GNUPG_CONFIG_H_INCLUDED*/
])


AM_MAINTAINER_MODE
AC_ARG_VAR(SYSROOT,[locate config scripts also below that directory])

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
AM_SILENT_RULES
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
AC_PATH_PROG(YAT2M, "yat2m")
AC_ARG_VAR(YAT2M, [tool to convert texi to man pages])
AM_CONDITIONAL(HAVE_YAT2M, test -n "$ac_cv_path_YAT2M")
AC_SEARCH_LIBS([strerror],[cposix])
AC_SYS_LARGEFILE
GNUPG_CHECK_USTAR


# GNU AWK requires -n option to interpret "0xHH" as a number
if $AWK 'BEGIN { if (PROCINFO@<:@"version"@:>@) exit 1 }'; then
  AWK_HEX_NUMBER_OPTION=''
  AC_MSG_NOTICE([awk with no option for hexadecimal])
else
  AWK_HEX_NUMBER_OPTION='-n'
  AC_MSG_NOTICE([awk with an option -n for hexadecimal])
fi
AC_SUBST(AWK_HEX_NUMBER_OPTION)

# We need to compile and run a program on the build machine.  A
# comment in libgpg-error says that the AC_PROG_CC_FOR_BUILD macro in
# the AC archive is broken for autoconf 2.57.  Given that there is no
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

# We need to call this macro because other pkg-config macros are
# not always used.
PKG_PROG_PKG_CONFIG


try_gettext=yes
require_iconv=yes
have_dosish_system=no
have_w32_system=no
have_w32ce_system=no
have_android_system=no
use_simple_gettext=no
mmap_needed=yes
require_pipe_to_unblock_pselect=yes
case "${host}" in
    *-mingw32*)
        # special stuff for Windoze NT
        ac_cv_have_dev_random=no
        AC_DEFINE(USE_ONLY_8DOT3,1,
                  [Set this to limit filenames to the 8.3 format])
        AC_DEFINE(USE_SIMPLE_GETTEXT,1,
                  [Because the Unix gettext has too much overhead on
                   MingW32 systems and these systems lack Posix functions,
                   we use a simplified version of gettext])
        have_dosish_system=yes
        have_w32_system=yes
        require_iconv=no
        require_pipe_to_unblock_pselect=no
        case "${host}" in
          *-mingw32ce*)
            have_w32ce_system=yes
            ;;
          *)
            AC_DEFINE(HAVE_DRIVE_LETTERS,1,
                      [Defined if the OS supports drive letters.])
            ;;
        esac
        try_gettext="no"
	use_simple_gettext=yes
	mmap_needed=no
        build_wks_tools=no
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        # OS/2 with the EMX environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        have_dosish_system=yes
        try_gettext="no"
        build_wks_tools=no
        ;;

    i?86-*-msdosdjgpp*)
        # DOS with the DJGPP environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        have_dosish_system=yes
        try_gettext="no"
        build_wks_tools=no
        ;;

    *-*-hpux*)
        if test -z "$GCC" ; then
            CFLAGS="-Ae -D_HPUX_SOURCE $CFLAGS"
        fi
        ;;
    *-dec-osf4*)
        if test -z "$GCC" ; then
            # Suppress all warnings
            # to get rid of the unsigned/signed char mismatch warnings.
            CFLAGS="-w $CFLAGS"
        fi
        ;;
    *-dec-osf5*)
        if test -z "$GCC" ; then
            # Use the newer compiler `-msg_disable ptrmismatch1' to
            # get rid of the unsigned/signed char mismatch warnings.
            # Using this may hide other pointer mismatch warnings, but
	    # it at least lets other warning classes through
            CFLAGS="-msg_disable ptrmismatch1 $CFLAGS"
        fi
        ;;
    m68k-atari-mint)
        ;;
    *-linux-android*)
        have_android_system=yes
        # Android is fully utf-8 and we do not want to use iconv to
        # keeps things simple
        require_iconv=no
        build_wks_tools=no
        ;;
    *-apple-darwin*)
        AC_DEFINE(_DARWIN_C_SOURCE, 1,
                  Expose all libc features (__DARWIN_C_FULL).)
        ;;
    *-*-netbsd*)
        require_pipe_to_unblock_pselect=yes
        ;;
    *)
        ;;
esac

if test "$require_pipe_to_unblock_pselect" = yes; then
   AC_DEFINE(HAVE_PSELECT_NO_EINTR, 1,
             [Defined if we run on systems like NetBSD, where
              pselect cannot be unblocked by signal from a thread
              within the same process.  We use pipe in this case, instead.])
fi

if test "$have_dosish_system" = yes; then
   AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
             [Defined if we run on some of the PCDOS like systems
              (DOS, Windoze. OS/2) with special properties like
              no file modes, case insensitive file names and preferred
              use of backslashes as directory name separators.])
fi
AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = yes)

AM_CONDITIONAL(USE_SIMPLE_GETTEXT, test x"$use_simple_gettext" = xyes)

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
   if test "$have_w32ce_system" = yes; then
      AC_DEFINE(HAVE_W32CE_SYSTEM,1,[Defined if we run on WindowsCE])
   fi
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)
AM_CONDITIONAL(HAVE_W32CE_SYSTEM, test "$have_w32ce_system" = yes)

if test "$have_android_system" = yes; then
   AC_DEFINE(HAVE_ANDROID_SYSTEM,1, [Defined if we build for an Android system])
fi
AM_CONDITIONAL(HAVE_ANDROID_SYSTEM, test "$have_android_system" = yes)


# (These need to go after AC_PROG_CC so that $EXEEXT is defined)
AC_DEFINE_UNQUOTED(EXEEXT,"$EXEEXT",[The executable file extension, if any])


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
                     [version of the libassuan library])
  show_tor_support="only .onion"
fi


#
# libksba is our X.509 support library
#
AM_PATH_KSBA("$NEED_KSBA_API:$NEED_KSBA_VERSION",have_ksba=yes,have_ksba=no)


#
# libusb allows us to use the integrated CCID smartcard reader driver.
#
# FiXME: Use GNUPG_CHECK_LIBUSB and modify to use separate AC_SUBSTs.
if test "$use_ccid_driver" = auto || test "$use_ccid_driver" = yes; then
   case "${host}" in
     *-mingw32*)
       LIBUSB_NAME=
       LIBUSB_LIBS=
       LIBUSB_CPPFLAGS=
       ;;
     *-*-darwin*)
       LIBUSB_NAME=usb-1.0
       LIBUSB_LIBS="-Wl,-framework,CoreFoundation -Wl,-framework,IOKit"
       ;;
     *-*-freebsd*)
       # FreeBSD has a native 1.0 compatible library by -lusb.
       LIBUSB_NAME=usb
       LIBUSB_LIBS=
       ;;
     *)
       LIBUSB_NAME=usb-1.0
       LIBUSB_LIBS=
       ;;
   esac
fi
if test x"$LIBUSB_NAME" != x ; then
   AC_CHECK_LIB($LIBUSB_NAME, libusb_init,
                [ LIBUSB_LIBS="-l$LIBUSB_NAME $LIBUSB_LIBS"
                  have_libusb=yes ])
   AC_MSG_CHECKING([libusb include dir])
   usb_incdir_found="no"
   for _incdir in "" "/usr/include/libusb-1.0" \
       "/usr/local/include/libusb-1.0" "/usr/pkg/include/libusb-1.0"; do
     _libusb_save_cppflags=$CPPFLAGS
     if test -n "${_incdir}"; then
       CPPFLAGS="-I${_incdir} ${CPPFLAGS}"
     fi
     AC_PREPROC_IFELSE([AC_LANG_SOURCE([[@%:@include <libusb.h>]])],
     [usb_incdir=${_incdir}; usb_incdir_found="yes"], [])
     CPPFLAGS=${_libusb_save_cppflags}
     if test "$usb_incdir_found" = "yes"; then
       break
     fi
   done
   if test "$usb_incdir_found" = "yes"; then
     AC_MSG_RESULT([${usb_incdir}])
   else
     AC_MSG_RESULT([not found])
     usb_incdir=""
     have_libusb=no
     if test "$use_ccid_driver" != yes; then
       use_ccid_driver=no
     fi
     LIBUSB_LIBS=""
   fi

   if test "$have_libusb" = yes; then
     AC_DEFINE(HAVE_LIBUSB,1, [defined if libusb is available])
   fi
   if test x"$usb_incdir" = x; then
     LIBUSB_CPPFLAGS=""
   else
     LIBUSB_CPPFLAGS="-I${usb_incdir}"
   fi
fi
AC_SUBST(LIBUSB_LIBS)
AC_SUBST(LIBUSB_CPPFLAGS)

#
# Check whether it is necessary to link against libdl.
# (For example to load libpcsclite)
#
gnupg_dlopen_save_libs="$LIBS"
LIBS=""
AC_SEARCH_LIBS(dlopen, c dl,,,)
DL_LIBS=$LIBS
AC_SUBST(DL_LIBS)
LIBS="$gnupg_dlopen_save_libs"


# Checks for g10

AC_ARG_ENABLE(sqlite,
                AS_HELP_STRING([--disable-sqlite],
                               [disable the use of SQLITE]),
              try_sqlite=$enableval, try_sqlite=yes)

if test x"$use_tofu" = xyes ; then
  if test x"$try_sqlite" = xyes ; then
    PKG_CHECK_MODULES([SQLITE3], [sqlite3 >= $NEED_SQLITE_VERSION],
                                 [have_sqlite=yes],
                                 [have_sqlite=no])
  fi
  if test "$have_sqlite" = "yes"; then
    :
    AC_SUBST([SQLITE3_CFLAGS])
    AC_SUBST([SQLITE3_LIBS])
  else
    use_tofu=no
    tmp=$(echo "$SQLITE3_PKG_ERRORS" | tr '\n' '\v' | sed 's/\v/\n*** /g')
    AC_MSG_WARN([[
***
*** Building without SQLite support - TOFU disabled
***
*** $tmp]])
  fi
fi

AM_CONDITIONAL(SQLITE3, test "$have_sqlite" = "yes")

if test x"$use_tofu" = xyes ; then
    AC_DEFINE(USE_TOFU, 1, [Enable to build the TOFU code])
fi


# Checks for g13

AC_PATH_PROG(ENCFS, encfs, /usr/bin/encfs)
AC_DEFINE_UNQUOTED(ENCFS,
	"${ENCFS}", [defines the filename of the encfs program])

AC_PATH_PROG(FUSERMOUNT, fusermount, /usr/bin/fusermount)
AC_DEFINE_UNQUOTED(FUSERMOUNT,
	"${FUSERMOUNT}", [defines the filename of the fusermount program])


# Checks for dirmngr


#
# Checks formerly used for symcryptrun.
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
# Check whether the nPth library is available
#
AM_PATH_NPTH("$NEED_NPTH_API:$NEED_NPTH_VERSION",have_npth=yes,have_npth=no)
if test "$have_npth" = "yes"; then
  AC_DEFINE(HAVE_NPTH, 1,
              [Defined if the New Portable Thread Library is available])
  AC_DEFINE(USE_NPTH, 1,
              [Defined if support for nPth is requested and nPth is available])
else
  AC_MSG_WARN([[
***
*** To support concurrent access for example in gpg-agent and the SCdaemon
*** we need the support of the New Portable Threads Library.
***]])
fi
#
# Enable debugging of nPth
#
AC_ARG_ENABLE(npth-debug,
   AS_HELP_STRING([--enable-npth-debug],
                  [build with debug version of npth]),
                  [if test $enableval = yes ; then
                     AC_DEFINE(NPTH_ENABLE_DEBUG,1,
                              [Build with debug version of nPth])
                  fi])



#
# NTBTLS is our TLS library.  If it is not available fallback to
# GNUTLS.
#
AC_ARG_ENABLE(ntbtls,
              AS_HELP_STRING([--disable-ntbtls],
                             [disable the use of NTBTLS as TLS library]),
              try_ntbtls=$enableval, try_ntbtls=yes)
if test x"$try_ntbtls" = xyes ; then
  AM_PATH_NTBTLS("$NEED_NTBTLS_API:$NEED_NTBTLS_VERSION",
                 [have_ntbtls=yes],[have_ntbtls=no])
fi
if test "$have_ntbtls" = yes ; then
   use_tls_library=ntbtls
   AC_DEFINE(HTTP_USE_NTBTLS, 1, [Enable NTBTLS support in http.c])
else
  AC_ARG_ENABLE(gnutls,
                AS_HELP_STRING([--disable-gnutls],
                               [disable GNUTLS as fallback TLS library]),
                try_gnutls=$enableval, try_gnutls=yes)
  if test x"$try_gnutls" = xyes ; then
    PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= $NEED_GNUTLS_VERSION],
                                   [have_gnutls=yes],
                                   [have_gnutls=no])
  fi
  if test "$have_gnutls" = "yes"; then
    AC_SUBST([LIBGNUTLS_CFLAGS])
    AC_SUBST([LIBGNUTLS_LIBS])
    use_tls_library=gnutls
    AC_DEFINE(HTTP_USE_GNUTLS, 1, [Enable GNUTLS support in http.c])
  else
    tmp=$(echo "$LIBGNUTLS_PKG_ERRORS" | tr '\n' '\v' | sed 's/\v/\n*** /g')
    AC_MSG_WARN([[
***
*** Building without NTBTLS and GNUTLS - no TLS access to keyservers.
***
*** $tmp]])
  fi
fi

#
# Allow to set a fixed trust store file for system provided certificates.
#
AC_ARG_WITH([default-trust-store-file],
            [AS_HELP_STRING([--with-default-trust-store-file=FILE],
                            [Use FILE as system trust store])],
            default_trust_store_file="$withval",
            default_trust_store_file="")
if test x"$default_trust_store_file" = xno;then
  default_trust_store_file=""
fi
if test x"$default_trust_store_file" != x ; then
  AC_DEFINE_UNQUOTED([DEFAULT_TRUST_STORE_FILE],
    ["$default_trust_store_file"], [Use as default system trust store file])
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
# Check standard resolver functions.
#
if test "$build_dirmngr" = "yes"; then
  _dns_save_libs=$LIBS
  LIBS=""

  # Find the system resolver which can always be enabled with
  # the dirmngr option --standard-resolver.

  # the double underscore thing is a glibc-ism?
  AC_SEARCH_LIBS(res_query,resolv bind,,
                 AC_SEARCH_LIBS(__res_query,resolv bind,,have_resolver=no))
  AC_SEARCH_LIBS(dn_expand,resolv bind,,
                 AC_SEARCH_LIBS(__dn_expand,resolv bind,,have_resolver=no))

  # macOS renames dn_skipname into res_9_dn_skipname in <resolv.h>,
  # and for some reason fools us into believing we don't need
  # -lresolv even if we do.  Since the test program checking for the
  # symbol does not include <resolv.h>, we need to check for the
  # renamed symbol explicitly.
  AC_SEARCH_LIBS(res_9_dn_skipname,resolv bind,,
      AC_SEARCH_LIBS(dn_skipname,resolv bind,,
          AC_SEARCH_LIBS(__dn_skipname,resolv bind,,have_resolver=no)))

  if test x"$have_resolver" != xno ; then

      # Make sure that the BIND 4 resolver interface is workable before
      # enabling any code that calls it.  At some point I'll rewrite the
      # code to use the BIND 8 resolver API.
      # We might also want to use libdns instead.

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
    AC_DEFINE(HAVE_SYSTEM_RESOLVER,1,[The system's resolver is usable.])
    DNSLIBS="$DNSLIBS $LIBS"
    if test x"$need_compat" = xyes ; then
      AC_DEFINE(BIND_8_COMPAT,1,[an Apple OSXism])
    fi
    if test "$use_libdns" = yes; then
     show_tor_support=yes
    fi
  elif test "$use_libdns" = yes; then
    show_tor_support=yes
  else
    AC_MSG_WARN([[
***
*** The system's DNS resolver is not usable.
*** Dirmngr functionality is limited.
***]])
    show_tor_support="${show_tor_support} (no system resolver)"
  fi

  if test "$have_w32_system" = yes; then
    if test "$use_libdns" = yes; then
      DNSLIBS="$DNSLIBS -liphlpapi"
    fi
  fi

  LIBS=$_dns_save_libs
fi

AC_SUBST(DNSLIBS)


#
# Check for LDAP
#
# Note that running the check changes the variable
# gnupg_have_ldap from "n/a" to "no" or "yes".

AC_ARG_ENABLE(ldap,
    AS_HELP_STRING([--disable-ldap],
                   [disable LDAP support]),
    [if test "$enableval" = "no"; then gnupg_have_ldap=no; fi])

if test "$gnupg_have_ldap" != "no" ; then
  if test "$build_dirmngr" = "yes" ; then
     GNUPG_CHECK_LDAP($NETLIBS)
     AC_CHECK_LIB(lber, ber_free,
                  [ LBER_LIBS="$LBER_LIBS -llber"
                    AC_DEFINE(HAVE_LBER,1,
                             [defined if liblber is available])
                    have_lber=yes
                 ])
  fi
fi
AC_SUBST(LBER_LIBS)
if test "$gnupg_have_ldap" = "no"; then
    AC_MSG_WARN([[
***
*** Building without LDAP support.
*** No CRL access or X.509 certificate search available.
***]])
fi

AM_CONDITIONAL(USE_LDAP, [test "$gnupg_have_ldap" = yes])
if test "$gnupg_have_ldap" = yes ; then
  AC_DEFINE(USE_LDAP,1,[Defined if LDAP is support])
fi


#
# Check for sendmail
#
# This isn't necessarily sendmail itself, but anything that gives a
# sendmail-ish interface to the outside world.  That includes Exim,
# Postfix, etc.  Basically, anything that can handle "sendmail -t".
AC_ARG_WITH(mailprog,
      AS_HELP_STRING([--with-mailprog=NAME],
                     [use "NAME -t" for mail transport]),
             ,with_mailprog=yes)
if test x"$with_mailprog" = xyes ; then
    AC_PATH_PROG(SENDMAIL,sendmail,,"$PATH":/usr/sbin:/usr/libexec:/usr/lib)
elif test x"$with_mailprog" != xno ; then
    AC_MSG_CHECKING([for a mail transport program])
    AC_SUBST(SENDMAIL,$with_mailprog)
    AC_MSG_RESULT($with_mailprog)
fi
AC_DEFINE_UNQUOTED(NAME_OF_SENDMAIL,"$SENDMAIL",
                   [Tool with sendmail -t interface])


#
# Construct a printable name of the OS
#
case "${host}" in
    *-mingw32ce*)
        PRINTABLE_OS_NAME="W32CE"
        ;;
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
if test "$require_iconv" = yes; then
  AM_ICONV
else
  LIBICONV=
  LTLIBICONV=
  AC_SUBST(LIBICONV)
  AC_SUBST(LTLIBICONV)
fi


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

# Checks required for our use of locales
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
AC_CHECK_HEADERS([unistd.h langinfo.h termio.h locale.h \
                  pwd.h inttypes.h signal.h sys/select.h sys/time.h \
                  stdint.h signal.h termios.h \
                  ucred.h sys/ucred.h sys/sysmacros.h sys/mkdev.h])



#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_MSG_NOTICE([checking for system characteristics])
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_CHECK_FUNCS([sigdescr_np])
AC_CHECK_DECLS([sys_siglist],[],[],[#include <signal.h>
/* NetBSD declares sys_siglist in unistd.h.  */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
])


gl_HEADER_SYS_SOCKET
gl_TYPE_SOCKLEN_T

AC_SEARCH_LIBS([inet_addr], [nsl])

AC_ARG_ENABLE(endian-check,
              AS_HELP_STRING([--disable-endian-check],
              [disable the endian check and trust the OS provided macros]),
	      endiancheck=$enableval,endiancheck=yes)

if test x"$endiancheck" = xyes ; then
  GNUPG_CHECK_ENDIAN
fi

# fixme: we should get rid of the byte type
AC_CHECK_TYPES([byte, ushort, ulong, u16, u32])
AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)
AC_CHECK_SIZEOF(time_t,,[[
#include <stdio.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#else
# include <time.h>
#endif
]])
GNUPG_TIME_T_UNSIGNED


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
AC_CHECK_FUNCS([atexit canonicalize_file_name clock_gettime ctermid  \
                explicit_bzero fcntl flockfile fsync ftello          \
                ftruncate funlockfile getaddrinfo getenv getpagesize \
                getpwnam getpwuid getrlimit getrusage gettimeofday   \
                gmtime_r inet_ntop inet_pton isascii lstat memicmp   \
                memmove memrchr mmap nl_langinfo pipe raise rand     \
                setenv setlocale setrlimit sigaction sigprocmask     \
                stat stpcpy strcasecmp strerror strftime stricmp     \
                strlwr strncasecmp strpbrk strsep strtol strtoul     \
                strtoull tcgetattr timegm times ttyname unsetenv     \
                wait4 waitpid ])

# On some systems (e.g. Solaris) nanosleep requires linking to librl.
# Given that we use nanosleep only as an optimization over a select
# based wait function we want it only if it is available in libc.
_save_libs="$LIBS"
AC_SEARCH_LIBS([nanosleep], [],
               [AC_DEFINE(HAVE_NANOSLEEP,1,
                [Define to 1 if you have the `nanosleep' function in libc.])])
LIBS="$_save_libs"


# See whether libc supports the Linux inotify interface
case "${host}" in
    *-*-linux*)
        AC_CHECK_FUNCS([inotify_init])
        ;;
esac


if test "$have_android_system" = yes; then
   # On Android ttyname is a stub but prints an error message.
   AC_DEFINE(HAVE_BROKEN_TTYNAME,1,
             [Defined if ttyname does not work properly])
fi

AC_CHECK_TYPES([struct sigaction, sigset_t],,,[#include <signal.h>])

# Dirmngr requires mmap on Unix systems.
if test $ac_cv_func_mmap != yes -a $mmap_needed = yes; then
  AC_MSG_ERROR([[Sorry, the current implementation requires mmap.]])
fi


#
# Check for the getsockopt SO_PEERCRED, etc.
#
AC_CHECK_MEMBERS([struct ucred.pid, struct ucred.cr_pid, struct sockpeercred.pid], [], [], [#include <sys/types.h>
#include <sys/socket.h> ])

# (Open)Solaris
AC_CHECK_FUNCS([getpeerucred])


#
# W32 specific test
#


#
# Do we have zlib? Must do it here because Solaris failed
# when compiling a conftest (due to the "-lz" from LIBS).
# Note that we combine zlib and bzlib2 in ZLIBS.
#
if test "$use_zip" = yes ; then
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
       [
       ZLIBS="-lz"
       AC_DEFINE(HAVE_ZIP,1, [Defined if ZIP and ZLIB are supported])
       ],
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})
fi


#
# Check whether we can support bzip2
#
if test "$use_bzip2" = yes ; then
  _cppflags="${CPPFLAGS}"
  _ldflags="${LDFLAGS}"
  AC_ARG_WITH(bzip2,
     AS_HELP_STRING([--with-bzip2=DIR],[look for bzip2 in DIR]),
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


if test "$development_version" = yes; then
    AC_DEFINE(IS_DEVELOPMENT_VERSION,1,
            [Defined if this is not a regular release])
fi

if test "$USE_MAINTAINER_MODE" = "yes"; then
    AC_DEFINE(MAINTAINER_MODE,1,
            [Defined if this build is in maintainer mode])
fi

AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

GNUPG_CHECK_GNUMAKE

# Add some extra libs here so that previous tests don't fail for
# mysterious reasons - the final link step should bail out.
# W32SOCKLIBS is also defined so that if can be used for tools not
# requiring any network stuff but linking to code in libcommon which
# tracks in winsock stuff (e.g. init_common_subsystems).
if test "$have_w32_system" = yes; then
   if test "$have_w32ce_system" = yes; then
     W32SOCKLIBS="-lws2"
   else
     W32SOCKLIBS="-lws2_32"
   fi
   NETLIBS="${NETLIBS} ${W32SOCKLIBS}"
fi

AC_SUBST(NETLIBS)
AC_SUBST(W32SOCKLIBS)

#
# Setup gcc specific options
#
USE_C99_CFLAGS=
AC_MSG_NOTICE([checking for cc features])
if test "$GCC" = yes; then
    mycflags=
    mycflags_save=$CFLAGS

    # Check whether gcc does not emit a diagnositc for unknown -Wno-*
    # options.  This is the case for gcc >= 4.6
    AC_MSG_CHECKING([if gcc ignores unknown -Wno-* options])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6 )
#kickerror
#endif]],[])],[_gcc_silent_wno=yes],[_gcc_silent_wno=no])
    AC_MSG_RESULT($_gcc_silent_wno)

    # Note that it is okay to use CFLAGS here because these are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        mycflags="$mycflags -O3 -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        mycflags="$mycflags -Wformat -Wno-format-y2k -Wformat-security"
        if test x"$_gcc_silent_wno" = xyes ; then
          _gcc_wopt=yes
        else
          AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
          CFLAGS="-Wno-missing-field-initializers"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                            [_gcc_wopt=yes],[_gcc_wopt=no])
          AC_MSG_RESULT($_gcc_wopt)
        fi
        if test x"$_gcc_wopt" = xyes ; then
          mycflags="$mycflags -W -Wno-sign-compare -Wno-format-zero-length"
          mycflags="$mycflags -Wno-missing-field-initializers"
          mycflags="$mycflags -Wno-format-zero-length"
        fi

        AC_MSG_CHECKING([if gcc supports -Wdeclaration-after-statement])
        CFLAGS="-Wdeclaration-after-statement"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        if test x"$_gcc_wopt" = xyes ; then
          mycflags="$mycflags -Wdeclaration-after-statement"
        fi

        AC_MSG_CHECKING([if gcc supports -Wlogical-op])
        CFLAGS="-Wlogical-op -Werror"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        if test x"$_gcc_wopt" = xyes ; then
          mycflags="$mycflags -Wlogical-op"
        fi

        AC_MSG_CHECKING([if gcc supports -Wvla])
        CFLAGS="-Wvla"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        if test x"$_gcc_wopt" = xyes ; then
          mycflags="$mycflags -Wvla"
        fi

    else
        mycflags="$mycflags -Wall"
        if test x"$_gcc_silent_wno" = xyes ; then
          mycflags="$mycflags -Wno-format-zero-length"
        fi
    fi

    if test x"$_gcc_silent_wno" = xyes ; then
      _gcc_psign=yes
    else
      AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
      CFLAGS="-Wno-pointer-sign"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                        [_gcc_psign=yes],[_gcc_psign=no])
      AC_MSG_RESULT($_gcc_psign)
    fi
    if test x"$_gcc_psign" = xyes ; then
       mycflags="$mycflags -Wno-pointer-sign"
    fi

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    if test x"$_gcc_psign" = xyes ; then
       mycflags="$mycflags -Wpointer-arith"
    fi

    CFLAGS="$mycflags $mycflags_save"
    if test "$use_libdns" = yes; then
       # dirmngr/dns.{c,h} require C99 and GNU extensions.  */
       USE_C99_CFLAGS="-std=gnu99"
    fi
fi

AC_SUBST(USE_C99_CFLAGS)


#
# This is handy for debugging so the compiler doesn't rearrange
# things and eliminate variables.
#
AC_ARG_ENABLE(optimization,
   AS_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed s/-O[[1-9]]\ /-O0\ /g`
                   fi])

# Add -Werror to CFLAGS.  This hack can be used to avoid problems with
# misbehaving autoconf tests in case the user supplied -Werror.
#
AC_ARG_ENABLE(werror,
   AS_HELP_STRING([--enable-werror],
                  [append -Werror to CFLAGS]),
                  [if test $enableval = yes ; then
                      CFLAGS="$CFLAGS -Werror"
                   fi])

#
# Configure option --enable-all-tests
#
AC_MSG_CHECKING([whether "make check" shall run all tests])
AC_ARG_ENABLE(all-tests,
              AS_HELP_STRING([--enable-all-tests],
                             [let "make check" run all tests]),
              run_all_tests=$enableval, run_all_tests=no)
AC_MSG_RESULT($run_all_tests)
if test "$run_all_tests" = "yes"; then
    AC_DEFINE(RUN_ALL_TESTS,1,
            [Defined if "make check" shall run all tests])
fi

#
# Configure option --disable-tests
#
AC_MSG_CHECKING([whether tests should be run])
AC_ARG_ENABLE(tests,
              AS_HELP_STRING([--disable-tests],
                             [do not run any tests]),
              run_tests=$enableval, run_tests=yes)
AC_MSG_RESULT($run_tests)

#
# We do not want support for the GNUPG_BUILDDIR environment variable
# in a released version.  However, our regression tests suite requires
# this and thus we build with support for it during "make distcheck".
# This configure option implements this along with the top Makefile's
# AM_DISTCHECK_CONFIGURE_FLAGS.
#
gnupg_builddir_envvar=no
AC_ARG_ENABLE(gnupg-builddir-envvar,,
              gnupg_builddir_envvar=$enableval)
if test x"$gnupg_builddir_envvar" = x"yes"; then
   AC_DEFINE(ENABLE_GNUPG_BUILDDIR_ENVVAR, 1,
      [This is only used with "make distcheck"])
fi


#
# To avoid problems with systemd cleaning up the /run/user directory,
# this option will make GnuPG try to use /run/gnupg/user as socket dir
# before /run/user
#
AC_ARG_ENABLE(run-gnupg-user-socket,
    AS_HELP_STRING([--enable-run-gnupg-user-socket],
                   [try /run/gnupg/user for sockets prior to /run/user]),
    use_run_gnupg_user_socket=$enableval)
if test x"$use_run_gnupg_user_socket" = x"yes"; then
   AC_DEFINE(USE_RUN_GNUPG_USER_SOCKET, 1,
            [If defined try /run/gnupg/user before /run/user])
fi


#
# Decide what to build
#

build_scdaemon_extra=""
if test "$build_scdaemon" = "yes"; then
  if test $have_libusb = no; then
     build_scdaemon_extra="without internal CCID driver"
  fi
  if test -n "$build_scdaemon_extra"; then
     build_scdaemon_extra="(${build_scdaemon_extra})"
  fi
fi


#
# Set variables for use by automake makefiles.
#
AM_CONDITIONAL(BUILD_GPG,         test "$build_gpg" = "yes")
AM_CONDITIONAL(BUILD_GPGSM,       test "$build_gpgsm" = "yes")
AM_CONDITIONAL(BUILD_AGENT,       test "$build_agent" = "yes")
AM_CONDITIONAL(BUILD_SCDAEMON,    test "$build_scdaemon" = "yes")
AM_CONDITIONAL(BUILD_G13,         test "$build_g13" = "yes")
AM_CONDITIONAL(BUILD_DIRMNGR,     test "$build_dirmngr" = "yes")
AM_CONDITIONAL(BUILD_DOC,         test "$build_doc" = "yes")
AM_CONDITIONAL(BUILD_GPGTAR,      test "$build_gpgtar" = "yes")
AM_CONDITIONAL(BUILD_WKS_TOOLS,   test "$build_wks_tools" = "yes")

AM_CONDITIONAL(DISABLE_TESTS,       test "$run_tests" != yes)
AM_CONDITIONAL(ENABLE_CARD_SUPPORT, test "$card_support" = yes)
AM_CONDITIONAL(NO_TRUST_MODELS,     test "$use_trust_models" = no)
AM_CONDITIONAL(USE_TOFU,            test "$use_tofu" = yes)

#
# Set some defines for use gpgconf.
#
if test "$build_gpg" = yes ; then
    AC_DEFINE(BUILD_WITH_GPG,1,[Defined if GPG is to be build])
fi
if test "$build_gpgsm" = yes ; then
    AC_DEFINE(BUILD_WITH_GPGSM,1,[Defined if GPGSM is to be build])
fi
if test "$build_agent" = yes ; then
    AC_DEFINE(BUILD_WITH_AGENT,1,[Defined if GPG-AGENT is to be build])
fi
if test "$build_scdaemon" = yes ; then
    AC_DEFINE(BUILD_WITH_SCDAEMON,1,[Defined if SCDAEMON is to be build])
fi
if test "$build_dirmngr" = yes ; then
    AC_DEFINE(BUILD_WITH_DIRMNGR,1,[Defined if DIRMNGR is to be build])
fi
if test "$build_g13" = yes ; then
    AC_DEFINE(BUILD_WITH_G13,1,[Defined if G13 is to be build])
fi


#
# Define Name strings
#
AC_DEFINE_UNQUOTED(GNUPG_NAME, "GnuPG", [The name of the project])

AC_DEFINE_UNQUOTED(GPG_NAME, "gpg", [The name of the OpenPGP tool])
AC_DEFINE_UNQUOTED(GPG_DISP_NAME, "GnuPG", [The displayed name of gpg])

AC_DEFINE_UNQUOTED(GPGSM_NAME, "gpgsm", [The name of the S/MIME tool])
AC_DEFINE_UNQUOTED(GPGSM_DISP_NAME, "GPGSM", [The displayed name of gpgsm])

AC_DEFINE_UNQUOTED(GPG_AGENT_NAME, "gpg-agent", [The name of the agent])
AC_DEFINE_UNQUOTED(GPG_AGENT_DISP_NAME, "GPG Agent",
                                        [The displayed name of gpg-agent])

AC_DEFINE_UNQUOTED(SCDAEMON_NAME, "scdaemon", [The name of the scdaemon])
AC_DEFINE_UNQUOTED(SCDAEMON_DISP_NAME, "SCDaemon",
                                       [The displayed name of scdaemon])

AC_DEFINE_UNQUOTED(DIRMNGR_NAME, "dirmngr", [The name of the dirmngr])
AC_DEFINE_UNQUOTED(DIRMNGR_DISP_NAME, "DirMngr",
                                      [The displayed name of dirmngr])

AC_DEFINE_UNQUOTED(G13_NAME, "g13", [The name of the g13 tool])
AC_DEFINE_UNQUOTED(G13_DISP_NAME, "G13", [The displayed name of g13])

AC_DEFINE_UNQUOTED(GPGCONF_NAME, "gpgconf", [The name of the gpgconf tool])
AC_DEFINE_UNQUOTED(GPGCONF_DISP_NAME, "GPGConf",
                                      [The displayed name of gpgconf])

AC_DEFINE_UNQUOTED(GPGTAR_NAME, "gpgtar", [The name of the gpgtar tool])

AC_DEFINE_UNQUOTED(GPG_AGENT_SOCK_NAME, "S.gpg-agent",
                   [The name of the agent socket])
AC_DEFINE_UNQUOTED(GPG_AGENT_EXTRA_SOCK_NAME, "S.gpg-agent.extra",
                   [The name of the agent socket for remote access])
AC_DEFINE_UNQUOTED(GPG_AGENT_BROWSER_SOCK_NAME, "S.gpg-agent.browser",
                   [The name of the agent socket for browsers])
AC_DEFINE_UNQUOTED(GPG_AGENT_SSH_SOCK_NAME, "S.gpg-agent.ssh",
                   [The name of the agent socket for ssh])
AC_DEFINE_UNQUOTED(DIRMNGR_INFO_NAME, "DIRMNGR_INFO",
                   [The name of the dirmngr info envvar])
AC_DEFINE_UNQUOTED(SCDAEMON_SOCK_NAME, "S.scdaemon",
                   [The name of the SCdaemon socket])
AC_DEFINE_UNQUOTED(DIRMNGR_SOCK_NAME, "S.dirmngr",
                   [The name of the dirmngr socket])
AC_DEFINE_UNQUOTED(DIRMNGR_DEFAULT_KEYSERVER,
                   "hkps://keyserver.ubuntu.com",
      [The default keyserver for dirmngr to use, if none is explicitly given])

AC_DEFINE_UNQUOTED(GPGEXT_GPG, "gpg", [The standard binary file suffix])

if test "$have_w32_system" = yes; then
  AC_DEFINE_UNQUOTED(GNUPG_REGISTRY_DIR, "Software\\\\GNU\\\\GnuPG",
                     [The directory part of the W32 registry keys])
fi


#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
BUILD_COMMITID="mym4_commitid"
AC_SUBST(BUILD_REVISION)
AC_DEFINE_UNQUOTED(BUILD_COMMITID, "$BUILD_COMMITID",
                   [Git commit id used to build this package])

changequote(,)dnl
BUILD_VERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./'`
changequote([,])dnl
BUILD_VERSION="${BUILD_VERSION}mym4_revision_dec"
BUILD_FILEVERSION=`echo "${BUILD_VERSION}" | tr . ,`
AC_SUBST(BUILD_VERSION)
AC_SUBST(BUILD_FILEVERSION)

AC_ARG_ENABLE([build-timestamp],
  AS_HELP_STRING([--enable-build-timestamp],
                 [set an explicit build timestamp for reproducibility.
                  (default is the current time in ISO-8601 format)]),
     [if test "$enableval" = "yes"; then
        BUILD_TIMESTAMP=`date -u +%Y-%m-%dT%H:%M+0000 2>/dev/null || date`
      else
        BUILD_TIMESTAMP="$enableval"
      fi
      BUILD_HOSTNAME="$ac_hostname"],
     [BUILD_TIMESTAMP="<none>"
      BUILD_HOSTNAME="<anon>"])
AC_SUBST(BUILD_TIMESTAMP)
AC_DEFINE_UNQUOTED(BUILD_TIMESTAMP, "$BUILD_TIMESTAMP",
                   [The time this package was configured for a build])
AC_SUBST(BUILD_HOSTNAME)


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
***   https://gnupg.org/ftp/gcrypt/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libgcrypt" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libgcrypt to build this program.
**  This library is for example available at
***   https://gnupg.org/ftp/gcrypt/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION (API $NEED_LIBGCRYPT_API) is required.)
***]])
fi
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program.
*** This library is for example available at
***   https://gnupg.org/ftp/gcrypt/libassuan/
*** (at least version $NEED_LIBASSUAN_VERSION (API $NEED_LIBASSUAN_API) is required).
***]])
fi
if test "$have_ksba" = "no"; then
    die=yes
    AC_MSG_NOTICE([[
***
*** You need libksba to build this program.
*** This library is for example available at
***   https://gnupg.org/ftp/gcrypt/libksba/
*** (at least version $NEED_KSBA_VERSION using API $NEED_KSBA_API is required).
***]])
fi
if test "$gnupg_have_ldap" = yes; then
  if test "$have_w32ce_system" = yes; then
    AC_MSG_NOTICE([[
*** Note that CeGCC might be broken, a package fixing this is:
***    http://files.kolab.org/local/windows-ce/
***                           source/wldap32_0.1-mingw32ce.orig.tar.gz
***                           binary/wldap32-ce-arm-dev_0.1-1_all.deb
***]])
   fi
fi
if test "$have_npth" = "no"; then
    die=yes
    AC_MSG_NOTICE([[
***
*** It is now required to build with support for the
*** New Portable Threads Library (nPth). Please install this
*** library first.  The library is for example available at
***   https://gnupg.org/ftp/gcrypt/npth/
*** (at least version $NEED_NPTH_VERSION (API $NEED_NPTH_API) is required).
***]])
fi

if test "$require_iconv" = yes; then
  if test "$am_func_iconv" != yes; then
    die=yes
    AC_MSG_NOTICE([[
***
*** The system does not provide a working iconv function.  Please
*** install a suitable library; for example GNU Libiconv which is
*** available at:
***   https://ftp.gnu.org/gnu/libiconv/
***]])
  fi
fi

if test "$use_ccid_driver" = yes; then
  if test "$have_libusb" != yes; then
    die=yes
    AC_MSG_NOTICE([[
***
*** You need libusb to build the internal ccid driver.  Please
*** install a libusb suitable for your system.
***]])
  fi
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
common/Makefile
common/w32info-rc.h
regexp/Makefile
kbx/Makefile
g10/Makefile
sm/Makefile
agent/Makefile
scd/Makefile
g13/Makefile
dirmngr/Makefile
tools/gpg-zip
tools/Makefile
doc/Makefile
tests/Makefile
tests/gpgscm/Makefile
tests/openpgp/Makefile
tests/migrations/Makefile
tests/gpgsm/Makefile
tests/gpgme/Makefile
tests/pkits/Makefile
g10/gpg.w32-manifest
g10/gpgv.w32-manifest
sm/gpgsm.w32-manifest
agent/gpg-agent.w32-manifest
scd/scdaemon.w32-manifest
dirmngr/dirmngr.w32-manifest
dirmngr/dirmngr_ldap.w32-manifest
dirmngr/dirmngr-client.w32-manifest
tools/gpgconf.w32-manifest
tools/gpgtar.w32-manifest
tools/gpg-connect-agent.w32-manifest
tools/gpg-check-pattern.w32-manifest
tools/gpg-wks-client.w32-manifest
])


AC_OUTPUT


echo "
        GnuPG v${VERSION} has been configured as follows:

        Revision:  mym4_revision  (mym4_revision_dec)
        Platform:  $PRINTABLE_OS_NAME ($host)

        OpenPGP:   $build_gpg
        S/MIME:    $build_gpgsm
        Agent:     $build_agent
        Smartcard: $build_scdaemon $build_scdaemon_extra
        G13:       $build_g13
        Dirmngr:   $build_dirmngr
        Gpgtar:    $build_gpgtar
        WKS tools: $build_wks_tools

        Protect tool:      $show_gnupg_protect_tool_pgm
        LDAP wrapper:      $show_gnupg_dirmngr_ldap_pgm
        Default agent:     $show_gnupg_agent_pgm
        Default pinentry:  $show_gnupg_pinentry_pgm
        Default scdaemon:  $show_gnupg_scdaemon_pgm
        Default dirmngr:   $show_gnupg_dirmngr_pgm

        Dirmngr auto start:  $dirmngr_auto_start
        Readline support:    $gnupg_cv_have_readline
        LDAP support:        $gnupg_have_ldap
        TLS support:         $use_tls_library
        TOFU support:        $use_tofu
        Tor support:         $show_tor_support
"
if test "x${gpg_config_script_warn}" != x; then
cat <<G10EOF
        Warning: Mismatches between the target platform and the
                 to be used libraries have been detected for:
                  ${gpg_config_script_warn}
                 Please check above for more warning messages.

G10EOF
fi
if test "${build_gpg}" != "yes"; then
cat <<G10EOF
        Warning: The component "gpg" is used by other components as
                 well as for the test suite.  You have disabled
                 this component and thus other things won't work.

G10EOF
fi
if test "${run_tests}" != "yes"; then
cat <<G10EOF
        Warning: The use of the test suite has been disabled!
                 This is in almost all cases a bad idea.  Take care.

G10EOF
fi
