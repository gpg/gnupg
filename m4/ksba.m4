# ksba.m4 - autoconf macro to detect ksba
#       Copyright (C) 2002, 2018, 2024 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Last-changed: 2024-06-13

dnl
dnl Find gpgrt-config, which uses .pc file
dnl (minimum pkg-config functionality, supporting cross build)
dnl
dnl _AM_PATH_GPGRT_CONFIG
AC_DEFUN([_AM_PATH_GPGRT_CONFIG],[dnl
  AC_PATH_PROG(GPGRT_CONFIG, gpgrt-config, no, [$prefix/bin:$PATH])
  if test "$GPGRT_CONFIG" != "no"; then
    # Determine gpgrt_libdir
    #
    # Get the prefix of gpgrt-config assuming it's something like:
    #   <PREFIX>/bin/gpgrt-config
    gpgrt_prefix=${GPGRT_CONFIG%/*/*}
    possible_libdir1=${gpgrt_prefix}/lib
    # Determine by using system libdir-format with CC, it's like:
    #   Normal style: /usr/lib
    #   GNU cross style: /usr/<triplet>/lib
    #   Debian style: /usr/lib/<multiarch-name>
    #   Fedora/openSUSE style: /usr/lib, /usr/lib32 or /usr/lib64
    # It is assumed that CC is specified to the one of host on cross build.
    if libdir_candidates=$(${CC:-cc} -print-search-dirs | \
          sed -n -e "/^libraries/{s/libraries: =//;s/:/\\
/g;p;}"); then
      # From the output of -print-search-dirs, select valid pkgconfig dirs.
      libdir_candidates=$(for dir in $libdir_candidates; do
        if p=$(cd $dir 2>/dev/null && pwd); then
          test -d "$p/pkgconfig" && echo $p;
        fi
      done)

      for possible_libdir0 in $libdir_candidates; do
        # possible_libdir0:
        #   Fallback candidate, the one of system-installed (by $CC)
        #   (/usr/<triplet>/lib, /usr/lib/<multiarch-name> or /usr/lib32)
        # possible_libdir1:
        #   Another candidate, user-locally-installed
        #   (<gpgrt_prefix>/lib)
        # possible_libdir2
        #   Most preferred
        #   (<gpgrt_prefix>/<triplet>/lib,
        #    <gpgrt_prefix>/lib/<multiarch-name> or <gpgrt_prefix>/lib32)
        if test "${possible_libdir0##*/}" = "lib"; then
          possible_prefix0=${possible_libdir0%/lib}
          possible_prefix0_triplet=${possible_prefix0##*/}
          if test -z "$possible_prefix0_triplet"; then
            continue
          fi
          possible_libdir2=${gpgrt_prefix}/$possible_prefix0_triplet/lib
        else
          possible_prefix0=${possible_libdir0%%/lib*}
          possible_libdir2=${gpgrt_prefix}${possible_libdir0#$possible_prefix0}
        fi
        if test -f ${possible_libdir2}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir2}
        elif test -f ${possible_libdir1}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir1}
        elif test -f ${possible_libdir0}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir0}
        fi
        if test -n "$gpgrt_libdir"; then break; fi
      done
    fi
    if test -z "$gpgrt_libdir"; then
      # No valid pkgconfig dir in any of the system directories, fallback
      gpgrt_libdir=${possible_libdir1}
    fi
  else
    unset GPGRT_CONFIG
  fi

  if test -n "$gpgrt_libdir"; then
    # Add the --libdir option to GPGRT_CONFIG
    GPGRT_CONFIG="$GPGRT_CONFIG --libdir=$gpgrt_libdir"
    # Make sure if gpgrt-config really works, by testing config gpg-error
    if ! $GPGRT_CONFIG gpg-error --exists; then
      # If it doesn't work, clear the GPGRT_CONFIG variable.
      unset GPGRT_CONFIG
    fi
  else
    # GPGRT_CONFIG found but no suitable dir for --libdir found.
    # This is a failure.  Clear the GPGRT_CONFIG variable.
    unset GPGRT_CONFIG
  fi
])

dnl AM_PATH_KSBA([MINIMUM-VERSION,
dnl              [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libksba and define KSBA_CFLAGS and KSBA_LIBS
dnl MINIMUM-VERSION is a string with the version number optionally prefixed
dnl with the API version to also check the API compatibility. Example:
dnl a MINIMUM-VERSION of 1:1.0.7 won't pass the test unless the installed
dnl version of libksba is at least 1.0.7 *and* the API number is 1.  Using
dnl this features allows to prevent build against newer versions of libksba
dnl with a changed API.
dnl
AC_DEFUN([AM_PATH_KSBA],
[ AC_REQUIRE([AC_CANONICAL_HOST])dnl
  AC_REQUIRE([_AM_PATH_GPGRT_CONFIG])dnl
  dnl --with-libksba-prefix=PFX is the preferred name for this option,
  dnl since that is consistent with how our three siblings use the directory/
  dnl package name in --with-$dir_name-prefix=PFX.
  AC_ARG_WITH(libksba-prefix,
              AS_HELP_STRING([--with-libksba-prefix=PFX],
                             [prefix where KSBA is installed (optional)]),
     ksba_config_prefix="$withval", ksba_config_prefix="")

  dnl Accept --with-ksba-prefix and make it work the same as
  dnl --with-libksba-prefix above, for backwards compatibility,
  dnl but do not document this old, inconsistently-named option.
  AC_ARG_WITH(ksba-prefix,,
     ksba_config_prefix="$withval", ksba_config_prefix="")

  if test x$ksba_config_prefix != x ; then
    if test x${KSBA_CONFIG+set} != xset ; then
      KSBA_CONFIG=$ksba_config_prefix/bin/ksba-config
    fi
  fi

  use_gpgrt_config=""
  if test x"$GPGRT_CONFIG" != x -a "$GPGRT_CONFIG" != "no"; then
    if $GPGRT_CONFIG ksba --exists; then
      KSBA_CONFIG="$GPGRT_CONFIG ksba"
      AC_MSG_NOTICE([Use gpgrt-config as ksba-config])
      use_gpgrt_config=yes
    fi
  fi
  if test -z "$use_gpgrt_config"; then
    AC_PATH_PROG(KSBA_CONFIG, ksba-config, no)
  fi

  tmp=ifelse([$1], ,1:1.0.0,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_ksba_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_ksba_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_ksba_api=0
     min_ksba_version="$tmp"
  fi

  AC_MSG_CHECKING(for KSBA - version >= $min_ksba_version)
  ok=no
  if test "$KSBA_CONFIG" != "no" ; then
    req_major=`echo $min_ksba_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_ksba_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_ksba_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    if test -z "$use_gpgrt_config"; then
      ksba_config_version=`$KSBA_CONFIG --version`
    else
      ksba_config_version=`$KSBA_CONFIG --modversion`
    fi
    major=`echo $ksba_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $ksba_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $ksba_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else
        if test "$major" -eq "$req_major"; then
            if test "$minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$minor" -eq "$req_minor"; then
                   if test "$micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    AC_MSG_RESULT([yes ($ksba_config_version)])
  else
    AC_MSG_RESULT(no)
  fi
  if test $ok = yes; then
     # Even if we have a recent libksba, we should check that the
     # API is compatible.
     if test "$req_ksba_api" -gt 0 ; then
        if test -z "$use_gpgrt_config"; then
          tmp=`$KSBA_CONFIG --api-version 2>/dev/null || echo 0`
	else
          tmp=`$KSBA_CONFIG --variable=api_version 2>/dev/null || echo 0`
	fi
        if test "$tmp" -gt 0 ; then
           AC_MSG_CHECKING([KSBA API version])
           if test "$req_ksba_api" -eq "$tmp" ; then
             AC_MSG_RESULT(okay)
           else
             ok=no
             AC_MSG_RESULT([does not match.  want=$req_ksba_api got=$tmp.])
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    KSBA_CFLAGS=`$KSBA_CONFIG --cflags`
    KSBA_LIBS=`$KSBA_CONFIG --libs`
    ifelse([$2], , :, [$2])
    if test -z "$use_gpgrt_config"; then
      libksba_config_host=`$KSBA_CONFIG --host 2>/dev/null || echo none`
    else
      libksba_config_host=`$KSBA_CONFIG --variable=host 2>/dev/null || echo none`
    fi
    if test x"$libksba_config_host" != xnone ; then
      if test x"$libksba_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script "$KSBA_CONFIG" was
*** built for $libksba_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-libksba-prefix
*** to specify a matching config script.
***]])
      fi
    fi
  else
    KSBA_CFLAGS=""
    KSBA_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(KSBA_CFLAGS)
  AC_SUBST(KSBA_LIBS)
])
