dnl Autoconf macros for libassuan
dnl Copyright (C) 2002, 2003, 2011 Free Software Foundation, Inc.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
dnl SPDX-License-Identifier: FSFULLR
# Last-changed: 2024-07-11

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

dnl
dnl Common code used for libassuan detection [internal]
dnl Returns ok set to yes or no.
dnl
AC_DEFUN([_AM_PATH_LIBASSUAN_COMMON],
[ AC_REQUIRE([AC_CANONICAL_HOST])dnl
  AC_REQUIRE([_AM_PATH_GPGRT_CONFIG])dnl
  AC_ARG_WITH(libassuan-prefix,
              AS_HELP_STRING([--with-libassuan-prefix=PFX],
                             [prefix where LIBASSUAN is installed (optional)]),
     libassuan_config_prefix="$withval", libassuan_config_prefix="")
  if test x$libassuan_config_prefix != x ; then
    if test x${LIBASSUAN_CONFIG+set} != xset ; then
      LIBASSUAN_CONFIG=$libassuan_config_prefix/bin/libassuan-config
    fi
  fi

  use_gpgrt_config=""
  if test x"$GPGRT_CONFIG" != x -a "$GPGRT_CONFIG" != "no"; then
    if $GPGRT_CONFIG libassuan --exists; then
      LIBASSUAN_CONFIG="$GPGRT_CONFIG libassuan"
      AC_MSG_NOTICE([Use gpgrt-config as libassuan-config])
      use_gpgrt_config=yes
    fi
  fi
  if test -z "$use_gpgrt_config"; then
    AC_PATH_PROG(LIBASSUAN_CONFIG, libassuan-config, no)
  fi

  tmp=ifelse([$1], ,1:0.9.2,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
    req_libassuan_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
    min_libassuan_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
    req_libassuan_api=0
    min_libassuan_version="$tmp"
  fi

  AC_MSG_CHECKING(for LIBASSUAN - version >= $min_libassuan_version)
  ok=no
  if test "$LIBASSUAN_CONFIG" != "no"; then
    req_major=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`

    if test -z "$use_gpgrt_config"; then
      libassuan_config_version=`$LIBASSUAN_CONFIG --version`
    else
      libassuan_config_version=`$LIBASSUAN_CONFIG --modversion`
    fi
    major=`echo $libassuan_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libassuan_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libassuan_config_version | \
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
    AC_MSG_RESULT([yes ($libassuan_config_version)])
    AC_DEFINE_UNQUOTED(LIBASSUAN_API_REQUESTED, $req_libassuan_api, [Requested API version for libassuan])
  else
    AC_MSG_RESULT(no)
  fi

  if test $ok = yes; then
    if test "$req_libassuan_api" -gt 0 ; then
      if test -z "$use_gpgrt_config"; then
        tmp=`$LIBASSUAN_CONFIG --api-version 2>/dev/null || echo 0`
      else
        tmp=`$LIBASSUAN_CONFIG --variable=api_version 2>/dev/null || echo 0`
      fi
      if test "$tmp" -gt 0 ; then
        AC_MSG_CHECKING([LIBASSUAN API version])
        if test "$req_libassuan_api" -eq "$tmp" ; then
          AC_MSG_RESULT(okay)
        elif test "$req_libassuan_api" -eq 2 -a "$tmp" -eq 3; then
          AC_MSG_RESULT(okay)
        else
          ok=no
          AC_MSG_RESULT([does not match.  want=$req_libassuan_api got=$tmp.])
        fi
      fi
    fi
  fi

  if test $ok = yes; then
    if test x"$host" != x ; then
      if test -z "$use_gpgrt_config"; then
        libassuan_config_host=`$LIBASSUAN_CONFIG --host 2>/dev/null || echo none`
      else
        libassuan_config_host=`$LIBASSUAN_CONFIG --variable=host 2>/dev/null || echo none`
      fi
      if test x"$libassuan_config_host" != xnone ; then
        if test x"$libassuan_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script "$LIBASSUAN_CONFIG" was
*** built for $libassuan_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-libassuan-prefix
*** to specify a matching config script.
***]])
        fi
      fi
    fi
  fi
])

dnl AM_CHECK_LIBASSUAN([MINIMUM-VERSION,
dnl                    [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test whether libassuan has at least MINIMUM-VERSION. This is
dnl used to test for features only available in newer versions.
dnl
AC_DEFUN([AM_CHECK_LIBASSUAN],
[ _AM_PATH_LIBASSUAN_COMMON($1)
  if test $ok = yes; then
    ifelse([$2], , :, [$2])
  else
    ifelse([$3], , :, [$3])
  fi
])




dnl AM_PATH_LIBASSUAN([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libassuan and define LIBASSUAN_CFLAGS and LIBASSUAN_LIBS
dnl
AC_DEFUN([AM_PATH_LIBASSUAN],
[ _AM_PATH_LIBASSUAN_COMMON($1)
  if test $ok = yes; then
    LIBASSUAN_CFLAGS=`$LIBASSUAN_CONFIG --cflags`
    LIBASSUAN_LIBS=`$LIBASSUAN_CONFIG --libs`
    ifelse([$2], , :, [$2])
  else
    LIBASSUAN_CFLAGS=""
    LIBASSUAN_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBASSUAN_CFLAGS)
  AC_SUBST(LIBASSUAN_LIBS)
])
