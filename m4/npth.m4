# npth.m4 - autoconf macro to detect NPTH.
# Copyright (C) 2002, 2003, 2004, 2011 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_DEFUN([_AM_PATH_NPTH_CONFIG],
[ AC_ARG_WITH(npth-prefix,
            AC_HELP_STRING([--with-npth-prefix=PFX],
                           [prefix where NPTH is installed (optional)]),
     npth_config_prefix="$withval", npth_config_prefix="")
  if test "x$npth_config_prefix" != x ; then
      NPTH_CONFIG="$npth_config_prefix/bin/npth-config"
  fi
  AC_PATH_PROG(NPTH_CONFIG, npth-config, no)

  if test "$NPTH_CONFIG" != "no" ; then
    npth_version=`$NPTH_CONFIG --version`
  fi
  npth_version_major=`echo $npth_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  npth_version_minor=`echo $npth_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  npth_version_micro=`echo $npth_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
])

dnl AM_PATH_NPTH([MINIMUM-VERSION,
dnl               [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libnpth and define NPTH_CFLAGS and NPTH_LIBS.
dnl
AC_DEFUN([AM_PATH_NPTH],
[ AC_REQUIRE([_AM_PATH_NPTH_CONFIG])dnl
  tmp=ifelse([$1], ,1:0.0.1,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_npth_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_npth_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_npth_api=0
     min_npth_version="$tmp"
  fi

  AC_MSG_CHECKING(for NPTH - version >= $min_npth_version)
  ok=no
  if test "$NPTH_CONFIG" != "no" ; then
    req_major=`echo $min_npth_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_npth_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_npth_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    if test "$npth_version_major" -gt "$req_major"; then
        ok=yes
    else
        if test "$npth_version_major" -eq "$req_major"; then
            if test "$npth_version_minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$npth_version_minor" -eq "$req_minor"; then
                   if test "$npth_version_micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
     # If we have a recent NPTH, we should also check that the
     # API is compatible.
     if test "$req_npth_api" -gt 0 ; then
        tmp=`$NPTH_CONFIG --api-version 2>/dev/null || echo 0`
        if test "$tmp" -gt 0 ; then
           if test "$req_npth_api" -ne "$tmp" ; then
             ok=no
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    NPTH_CFLAGS=`$NPTH_CONFIG --cflags`
    NPTH_LIBS=`$NPTH_CONFIG --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    NPTH_CFLAGS=""
    NPTH_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(NPTH_CFLAGS)
  AC_SUBST(NPTH_LIBS)
])
