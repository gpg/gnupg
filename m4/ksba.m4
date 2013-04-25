# ksba.m4 - autoconf macro to detect ksba
#       Copyright (C) 2002 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


dnl AM_PATH_KSBA([MINIMUM-VERSION,
dnl              [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libksba and define KSBA_CFLAGS and KSBA_LIBS
dnl MINIMUN-VERSION is a string with the version number optionalliy prefixed
dnl with the API version to also check the API compatibility. Example:
dnl a MINIMUN-VERSION of 1:1.0.7 won't pass the test unless the installed
dnl version of libksba is at least 1.0.7 *and* the API number is 1.  Using
dnl this features allows to prevent build against newer versions of libksba
dnl with a changed API.
dnl
AC_DEFUN([AM_PATH_KSBA],
[AC_REQUIRE([AC_CANONICAL_HOST])
 AC_ARG_WITH(ksba-prefix,
            AC_HELP_STRING([--with-ksba-prefix=PFX],
                           [prefix where KSBA is installed (optional)]),
     ksba_config_prefix="$withval", ksba_config_prefix="")
  if test x$ksba_config_prefix != x ; then
     ksba_config_args="$ksba_config_args --prefix=$ksba_config_prefix"
     if test x${KSBA_CONFIG+set} != xset ; then
        KSBA_CONFIG=$ksba_config_prefix/bin/ksba-config
     fi
  fi

  AC_PATH_PROG(KSBA_CONFIG, ksba-config, no)
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
    ksba_config_version=`$KSBA_CONFIG $ksba_config_args --version`
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
        tmp=`$KSBA_CONFIG --api-version 2>/dev/null || echo 0`
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
    KSBA_CFLAGS=`$KSBA_CONFIG $ksba_config_args --cflags`
    KSBA_LIBS=`$KSBA_CONFIG $ksba_config_args --libs`
    ifelse([$2], , :, [$2])
    libksba_config_host=`$LIBKSBA_CONFIG $ksba_config_args --host 2>/dev/null || echo none`
    if test x"$libksba_config_host" != xnone ; then
      if test x"$libksba_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script $LIBKSBA_CONFIG was
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
