dnl Autoconf macros for NTBTLS
dnl Copyright (C) 2002, 2004, 2011 Free Software Foundation, Inc.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


dnl AM_PATH_NTBTLS([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl
dnl Test for NTBTLS and define NTBTLS_CFLAGS and NTBTLS_LIBS.
dnl MINIMUM-VERSION is a string with the version number optionalliy prefixed
dnl with the API version to also check the API compatibility. Example:
dnl a MINIMUM-VERSION of 1:1.2.5 won't pass the test unless the installed
dnl version of ntbtls is at least 1.2.5 *and* the API number is 1.  Using
dnl this feature prevents building against newer versions of ntbtls
dnl with a changed API.
dnl
AC_DEFUN([AM_PATH_NTBTLS],
[ AC_REQUIRE([AC_CANONICAL_HOST])
  AC_ARG_WITH(ntbtls-prefix,
            AC_HELP_STRING([--with-ntbtls-prefix=PFX],
                           [prefix where NTBTLS is installed (optional)]),
     ntbtls_config_prefix="$withval", ntbtls_config_prefix="")
  if test x"${NTBTLS_CONFIG}" = x ; then
     if test x"${ntbtls_config_prefix}" != x ; then
        NTBTLS_CONFIG="${ntbtls_config_prefix}/bin/ntbtls-config"
     else
       case "${SYSROOT}" in
         /*)
           if test -x "${SYSROOT}/bin/ntbtls-config" ; then
             NTBTLS_CONFIG="${SYSROOT}/bin/ntbtls-config"
           fi
           ;;
         '')
           ;;
          *)
           AC_MSG_WARN([Ignoring \$SYSROOT as it is not an absolute path.])
           ;;
       esac
     fi
  fi

  AC_PATH_PROG(NTBTLS_CONFIG, ntbtls-config, no)
  tmp=ifelse([$1], ,1:1.0.0,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_ntbtls_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_ntbtls_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_ntbtls_api=0
     min_ntbtls_version="$tmp"
  fi

  AC_MSG_CHECKING(for NTBTLS - version >= $min_ntbtls_version)
  ok=no
  if test "$NTBTLS_CONFIG" != "no" ; then
    req_major=`echo $min_ntbtls_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_ntbtls_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_ntbtls_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    ntbtls_config_version=`$NTBTLS_CONFIG --version`
    major=`echo $ntbtls_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $ntbtls_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $ntbtls_config_version | \
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
    AC_MSG_RESULT([yes ($ntbtls_config_version)])
  else
    AC_MSG_RESULT(no)
  fi
  if test $ok = yes; then
     # If we have a recent ntbtls, we should also check that the
     # API is compatible
     if test "$req_ntbtls_api" -gt 0 ; then
        tmp=`$NTBTLS_CONFIG --api-version 2>/dev/null || echo 0`
        if test "$tmp" -gt 0 ; then
           AC_MSG_CHECKING([NTBTLS API version])
           if test "$req_ntbtls_api" -eq "$tmp" ; then
             AC_MSG_RESULT([okay])
           else
             ok=no
             AC_MSG_RESULT([does not match. want=$req_ntbtls_api got=$tmp])
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    NTBTLS_CFLAGS=`$NTBTLS_CONFIG --cflags`
    NTBTLS_LIBS=`$NTBTLS_CONFIG --libs`
    ifelse([$2], , :, [$2])
    ntbtls_config_host=`$NTBTLS_CONFIG --host 2>/dev/null || echo none`
    if test x"$ntbtls_config_host" != xnone ; then
      if test x"$ntbtls_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script $NTBTLS_CONFIG was
*** built for $ntbtls_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-ntbtls-prefix
*** to specify a matching config script or use \$SYSROOT.
***]])
        gpg_config_script_warn="$gpg_config_script_warn ntbtls"
      fi
    fi
  else
    NTBTLS_CFLAGS=""
    NTBTLS_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(NTBTLS_CFLAGS)
  AC_SUBST(NTBTLS_LIBS)
])
