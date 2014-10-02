# gpg-error.m4 - autoconf macro to detect libgpg-error.
# Copyright (C) 2002, 2003, 2004, 2011, 2014 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Last-changed: 2014-10-02


dnl AM_PATH_GPG_ERROR([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl
dnl Test for libgpg-error and define GPG_ERROR_CFLAGS, GPG_ERROR_LIBS,
dnl GPG_ERROR_MT_CFLAGS, and GPG_ERROR_MT_LIBS.  The _MT_ variants are
dnl used for programs requireing real multi thread support.
dnl
dnl If a prefix option is not used, the config script is first
dnl searched in $SYSROOT/bin and then along $PATH.  If the used
dnl config script does not match the host specification the script
dnl is added to the gpg_config_script_warn variable.
dnl
AC_DEFUN([AM_PATH_GPG_ERROR],
[ AC_REQUIRE([AC_CANONICAL_HOST])
  gpg_error_config_prefix=""
  dnl --with-libgpg-error-prefix=PFX is the preferred name for this option,
  dnl since that is consistent with how our three siblings use the directory/
  dnl package name in --with-$dir_name-prefix=PFX.
  AC_ARG_WITH(libgpg-error-prefix,
              AC_HELP_STRING([--with-libgpg-error-prefix=PFX],
                             [prefix where GPG Error is installed (optional)]),
              [gpg_error_config_prefix="$withval"])

  dnl Accept --with-gpg-error-prefix and make it work the same as
  dnl --with-libgpg-error-prefix above, for backwards compatibility,
  dnl but do not document this old, inconsistently-named option.
  AC_ARG_WITH(gpg-error-prefix,,
              [gpg_error_config_prefix="$withval"])

  if test x"${GPG_ERROR_CONFIG}" = x ; then
     if test x"${gpg_error_config_prefix}" != x ; then
        GPG_ERROR_CONFIG="${gpg_error_config_prefix}/bin/gpg-error-config"
     else
       case "${SYSROOT}" in
         /*)
           if test -x "${SYSROOT}/bin/gpg-error-config" ; then
             GPG_ERROR_CONFIG="${SYSROOT}/bin/gpg-error-config"
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

  AC_PATH_PROG(GPG_ERROR_CONFIG, gpg-error-config, no)
  min_gpg_error_version=ifelse([$1], ,0.0,$1)
  AC_MSG_CHECKING(for GPG Error - version >= $min_gpg_error_version)
  ok=no
  if test "$GPG_ERROR_CONFIG" != "no" \
     && test -f "$GPG_ERROR_CONFIG" ; then
    req_major=`echo $min_gpg_error_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_gpg_error_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    gpg_error_config_version=`$GPG_ERROR_CONFIG $gpg_error_config_args --version`
    major=`echo $gpg_error_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $gpg_error_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else
        if test "$major" -eq "$req_major"; then
            if test "$minor" -ge "$req_minor"; then
               ok=yes
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    GPG_ERROR_CFLAGS=`$GPG_ERROR_CONFIG $gpg_error_config_args --cflags`
    GPG_ERROR_LIBS=`$GPG_ERROR_CONFIG $gpg_error_config_args --libs`
    GPG_ERROR_MT_CFLAGS=`$GPG_ERROR_CONFIG $gpg_error_config_args --mt --cflags 2>/dev/null`
    GPG_ERROR_MT_LIBS=`$GPG_ERROR_CONFIG $gpg_error_config_args --mt --libs 2>/dev/null`
    AC_MSG_RESULT([yes ($gpg_error_config_version)])
    ifelse([$2], , :, [$2])
    gpg_error_config_host=`$GPG_ERROR_CONFIG $gpg_error_config_args --host 2>/dev/null || echo none`
    if test x"$gpg_error_config_host" != xnone ; then
      if test x"$gpg_error_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script $GPG_ERROR_CONFIG was
*** built for $gpg_error_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-gpg-error-prefix
*** to specify a matching config script or use \$SYSROOT.
***]])
        gpg_config_script_warn="$gpg_config_script_warn libgpg-error"
      fi
    fi
  else
    GPG_ERROR_CFLAGS=""
    GPG_ERROR_LIBS=""
    GPG_ERROR_MT_CFLAGS=""
    GPG_ERROR_MT_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPG_ERROR_CFLAGS)
  AC_SUBST(GPG_ERROR_LIBS)
  AC_SUBST(GPG_ERROR_MT_CFLAGS)
  AC_SUBST(GPG_ERROR_MT_LIBS)
])
