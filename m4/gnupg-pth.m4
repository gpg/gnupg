dnl GnuPG's check for Pth.
dnl       Copyright (C) 2003 Free Software Foundation, Inc.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


# GNUPG_PTH_VERSION_CHECK(REQUIRED)
# 
# If the version is sufficient, HAVE_PTH will be set to yes.
#
# Taken and modified from the m4 macros which come with Pth.
AC_DEFUN([GNUPG_PTH_VERSION_CHECK],
  [
    _pth_version=`$PTH_CONFIG --version | awk 'NR==1 {print [$]3}'`
    _req_version="ifelse([$1],,1.2.0,$1)"

    AC_MSG_CHECKING(for PTH - version >= $_req_version)
    for _var in _pth_version _req_version; do
        eval "_val=\"\$${_var}\""
        _major=`echo $_val | sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\([[ab.]]\)\([[0-9]]*\)/\1/'`
        _minor=`echo $_val | sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\([[ab.]]\)\([[0-9]]*\)/\2/'`
        _rtype=`echo $_val | sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\([[ab.]]\)\([[0-9]]*\)/\3/'`
        _micro=`echo $_val | sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\([[ab.]]\)\([[0-9]]*\)/\4/'`
        case $_rtype in
            "a" ) _rtype=0 ;;
            "b" ) _rtype=1 ;;
            "." ) _rtype=2 ;;
        esac
        _hex=`echo dummy | awk '{ printf("%d%02d%1d%02d", major, minor, rtype, micro); }' \
              "major=$_major" "minor=$_minor" "rtype=$_rtype" "micro=$_micro"`
        eval "${_var}_hex=\"\$_hex\""
    done
    have_pth=no
    if test ".$_pth_version_hex" != .; then
        if test ".$_req_version_hex" != .; then
            if test $_pth_version_hex -ge $_req_version_hex; then
                have_pth=yes
            fi
        fi
    fi
    if test $have_pth = yes; then
       AC_MSG_RESULT(yes)
       AC_MSG_CHECKING([whether PTH installation is sane])
       AC_CACHE_VAL(gnupg_cv_pth_is_sane,[
         _gnupg_pth_save_cflags=$CFLAGS
         _gnupg_pth_save_ldflags=$LDFLAGS
         _gnupg_pth_save_libs=$LIBS
         CFLAGS="$CFLAGS `$PTH_CONFIG --cflags`"
         LDFLAGS="$LDFLAGS `$PTH_CONFIG --ldflags`"
         LIBS="$LIBS `$PTH_CONFIG --libs --all`"
         AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <pth.h>
                                         ],
                                         [[ pth_init ();]])],
                        gnupg_cv_pth_is_sane=yes,
                        gnupg_cv_pth_is_sane=no)
         CFLAGS=$_gnupg_pth_save_cflags
         LDFLAGS=$_gnupg_pth_save_ldflags
         LIBS=$_gnupg_pth_save_libs
       ])
       if test $gnupg_cv_pth_is_sane != yes; then
          have_pth=no
       fi
       AC_MSG_RESULT($gnupg_cv_pth_is_sane)
    else
       AC_MSG_RESULT(no)
    fi    
  ])



# GNUPG_PATH_PTH([MINIMUM_VERSION])
#
# On return $have_pth is set as well as HAVE_PTH is defined and
# PTH_CLFAGS and PTH_LIBS are AS_SUBST.
#
AC_DEFUN([GNUPG_PATH_PTH],
[ AC_ARG_WITH(pth-prefix,
             AC_HELP_STRING([--with-pth-prefix=PFX],
                           [prefix where GNU Pth is installed (optional)]),
     pth_config_prefix="$withval", pth_config_prefix="")
  if test x$pth_config_prefix != x ; then
     PTH_CONFIG="$pth_config_prefix/bin/pth-config"
  fi
  AC_PATH_PROG(PTH_CONFIG, pth-config, no)
  tmp=ifelse([$1], ,1.3.7,$1)
  if test "$PTH_CONFIG" != "no"; then
    GNUPG_PTH_VERSION_CHECK($tmp)
    if test $have_pth = yes; then      
       PTH_CFLAGS=`$PTH_CONFIG --cflags`
       PTH_LIBS=`$PTH_CONFIG --ldflags`
       PTH_LIBS="$PTH_LIBS `$PTH_CONFIG --libs --all`"
       AC_DEFINE(HAVE_PTH, 1,
                [Defined if the GNU Pth is available])
    fi
  fi
  AC_SUBST(PTH_CFLAGS)
  AC_SUBST(PTH_LIBS)
])

