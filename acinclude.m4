dnl macros to configure gnupg
dnl Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
dnl
dnl This file is part of GnuPG.
dnl
dnl GnuPG is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl GnuPG is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, see <https://www.gnu.org/licenses/>.

dnl GNUPG_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN([GNUPG_CHECK_TYPEDEF],
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(gnupg_cv_typedef_$1,
    [AC_TRY_COMPILE([#define _GNU_SOURCE 1
    #include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], gnupg_cv_typedef_$1=yes, gnupg_cv_typedef_$1=no )])
    AC_MSG_RESULT($gnupg_cv_typedef_$1)
    if test "$gnupg_cv_typedef_$1" = yes; then
        AC_DEFINE($2,1,[Defined if a `]$1[' is typedef'd])
    fi
  ])


dnl GNUPG_CHECK_GNUMAKE
dnl
AC_DEFUN([GNUPG_CHECK_GNUMAKE],
  [
    if ${MAKE-make} --version 2>/dev/null | grep '^GNU ' >/dev/null 2>&1; then
        :
    else
        AC_MSG_WARN([[
***
*** It seems that you are not using GNU make.  Some make tools have serious
*** flaws and you may not be able to build this software at all. Before you
*** complain, please try GNU make:  GNU make is easy to build and available
*** at all GNU archives.  It is always available from ftp.gnu.org:/gnu/make.
***]])
    fi
  ])


# GNUPG_BUILD_PROGRAM(NAME,DEFAULT)
# Add a --enable-NAME option to configure an set the
# shell variable build_NAME either to "yes" or "no".  DEFAULT must
# either be "yes" or "no" and decided on the default value for
# build_NAME and whether --enable-NAME or --disable-NAME is shown with
# ./configure --help
AC_DEFUN([GNUPG_BUILD_PROGRAM],
  [m4_define([my_build], [m4_bpatsubst(build_$1, [[^a-zA-Z0-9_]], [_])])
   my_build=$2
   m4_if([$2],[yes],[
      AC_ARG_ENABLE([$1], AS_HELP_STRING([--disable-$1],
                                         [do not build the $1 program]),
                           my_build=$enableval, my_build=$2)
    ],[
      AC_ARG_ENABLE([$1], AS_HELP_STRING([--enable-$1],
                                         [build the $1 program]),
                           my_build=$enableval, my_build=$2)
    ])
   case "$my_build" in
         no|yes)
           ;;
         *)
           AC_MSG_ERROR([only yes or no allowed for feature --enable-$1])
           ;;
   esac
   m4_undefine([my_build])
  ])



# GNUPG_DISABLE_GPG_ALGO(NAME,DESCRIPTION)
#
# Add a --disable-gpg-NAME option and the corresponding ac_define
# GPG_USE_<NAME>.
AC_DEFUN([GNUPG_GPG_DISABLE_ALGO],
  [AC_MSG_CHECKING([whether to enable the $2 for gpg])
   AC_ARG_ENABLE([gpg-$1], AS_HELP_STRING([--disable-gpg-$1],
                                          [disable the $2 algorithm in gpg]),
                                          , enableval=yes)
   AC_MSG_RESULT($enableval)
   if test x"$enableval" = xyes ; then
     AC_DEFINE(GPG_USE_[]m4_toupper($1), 1, [Define to support the $2])
   fi
  ])

# GNUPG_TIME_T_UNSIGNED
# Check whether time_t is unsigned
#
AC_DEFUN([GNUPG_TIME_T_UNSIGNED],
  [ AC_CACHE_CHECK(whether time_t is unsigned, gnupg_cv_time_t_unsigned,
     [AC_COMPILE_IFELSE([AC_LANG_BOOL_COMPILE_TRY(
       [AC_INCLUDES_DEFAULT([])
#if HAVE_SYS_TIME_H
# include <sys/time.h>
#else
# include <time.h>
#endif
],
       [((time_t)-1) < 0])],
       gnupg_cv_time_t_unsigned=no, gnupg_cv_time_t_unsigned=yes)])
    if test $gnupg_cv_time_t_unsigned = yes; then
      AC_DEFINE(HAVE_UNSIGNED_TIME_T,1,[Defined if time_t is an unsigned type])
    fi
])# GNUPG_TIME_T_UNSIGNED
