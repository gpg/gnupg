dnl macros to configure gnupg
dnl Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
dnl
dnl This file is part of GnuPG.
dnl
dnl GnuPG is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl 
dnl GnuPG is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

dnl GNUPG_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN(GNUPG_CHECK_TYPEDEF,
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


# Check for the getsockopt SO_PEERCRED
AC_DEFUN(GNUPG_SYS_SO_PEERCRED,
  [ AC_MSG_CHECKING(for SO_PEERCRED)
    AC_CACHE_VAL(gnupg_cv_sys_so_peercred,
      [AC_TRY_COMPILE([#include <sys/socket.h>], 
                    [struct ucred cr; 
                     int cl = sizeof cr;
                     getsockopt (1, SOL_SOCKET, SO_PEERCRED, &cr, &cl);],
                    gnupg_cv_sys_so_peercred=yes,
                    gnupg_cv_sys_so_peercred=no)
      ])
    AC_MSG_RESULT($gnupg_cv_sys_so_peercred) 
    if test $gnupg_cv_sys_so_peercred = yes; then
         AC_DEFINE(HAVE_SO_PEERCRED, 1,
                            [Defined if SO_PEERCRED is supported (Linux)])
    fi
  ])



# GNUPG_BUILD_PROGRAM(NAME,DEFAULT)
# Add a --enable-NAME option to configure an set the
# shell variable build_NAME either to "yes" or "no".  DEFAULT must
# either be "yes" or "no" and decided on the default value for
# build_NAME and whether --enable-NAME or --disable-NAME is shown with 
# ./configure --help
AC_DEFUN(GNUPG_BUILD_PROGRAM,
  [build_$1=$2
   m4_if([$2],[yes],[
      AC_ARG_ENABLE([$1], AC_HELP_STRING([--disable-$1],
                                         [do not build the $1 program]),
                           build_$1=$enableval, build_$1=$2)
    ],[
      AC_ARG_ENABLE([$1], AC_HELP_STRING([--enable-$1],
                                         [build the $1 program]),
                           build_$1=$enableval, build_$1=$2)
    ])
   case "$build_$1" in
         no|yes)
           ;;
         *) 
           AC_MSG_ERROR([only yes or no allowed for feature --enable-$1])
           ;;
   esac
  ])



# GNUPG_PTH_VERSION_CHECK(REQUIRED)
# 
# If the version is sufficient, HAVE_PTH will be set to yes.
#
# Taken form the m4 macros which come with Pth
AC_DEFUN(GNUPG_PTH_VERSION_CHECK,
  [
    _pth_version=`$PTH_CONFIG --version | awk 'NR==1 {print [$]3}'`
    _req_version="ifelse([$1],,1.2.0,$1)"
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
    if test $have_pth = no; then
       AC_MSG_WARN([[
***
*** Found Pth version $_pth_version, but require at least
*** version $_req_version.  Please upgrade Pth first.
***]])
    fi    
  ])

######################################################################
# Check whether mlock is broken (hpux 10.20 raises a SIGBUS if mlock
# is not called from uid 0 (not tested whether uid 0 works)
# For DECs Tru64 we have also to check whether mlock is in librt
# mlock is there a macro using memlk()
######################################################################
dnl GNUPG_CHECK_MLOCK
dnl
define(GNUPG_CHECK_MLOCK,
  [ AC_CHECK_FUNCS(mlock)
    if test "$ac_cv_func_mlock" = "no"; then
        AC_CHECK_HEADERS(sys/mman.h)
        if test "$ac_cv_header_sys_mman_h" = "yes"; then
            # Add librt to LIBS:
            AC_CHECK_LIB(rt, memlk)
            AC_CACHE_CHECK([whether mlock is in sys/mman.h],
                            gnupg_cv_mlock_is_in_sys_mman,
                [AC_TRY_LINK([
                    #include <assert.h>
                    #ifdef HAVE_SYS_MMAN_H
                    #include <sys/mman.h>
                    #endif
                ], [
                    int i;

                    /* glibc defines this for functions which it implements
                     * to always fail with ENOSYS.  Some functions are actually
                     * named something starting with __ and the normal name
                     * is an alias.  */
                    #if defined (__stub_mlock) || defined (__stub___mlock)
                    choke me
                    #else
                    mlock(&i, 4);
                    #endif
                    ; return 0;
                ],
                gnupg_cv_mlock_is_in_sys_mman=yes,
                gnupg_cv_mlock_is_in_sys_mman=no)])
            if test "$gnupg_cv_mlock_is_in_sys_mman" = "yes"; then
                AC_DEFINE(HAVE_MLOCK,1,
                          [Defined if the system supports an mlock() call])
            fi
        fi
    fi
    if test "$ac_cv_func_mlock" = "yes"; then
        AC_MSG_CHECKING(whether mlock is broken)
          AC_CACHE_VAL(gnupg_cv_have_broken_mlock,
             AC_TRY_RUN([
                #include <stdlib.h>
                #include <unistd.h>
                #include <errno.h>
                #include <sys/mman.h>
                #include <sys/types.h>
                #include <fcntl.h>

                int main()
                {
                    char *pool;
                    int err;
                    long int pgsize = getpagesize();

                    pool = malloc( 4096 + pgsize );
                    if( !pool )
                        return 2;
                    pool += (pgsize - ((long int)pool % pgsize));

                    err = mlock( pool, 4096 );
                    if( !err || errno == EPERM )
                        return 0; /* okay */

                    return 1;  /* hmmm */
                }

            ],
            gnupg_cv_have_broken_mlock="no",
            gnupg_cv_have_broken_mlock="yes",
            gnupg_cv_have_broken_mlock="assume-no"
           )
         )
         if test "$gnupg_cv_have_broken_mlock" = "yes"; then
             AC_DEFINE(HAVE_BROKEN_MLOCK,1,
                       [Defined if the mlock() call does not work])
             AC_MSG_RESULT(yes)
             AC_CHECK_FUNCS(plock)
         else
            if test "$gnupg_cv_have_broken_mlock" = "no"; then
                AC_MSG_RESULT(no)
            else
                AC_MSG_RESULT(assuming no)
            fi
         fi
    fi
  ])



dnl [copied from libgcrypt]
dnl AM_PATH_LIBGCRYPT([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for liblibgcrypt and define LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS
dnl
AC_DEFUN(AM_PATH_LIBGCRYPT,
[ AC_ARG_WITH(libgcrypt-prefix,
            AC_HELP_STRING([--with-libgcrypt-prefix=PFX],
                           [prefix where LIBGCRYPT is installed (optional)]),
     libgcrypt_config_prefix="$withval", libgcrypt_config_prefix="")
  if test x$libgcrypt_config_prefix != x ; then
     libgcrypt_config_args="$libgcrypt_config_args --prefix=$libgcrypt_config_prefix"
     if test x${LIBGCRYPT_CONFIG+set} != xset ; then
        LIBGCRYPT_CONFIG=$libgcrypt_config_prefix/bin/libgcrypt-config
     fi
  fi

  AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config, no)
  min_libgcrypt_version=ifelse([$1], ,0.4.4,$1)
  AC_MSG_CHECKING(for LIBGCRYPT - version >= $min_libgcrypt_version)
  ok=no
  if test "$LIBGCRYPT_CONFIG" != "no" ; then
    req_major=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    libgcrypt_config_version=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --version`
    major=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libgcrypt_config_version | \
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
    LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --cflags`
    LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    LIBGCRYPT_CFLAGS=""
    LIBGCRYPT_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBGCRYPT_CFLAGS)
  AC_SUBST(LIBGCRYPT_LIBS)
])

dnl [copied from libassuan 0.0.1]
dnl AM_PATH_LIBASSUAN([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libassuan and define LIBASSUAN_CFLAGS and LIBASSUAN_LIBS
dnl
AC_DEFUN(AM_PATH_LIBASSUAN,
[ AC_ARG_WITH(libassuan-prefix,
            AC_HELP_STRING([--with-libassuan-prefix=PFX],
                           [prefix where LIBASSUAN is installed (optional)]),
     libassuan_config_prefix="$withval", libassuan_config_prefix="")
  if test x$libassuan_config_prefix != x ; then
     libassuan_config_args="$libassuan_config_args --prefix=$libassuan_config_prefix"
     if test x${LIBASSUAN_CONFIG+set} != xset ; then
        LIBASSUAN_CONFIG=$libassuan_config_prefix/bin/libassuan-config
     fi
  fi

  AC_PATH_PROG(LIBASSUAN_CONFIG, libassuan-config, no)
  min_libassuan_version=ifelse([$1], ,0.0.1,$1)
  AC_MSG_CHECKING(for LIBASSUAN - version >= $min_libassuan_version)
  ok=no
  if test "$LIBASSUAN_CONFIG" != "no" ; then
    req_major=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    libassuan_config_version=`$LIBASSUAN_CONFIG $libassuan_config_args --version`
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
    LIBASSUAN_CFLAGS=`$LIBASSUAN_CONFIG $libassuan_config_args --cflags`
    LIBASSUAN_LIBS=`$LIBASSUAN_CONFIG $libassuan_config_args --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    LIBASSUAN_CFLAGS=""
    LIBASSUAN_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBASSUAN_CFLAGS)
  AC_SUBST(LIBASSUAN_LIBS)
])



dnl [Copied from libksba]
dnl AM_PATH_KSBA([MINIMUM-VERSION,
dnl              [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libksba and define KSBA_CFLAGS and KSBA_LIBS
dnl
AC_DEFUN(AM_PATH_KSBA,
[ AC_ARG_WITH(ksba-prefix,
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
  min_ksba_version=ifelse([$1], ,0.4.4,$1)
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
    KSBA_CFLAGS=`$KSBA_CONFIG $ksba_config_args --cflags`
    KSBA_LIBS=`$KSBA_CONFIG $ksba_config_args --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    KSBA_CFLAGS=""
    KSBA_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(KSBA_CFLAGS)
  AC_SUBST(KSBA_LIBS)
])



dnl AM_PATH_OPENSC([MINIMUM-VERSION,
dnl               [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for OpenSC and define OPENSC_CFLAGS and OPENSC_LIBS
dnl
AC_DEFUN(AM_PATH_OPENSC,
[ AC_ARG_WITH(opensc-prefix,
            AC_HELP_STRING([--with-opensc-prefix=PFX],
                           [prefix where OpenSC is installed (optional)]),
     opensc_config_prefix="$withval", opensc_config_prefix="")
  if test x$opensc_config_prefix != x ; then
     opensc_config_args="$opensc_config_args --prefix=$opensc_config_prefix"
     if test x${OPENSC_CONFIG+set} != xset ; then
        OPENSC_CONFIG=$opensc_config_prefix/bin/opensc-config
     fi
  fi

  AC_PATH_PROG(OPENSC_CONFIG, opensc-config, no)
  min_opensc_version=ifelse([$1], ,0.7.0,$1)
  AC_MSG_CHECKING(for OpenSC - version >= $min_opensc_version)
  ok=no
  if test "$OPENSC_CONFIG" != "no" ; then
    req_major=`echo $min_opensc_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_opensc_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_opensc_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    opensc_config_version=`$OPENSC_CONFIG $opensc_config_args --version`
    major=`echo $opensc_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $opensc_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $opensc_config_version | \
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
    OPENSC_CFLAGS=`$OPENSC_CONFIG $opensc_config_args --cflags`
    OPENSC_LIBS=`$OPENSC_CONFIG $opensc_config_args --libs`
    OPENSC_LIBS="$OPENSC_LIBS -lpcsclite -lpthread"
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    OPENSC_CFLAGS=""
    OPENSC_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(OPENSC_CFLAGS)
  AC_SUBST(OPENSC_LIBS)
])


