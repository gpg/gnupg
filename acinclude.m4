dnl macros to configure g10

AC_PREREQ(2.5)

AC_DEFUN(md_TYPE_PTRDIFF_T,
  [AC_CACHE_CHECK([for ptrdiff_t], ac_cv_type_ptrdiff_t,
     [AC_TRY_COMPILE(stddef.h, [ptrdiff_t p], ac_cv_type_ptrdiff_t=yes,
		     ac_cv_type_ptrdiff_t=no)])
   if test $ac_cv_type_ptrdiff_t = yes; then
     AC_DEFINE(HAVE_PTRDIFF_T)
   fi
])

AC_DEFUN(md_PATH_PROG,
  [AC_PATH_PROG($1,$2,$3)dnl
   if echo $$1 | grep openwin > /dev/null; then
     echo "WARNING: Do not use OpenWin's $2.  (Better remove it.) >&AC_FD_MSG"
     ac_cv_path_$1=$2
     $1=$2
   fi
])

dnl Check NLS options

AC_DEFUN(ud_LC_MESSAGES,
  [if test $ac_cv_header_locale_h = yes; then
    AC_CACHE_CHECK([for LC_MESSAGES], ud_cv_val_LC_MESSAGES,
      [AC_TRY_LINK([#include <locale.h>], [return LC_MESSAGES],
       ud_cv_val_LC_MESSAGES=yes, ud_cv_val_LC_MESSAGES=no)])
    if test $ud_cv_val_LC_MESSAGES = yes; then
      AC_DEFINE(HAVE_LC_MESSAGES)
    fi
  fi])

AC_DEFUN(ud_WITH_NLS,
  [AC_MSG_CHECKING([whether NLS is requested])
    dnl Default is enabled NLS
    AC_ARG_ENABLE(nls,
      [  --disable-nls		 do not use Native Language Support],
      nls_cv_use_nls=$enableval, nls_cv_use_nls=yes)
    AC_MSG_RESULT($nls_cv_use_nls)

    dnl If we use NLS figure out what method
    if test "$nls_cv_use_nls" = "yes"; then
      AC_DEFINE(ENABLE_NLS)
      AC_MSG_CHECKING([for explicitly using GNU gettext])
      AC_ARG_WITH(gnu-gettext,
	[  --with-gnu-gettext	   use the GNU gettext library],
	nls_cv_force_use_gnu_gettext=$withval,
	nls_cv_force_use_gnu_gettext=no)
      AC_MSG_RESULT($nls_cv_force_use_gnu_gettext)

      if test "$nls_cv_force_use_gnu_gettext" = "yes"; then
	nls_cv_use_gnu_gettext=yes
      else
	dnl User does not insist on using GNU NLS library.  Figure out what
	dnl to use.  If gettext or catgets are available (in this order) we
	dnl use this.  Else we have to fall back to GNU NLS library.
	AC_CHECK_LIB(intl, main)
	AC_CHECK_LIB(i, main)
	CATOBJEXT=NONE

	dnl Debian 1.3.1 does not have libintl.h but libintl.a
	AC_CHECK_HEADERS(libintl.h)
	if    test "$ac_cv_lib_intl_main" = yes \
	   && test "$ac_cv_header_libintl_h" != "yes" ; then
	    nls_cv_use_gnu_gettext=yes
	else
	    AC_CHECK_FUNC(gettext,
	      [AC_DEFINE(HAVE_GETTEXT)
	       md_PATH_PROG(MSGFMT, msgfmt, no)dnl
	       if test "$MSGFMT" != "no"; then
		 AC_CHECK_FUNCS(dcgettext)
		 md_PATH_PROG(GMSGFMT, gmsgfmt, $MSGFMT)
		 md_PATH_PROG(XGETTEXT, xgettext, xgettext)
		 CATOBJEXT=.mo
		 INSTOBJEXT=.mo
		 DATADIRNAME=lib
		 if test "$ac_cv_lib_intl[_]main" = yes; then
		   INTLLIBS=-lintl
		 elif test "$ac_cv_lib_i[_]main" = yes; then
		   INTLLIBS=-li
		 fi
	       fi])

	    if test "$CATOBJEXT" = "NONE"; then
	      dnl No gettext in C library.  Try catgets next.
	      AC_CHECK_FUNC(catgets,
		[AC_DEFINE(HAVE_CATGETS)
		 INTLOBJS="\$(CATOBJS)"
		 AC_PATH_PROG(GENCAT, gencat, no)dnl
		 if test "$GENCAT" != "no"; then
		   AC_PATH_PROGS(GMSGFMT, [gmsgfmt msgfmt], msgfmt)
		   md_PATH_PROG(XGETTEXT, xgettext, xgettext)
		   CATOBJEXT=.cat
		   INSTOBJEXT=.cat
		   DATADIRNAME=lib
		   INTLDEPS="\${top_srcdir}/intl/libintl.a"
		   INTLLIBS=$INTLDEPS
		   LIBS=`echo $LIBS | sed -e 's/-lintl//'`
		   nls_cv_header_intl=intl/libintl.h
		   nls_cv_header_libgt=intl/libgettext.h
		 fi])
	    fi
	fi

	if test "$CATOBJEXT" = "NONE"; then
	  dnl Neither gettext nor catgets in included in the C library.
	  dnl Fall back on GNU gettext library.
	  nls_cv_use_gnu_gettext=yes
	fi
      fi

      if test "$nls_cv_use_gnu_gettext" = "yes"; then
	dnl Mark actions used to generate GNU NLS library.
	INTLOBJS="\$(GETTOBJS)"
	md_PATH_PROG(MSGFMT, msgfmt, msgfmt)
	md_PATH_PROG(GMSGFMT, gmsgfmt, $MSGFMT)
	md_PATH_PROG(XGETTEXT, xgettext, xgettext)
	AC_SUBST(MSGFMT)
	CATOBJEXT=.gmo
	INSTOBJEXT=.mo
	DATADIRNAME=share
	INTLDEPS="\${top_srcdir}/intl/libintl.a"
	INTLLIBS=$INTLDEPS
	LIBS=`echo $LIBS | sed -e 's/-lintl//'`
	nls_cv_header_intl=intl/libintl.h
	nls_cv_header_libgt=intl/libgettext.h
      fi

      # We need to process the intl/ and po/ directory.
      INTLSUB=intl
      POSUB=po
    else
      DATADIRNAME=share
      nls_cv_header_intl=intl/libintl.h
      nls_cv_header_libgt=intl/libgettext.h
    fi

    dnl These rules are solely for the distribution goal.  While doing this
    dnl we only have to keep exactly one list of the available catalogs
    dnl in configure.in.
    for lang in $ALL_LINGUAS; do
      GMOFILES="$GMOFILES $lang.gmo"
      POFILES="$POFILES $lang.po"
    done

    dnl Make all variables we use known to autoconf.
    AC_SUBST(CATALOGS)
    AC_SUBST(CATOBJEXT)
    AC_SUBST(DATADIRNAME)
    AC_SUBST(GMOFILES)
    AC_SUBST(INSTOBJEXT)
    AC_SUBST(INTLDEPS)
    AC_SUBST(INTLLIBS)
    AC_SUBST(INTLOBJS)
    AC_SUBST(INTLSUB)
    AC_SUBST(POFILES)
    AC_SUBST(POSUB)
  ])

AC_DEFUN(AM_GNU_GETTEXT,
  [AC_REQUIRE([AC_PROG_MAKE_SET])dnl
   AC_REQUIRE([AC_PROG_CC])dnl
   AC_REQUIRE([AC_PROG_RANLIB])dnl
   AC_REQUIRE([AC_HEADER_STDC])dnl
   AC_REQUIRE([AC_C_CONST])dnl
   AC_REQUIRE([AC_C_INLINE])dnl
   AC_REQUIRE([AC_TYPE_OFF_T])dnl
   AC_REQUIRE([AC_TYPE_SIZE_T])dnl
   AC_REQUIRE([AC_FUNC_ALLOCA])dnl
   AC_REQUIRE([AC_FUNC_MMAP])dnl

   AC_CHECK_HEADERS([limits.h locale.h nl_types.h malloc.h string.h unistd.h values.h])
   AC_CHECK_FUNCS([getcwd munmap putenv setenv setlocale strchr strcasecmp])

   if test "${ac_cv_func_stpcpy+set}" != "set"; then
     AC_CHECK_FUNCS(stpcpy)
   fi
   if test "${ac_cv_func_stpcpy}" = "yes"; then
     AC_DEFINE(HAVE_STPCPY)
   fi

   ud_LC_MESSAGES
   ud_WITH_NLS

   if test "x$CATOBJEXT" != "x"; then
     if test "x$ALL_LINGUAS" = "x"; then
       LINGUAS=
     else
       AC_MSG_CHECKING(for catalogs to be installed)
       NEW_LINGUAS=
       for lang in ${LINGUAS=$ALL_LINGUAS}; do
	 case "$ALL_LINGUAS" in
	  *$lang*) NEW_LINGUAS="$NEW_LINGUAS $lang" ;;
	 esac
       done
       LINGUAS=$NEW_LINGUAS
       AC_MSG_RESULT($LINGUAS)
     fi

     dnl Construct list of names of catalog files to be constructed.
     if test -n "$LINGUAS"; then
       for lang in $LINGUAS; do CATALOGS="$CATALOGS $lang$CATOBJEXT"; done
     fi
   fi

   dnl Determine which catalog format we have (if any is needed)
   dnl For now we know about two different formats:
   dnl	 Linux and the normal X/Open format
   test -d intl || mkdir intl
   if test "$CATOBJEXT" = ".cat"; then
     AC_CHECK_HEADER(linux/version.h, msgformat=linux, msgformat=xopen)

     dnl Transform the SED scripts while copying because some dumb SEDs
     dnl cannot handle comments.
     sed -e '/^#/d' $srcdir/intl/$msgformat-msg.sed > intl/po2msg.sed
   fi
   dnl po2tbl.sed is always needed.
   sed -e '/^#.*[^\\]$/d' -e '/^#$/d' \
     $srcdir/intl/po2tbl.sed.in > intl/po2tbl.sed

   dnl Generate list of files to be processed by xgettext which will
   dnl be included in po/Makefile.
   test -d po || mkdir po
   if test "x$srcdir" != "x."; then
     if test "x`echo $srcdir | sed 's@/.*@@'`" = "x"; then
       posrcprefix="$srcdir/"
     else
       posrcprefix="../$srcdir/"
     fi
   else
     posrcprefix="../"
   fi
   sed -e "/^#/d" -e "/^\$/d" -e "s,.*, $posrcprefix& \\\\," -e "\$s/\(.*\) \\\\/\1/" \
	< $srcdir/po/POTFILES.in > po/POTFILES
  ])



dnl --------------------------------------------------
dnl G10 stuff
dnl --------------------------------------------------


dnl WK_MSG_PRINT(STRING)
dnl print a message
dnl
define(WK_MSG_PRINT,
  [ echo $ac_n "$1"" $ac_c" 1>&AC_FD_MSG
  ])


dnl WK_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check wether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN(WK_CHECK_TYPEDEF,
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(wk_cv_typedef_$1,
    [AC_TRY_COMPILE([#include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], wk_cv_typedef_$1=yes, wk_cv_typedef_$1=no )])
    AC_MSG_RESULT($wk_cv_typedef_$1)
    if test "$wk_cv_typedef_$1" = yes; then
	AC_DEFINE($2)
    fi
  ])



dnl WK_LINK_FILES( SRC, DEST )
dnl same as AC_LINK_FILES, but collet the files to link in
dnl some special variables and do the link macro
dnl when WK_DO_LINK_FILES is called
dnl This is a workaround for AC_LINK_FILES, because it does not work
dnl correct when using a caching scheme
dnl
define(WK_LINK_FILES,
  [ if test "x$wk_link_files_src" = "x"; then
	wk_link_files_src="$1"
	wk_link_files_dst="$2"
    else
	wk_link_files_src="$wk_link_files_src $1"
	wk_link_files_dst="$wk_link_files_dst $2"
    fi
  ])
define(WK_DO_LINK_FILES,
  [ AC_LINK_FILES( $wk_link_files_src, $wk_link_files_dst )
  ])


dnl WK_CHECK_ENDIAN
dnl define either LITTLE_ENDIAN_HOST or BIG_ENDIAN_HOST
dnl
define(WK_CHECK_ENDIAN,
  [ if test "$cross_compiling" = yes; then
	AC_MSG_WARN(cross compiling; assuming little endianess)
    fi
    AC_MSG_CHECKING(endianess)
    AC_CACHE_VAL(wk_cv_c_endian,
      [ wk_cv_c_endian=unknown
	# See if sys/param.h defines the BYTE_ORDER macro.
	AC_TRY_COMPILE([#include <sys/types.h>
	#include <sys/param.h>], [
	#if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
	 bogus endian macros
	#endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
	AC_TRY_COMPILE([#include <sys/types.h>
	#include <sys/param.h>], [
	#if BYTE_ORDER != BIG_ENDIAN
	 not big endian
	#endif], wk_cv_c_endian=big, wk_cv_c_endian=big)])
	if test "$wk_cv_c_endian" = unknown; then
	    AC_TRY_RUN([main () {
	      /* Are we little or big endian?  From Harbison&Steele.  */
	      union
	      {
		long l;
		char c[sizeof (long)];
	      } u;
	      u.l = 1;
	      exit (u.c[sizeof (long) - 1] == 1);
	      }],
	      wk_cv_c_endian=little,
	      wk_cv_c_endian=big,
	      wk_cv_c_endian=little
	    )
	fi
      ])
    AC_MSG_RESULT([$wk_cv_c_endian])
    if test "$wk_cv_c_endian" = little; then
      AC_DEFINE(LITTLE_ENDIAN_HOST)
    else
      AC_DEFINE(BIG_ENDIAN_HOST)
    fi
  ])

dnl WK_CHECK_CACHE
dnl
define(WK_CHECK_CACHE,
  [ AC_MSG_CHECKING(cached information)
    wk_hostcheck="$target"
    AC_CACHE_VAL(wk_cv_hostcheck, [ wk_cv_hostcheck="$wk_hostcheck" ])
    if test "$wk_cv_hostcheck" != "$wk_hostcheck"; then
	AC_MSG_RESULT(changed)
	AC_MSG_WARN(config.cache exists!)
	AC_MSG_ERROR(you must do 'make distclean' first to compile for
		 different target or different parameters.)
    else
	AC_MSG_RESULT(ok)
    fi
  ])


