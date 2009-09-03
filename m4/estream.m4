dnl Autoconf macros for libestream
dnl       Copyright (C) 2007 g10 Code GmbH
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


dnl estream_PRINTF_INIT
dnl Prepare build of source included estream-printf.c
dnl
AC_DEFUN([estream_PRINTF_INIT],
[ 
  AC_MSG_NOTICE([checking system features for estream-printf])
  AC_CHECK_HEADERS(stdint.h)
  AC_TYPE_LONG_LONG_INT  
  AC_TYPE_LONG_DOUBLE  
  AC_TYPE_INTMAX_T
  AC_TYPE_UINTMAX_T
  AC_CHECK_TYPES([ptrdiff_t])
  AC_CHECK_SIZEOF([unsigned long])
  AC_CHECK_SIZEOF([void *])
  AC_CACHE_CHECK([for nl_langinfo and THOUSANDS_SEP],
                  estream_cv_langinfo_thousands_sep,
      [AC_TRY_LINK([#include <langinfo.h>],
        [char* cs = nl_langinfo(THOUSANDS_SEP); return !cs;],
        estream_cv_langinfo_thousands_sep=yes,
        estream_cv_langinfo_thousands_sep=no)
      ])
  if test $estream_cv_langinfo_thousands_sep = yes; then
    AC_DEFINE(HAVE_LANGINFO_THOUSANDS_SEP, 1,
      [Define if you have <langinfo.h> and nl_langinfo(THOUSANDS_SEP).])
  fi
])


dnl estream_INIT
dnl Prepare build of source included estream.c
dnl
AC_DEFUN([estream_INIT],
[ 
  AC_REQUIRE([estream_PRINTF_INIT])
  AC_MSG_NOTICE([checking system features for estream])

])
