dnl macros to configure g10


dnl GNUPG_MSG_PRINT(STRING)
dnl print a message
dnl
define(GNUPG_MSG_PRINT,
  [ echo $ac_n "$1"" $ac_c" 1>&AC_FD_MSG
  ])


dnl GNUPG_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN(GNUPG_CHECK_TYPEDEF,
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(gnupg_cv_typedef_$1,
    [AC_TRY_COMPILE([#include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], gnupg_cv_typedef_$1=yes, gnupg_cv_typedef_$1=no )])
    AC_MSG_RESULT($gnupg_cv_typedef_$1)
    if test "$gnupg_cv_typedef_$1" = yes; then
        AC_DEFINE($2)
    fi
  ])


dnl GNUPG_CHECK_GNUMAKE
dnl
AC_DEFUN(GNUPG_CHECK_GNUMAKE,
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



dnl GNUPG_LINK_FILES( SRC, DEST )
dnl same as AC_LINK_FILES, but collect the files to link in
dnl some special variables and do the link
dnl when GNUPG_DO_LINK_FILES is called
dnl This is a workaround for AC_LINK_FILES, because it does not work
dnl correct when using a caching scheme
dnl
define(GNUPG_LINK_FILES,
  [ if test "x$wk_link_files_src" = "x"; then
        wk_link_files_src="$1"
        wk_link_files_dst="$2"
    else
        wk_link_files_src="$wk_link_files_src $1"
        wk_link_files_dst="$wk_link_files_dst $2"
    fi
  ])
define(GNUPG_DO_LINK_FILES,
  [ AC_LINK_FILES( $wk_link_files_src, $wk_link_files_dst )
  ])


dnl GNUPG_CHECK_ENDIAN
dnl define either LITTLE_ENDIAN_HOST or BIG_ENDIAN_HOST
dnl
define(GNUPG_CHECK_ENDIAN,
  [ if test "$cross_compiling" = yes; then
        AC_MSG_WARN(cross compiling; assuming little endianess)
    fi
    AC_MSG_CHECKING(endianess)
    AC_CACHE_VAL(gnupg_cv_c_endian,
      [ gnupg_cv_c_endian=unknown
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
        #endif], gnupg_cv_c_endian=big, gnupg_cv_c_endian=little)])
        if test "$gnupg_cv_c_endian" = unknown; then
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
              gnupg_cv_c_endian=little,
              gnupg_cv_c_endian=big,
              gnupg_cv_c_endian=little
            )
        fi
      ])
    AC_MSG_RESULT([$gnupg_cv_c_endian])
    if test "$gnupg_cv_c_endian" = little; then
      AC_DEFINE(LITTLE_ENDIAN_HOST)
    else
      AC_DEFINE(BIG_ENDIAN_HOST)
    fi
  ])

dnl GNUPG_CHECK_CACHE
dnl
define(GNUPG_CHECK_CACHE,
  [ AC_MSG_CHECKING(cached information)
    gnupg_hostcheck="$target"
    AC_CACHE_VAL(gnupg_cv_hostcheck, [ gnupg_cv_hostcheck="$gnupg_hostcheck" ])
    if test "$gnupg_cv_hostcheck" != "$gnupg_hostcheck"; then
        AC_MSG_RESULT(changed)
        AC_MSG_WARN(config.cache exists!)
        AC_MSG_ERROR(you must do 'make distclean' first to compile for
                 different target or different parameters.)
    else
        AC_MSG_RESULT(ok)
    fi
  ])


######################################################################
# Check for -fPIC etc (taken from libtool)
# This sets CFLAGS_PIC to the required flags
#           NO_PIC to yes if it is not possible to
#                  generate PIC
######################################################################
dnl GNUPG_CHECK_PIC
dnl
define(GNUPG_CHECK_PIC,
  [ AC_MSG_CHECKING(for option to create PIC)
    CFLAGS_PIC=
    NO_PIC=no
    if test "$cross_compiling" = yes; then
        AC_MSG_RESULT(assume none)
    else
        if test "$GCC" = yes; then
            CFLAGS_PIC="-fPIC"
        else
            case "$host_os" in
              aix3* | aix4*)
                # All rs/6000 code is PIC
                # but is there any non-rs/6000 AIX platform?
                ;;

              hpux9* | hpux10*)
                CFLAGS_PIC="+Z"
                ;;

              irix5* | irix6*)
                # PIC (with -KPIC) is the default.
                ;;

              osf3* | osf4*)
                # FIXME - pic_flag is probably required for
                # hppa*-osf* and i860-osf*
                ;;

              sco3.2v5*)
                CFLAGS_PIC='-Kpic'
                ;;

              solaris2* | solaris7* )
                CFLAGS_PIC='-KPIC'
                ;;

              sunos4*)
                CFLAGS_PIC='-PIC'
                ;;

              *)
                NO_PIC=yes
                ;;
            esac
        fi

        case "$host_cpu" in
        rs6000 | powerpc | powerpcle)
          # Yippee! All RS/6000 and PowerPC code is position-independent.
          CFLAGS_PIC=""
          ;;
        esac

        if test "$NO_PIC" = yes; then
            AC_MSG_RESULT(not possible)
        else
            if test -z "$CFLAGS_PIC"; then
               AC_MSG_RESULT(none)
            else
                AC_MSG_RESULT($CFLAGS_PIC)
            fi
        fi
    fi
  ])


######################################################################
# Check for export-dynamic flag
# This sets CFLAGS_EXPORTDYNAMIC to the required flags
######################################################################
dnl GNUPG_CHECK_EXPORTDYNAMIC
dnl
define(GNUPG_CHECK_EXPORTDYNAMIC,
  [ AC_MSG_CHECKING(how to specify -export-dynamic)
    if test "$cross_compiling" = yes; then
      AC_MSG_RESULT(assume none)
      CFLAGS_EXPORTDYNAMIC=""
    else
      AC_CACHE_VAL(gnupg_cv_export_dynamic,[
      if AC_TRY_COMMAND([${CC-cc} $CFLAGS -Wl,--version 2>&1 |
                                          grep "GNU ld" >/dev/null]); then
          # using gnu's linker
          gnupg_cv_export_dynamic="-Wl,-export-dynamic"
      else
          case "$host_os" in
            hpux* )
              gnupg_cv_export_dynamic="-Wl,-E"
              ;;
            * )
              gnupg_cv_export_dynamic=""
              ;;
          esac
      fi
      ])
      AC_MSG_RESULT($gnupg_cv_export_dynamic)
      CFLAGS_EXPORTDYNAMIC="$gnupg_cv_export_dynamic"
    fi
  ])

#####################################################################
# Check for SysV IPC  (from GIMP)
#   And see whether we have a SHM_LOCK (FreeBSD does not have it).
#####################################################################
dnl GNUPG_CHECK_IPC
dnl
define(GNUPG_CHECK_IPC,
   [ AC_CHECK_HEADERS(sys/ipc.h sys/shm.h)
     if test "$ac_cv_header_sys_shm_h" = "yes"; then
       AC_MSG_CHECKING(whether IPC_RMID allowes subsequent attaches)
       AC_CACHE_VAL(gnupg_cv_ipc_rmid_deferred_release,
          AC_TRY_RUN([
             #include <sys/types.h>
             #include <sys/ipc.h>
             #include <sys/shm.h>
             int main()
             {
               int id;
               char *shmaddr;
             id = shmget (IPC_PRIVATE, 4, IPC_CREAT | 0777);
             if (id == -1)
               exit (2);
               shmaddr = shmat (id, 0, 0);
               shmctl (id, IPC_RMID, 0);
               if ((char*) shmat (id, 0, 0) == (char*) -1)
               {
                 shmdt (shmaddr);
                 exit (1);
               }
               shmdt (shmaddr);
               shmdt (shmaddr);
               exit (0);
             }
         ],
         gnupg_cv_ipc_rmid_deferred_release="yes",
         gnupg_cv_ipc_rmid_deferred_release="no",
         gnupg_cv_ipc_rmid_deferred_release="assume-no")
       )
       if test "$gnupg_cv_ipc_rmid_deferred_release" = "yes"; then
           AC_DEFINE(IPC_RMID_DEFERRED_RELEASE)
           AC_MSG_RESULT(yes)
       else
          if test "$gnupg_cv_ipc_rmid_deferred_release" = "no"; then
              AC_MSG_RESULT(no)
          else
              AC_MSG_RESULT([assuming no])
          fi
       fi

       AC_MSG_CHECKING(whether SHM_LOCK is available)
       AC_CACHE_VAL(gnupg_cv_ipc_have_shm_lock,
          AC_TRY_COMPILE([#include <sys/types.h>
             #include <sys/ipc.h>
             #include <sys/shm.h>],[
             int shm_id;
             shmctl(shm_id, SHM_LOCK, 0);
             ],
             gnupg_cv_ipc_have_shm_lock="yes",
             gnupg_cv_ipc_have_shm_lock="no"
          )
       )
       if test "$gnupg_cv_ipc_have_shm_lock" = "yes"; then
         AC_DEFINE(IPC_HAVE_SHM_LOCK)
         AC_MSG_RESULT(yes)
       else
         AC_MSG_RESULT(no)
       fi
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
                    mkdir ("foo", 0);
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
                AC_DEFINE(HAVE_MLOCK)
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
             AC_DEFINE(HAVE_BROKEN_MLOCK)
             AC_MSG_RESULT(yes)
         else
            if test "$gnupg_cv_have_broken_mlock" = "no"; then
                AC_MSG_RESULT(no)
            else
                AC_MSG_RESULT(assuming no)
            fi
         fi
    fi
  ])


################################################################

# GNUPG_PROG_NM - find the path to a BSD-compatible name lister
AC_DEFUN(GNUPG_PROG_NM,
[AC_MSG_CHECKING([for BSD-compatible nm])
AC_CACHE_VAL(ac_cv_path_NM,
[if test -n "$NM"; then
  # Let the user override the test.
  ac_cv_path_NM="$NM"
else
  IFS="${IFS=   }"; ac_save_ifs="$IFS"; IFS="${IFS}:"
  for ac_dir in /usr/ucb /usr/ccs/bin $PATH /bin; do
    test -z "$ac_dir" && ac_dir=.
    if test -f $ac_dir/nm; then
      # Check to see if the nm accepts a BSD-compat flag.
      # Adding the `sed 1q' prevents false positives on HP-UX, which says:
      #   nm: unknown option "B" ignored
      if ($ac_dir/nm -B /dev/null 2>&1 | sed '1q'; exit 0) | egrep /dev/null >/dev/null; then
        ac_cv_path_NM="$ac_dir/nm -B"
      elif ($ac_dir/nm -p /dev/null 2>&1 | sed '1q'; exit 0) | egrep /dev/null >/dev/null; then
        ac_cv_path_NM="$ac_dir/nm -p"
      else
        ac_cv_path_NM="$ac_dir/nm"
      fi
      break
    fi
  done
  IFS="$ac_save_ifs"
  test -z "$ac_cv_path_NM" && ac_cv_path_NM=nm
fi])
NM="$ac_cv_path_NM"
AC_MSG_RESULT([$NM])
AC_SUBST(NM)
])

# GNUPG_SYS_NM_PARSE - Check for command ro grab the raw symbol name followed
# by C symbol name from nm.
AC_DEFUN(GNUPG_SYS_NM_PARSE,
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([GNUPG_PROG_NM])dnl
# Check for command to grab the raw symbol name followed by C symbol from nm.
AC_MSG_CHECKING([command to parse $NM output])
AC_CACHE_VAL(ac_cv_sys_global_symbol_pipe,
[# These are sane defaults that work on at least a few old systems.
# {They come from Ultrix.  What could be older than Ultrix?!! ;)}

changequote(,)dnl
# Character class describing NM global symbol codes.
ac_symcode='[BCDEGRSTU]'

# Regexp to match symbols that can be accessed directly from C.
ac_sympat='\([_A-Za-z][_A-Za-z0-9]*\)'

# Transform the above into a raw symbol and a C symbol.
ac_symxfrm='\1 \1'

# Define system-specific variables.
case "$host_os" in
aix*)
  ac_symcode='[BCDTU]'
  ;;
freebsd* | netbsd* | openbsd* | bsdi* | sunos* | cygwin32* | mingw32*)
  ac_sympat='_\([_A-Za-z][_A-Za-z0-9]*\)'
  ac_symxfrm='_\1 \1'
  ;;
irix*)
  # Cannot use undefined symbols on IRIX because inlined functions mess us up.
  ac_symcode='[BCDEGRST]'
  ;;
solaris*)
  ac_symcode='[BDTU]'
  ;;
esac

# If we're using GNU nm, then use its standard symbol codes.
if $NM -V 2>&1 | egrep '(GNU|with BFD)' > /dev/null; then
  ac_symcode='[ABCDGISTUW]'
fi

case "$host_os" in
cygwin32* | mingw32*)
  # We do not want undefined symbols on cygwin32.  The user must
  # arrange to define them via -l arguments.
  ac_symcode='[ABCDGISTW]'
  ;;
esac
changequote([,])dnl

# Write the raw and C identifiers.
ac_cv_sys_global_symbol_pipe="sed -n -e 's/^.* $ac_symcode $ac_sympat$/$ac_symxfrm/p'"

# Check to see that the pipe works correctly.
ac_pipe_works=no
cat > conftest.$ac_ext <<EOF
#ifdef __cplusplus
extern "C" {
#endif
char nm_test_var;
void nm_test_func(){}
#ifdef __cplusplus
}
#endif
int main(){nm_test_var='a';nm_test_func;return 0;}
EOF
if AC_TRY_EVAL(ac_compile); then
  # Now try to grab the symbols.
  ac_nlist=conftest.nm
  if AC_TRY_EVAL(NM conftest.$ac_objext \| $ac_cv_sys_global_symbol_pipe \> $ac_nlist) && test -s "$ac_nlist"; then

    # Try sorting and uniquifying the output.
    if sort "$ac_nlist" | uniq > "$ac_nlist"T; then
      mv -f "$ac_nlist"T "$ac_nlist"
      ac_wcout=`wc "$ac_nlist" 2>/dev/null`
changequote(,)dnl
      ac_count=`echo "X$ac_wcout" | sed -e 's,^X,,' -e 's/^[    ]*\([0-9][0-9]*\).*$/\1/'`
changequote([,])dnl
      (test "$ac_count" -ge 0) 2>/dev/null || ac_count=-1
    else
      rm -f "$ac_nlist"T
      ac_count=-1
    fi

    # Make sure that we snagged all the symbols we need.
    if egrep ' nm_test_var$' "$ac_nlist" >/dev/null; then
      if egrep ' nm_test_func$' "$ac_nlist" >/dev/null; then
        cat <<EOF > conftest.c
#ifdef __cplusplus
extern "C" {
#endif

EOF
        # Now generate the symbol file.
        sed 's/^.* \(.*\)$/extern char \1;/' < "$ac_nlist" >> conftest.c

        cat <<EOF >> conftest.c
#if defined (__STDC__) && __STDC__
# define __ptr_t void *
#else
# define __ptr_t char *
#endif

/* The number of symbols in dld_preloaded_symbols, -1 if unsorted. */
int dld_preloaded_symbol_count = $ac_count;

/* The mapping between symbol names and symbols. */
struct {
  char *name;
  __ptr_t address;
}
changequote(,)dnl
dld_preloaded_symbols[] =
changequote([,])dnl
{
EOF
        sed 's/^\(.*\) \(.*\)$/  {"\1", (__ptr_t) \&\2},/' < "$ac_nlist" >> conftest.c
        cat <<\EOF >> conftest.c
  {0, (__ptr_t) 0}
};

#ifdef __cplusplus
}
#endif
EOF
        # Now try linking the two files.
        mv conftest.$ac_objext conftestm.$ac_objext
        ac_save_LIBS="$LIBS"
        ac_save_CFLAGS="$CFLAGS"
        LIBS="conftestm.$ac_objext"
        CFLAGS="$CFLAGS$no_builtin_flag"
        if AC_TRY_EVAL(ac_link) && test -s conftest; then
          ac_pipe_works=yes
        else
          echo "configure: failed program was:" >&AC_FD_CC
          cat conftest.c >&AC_FD_CC
        fi
        LIBS="$ac_save_LIBS"
        CFLAGS="$ac_save_CFLAGS"
      else
        echo "cannot find nm_test_func in $ac_nlist" >&AC_FD_CC
      fi
    else
      echo "cannot find nm_test_var in $ac_nlist" >&AC_FD_CC
    fi
  else
    echo "cannot run $ac_cv_sys_global_symbol_pipe" >&AC_FD_CC
  fi
else
  echo "$progname: failed program was:" >&AC_FD_CC
  cat conftest.c >&AC_FD_CC
fi
rm -rf conftest*

# Do not use the global_symbol_pipe unless it works.
test "$ac_pipe_works" = yes || ac_cv_sys_global_symbol_pipe=
])

ac_result=yes
if test -z "$ac_cv_sys_global_symbol_pipe"; then
   ac_result=no
fi
AC_MSG_RESULT($ac_result)
])

# GNUPG_SYS_LIBTOOL_CYGWIN32 - find tools needed on cygwin32
AC_DEFUN(GNUPG_SYS_LIBTOOL_CYGWIN32,
[AC_CHECK_TOOL(DLLTOOL, dlltool, false)
AC_CHECK_TOOL(AS, as, false)
])

# GNUPG_SYS_SYMBOL_UNDERSCORE - does the compiler prefix global symbols
#                              with an underscore?
AC_DEFUN(GNUPG_SYS_SYMBOL_UNDERSCORE,
[tmp_do_check="no"
case "${target}" in
    i386-emx-os2 | i[3456]86-pc-os2*emx | i386-pc-msdosdjgpp)
        ac_cv_sys_symbol_underscore=yes
        ;;
    *)
      if test "$cross_compiling" = yes; then
         ac_cv_sys_symbol_underscore=yes
      else
         tmp_do_check="yes"
      fi
       ;;
esac

if test "$tmp_do_check" = "yes"; then
AC_REQUIRE([GNUPG_PROG_NM])dnl
AC_REQUIRE([GNUPG_SYS_NM_PARSE])dnl
AC_MSG_CHECKING([for _ prefix in compiled symbols])
AC_CACHE_VAL(ac_cv_sys_symbol_underscore,
[ac_cv_sys_symbol_underscore=no
cat > conftest.$ac_ext <<EOF
void nm_test_func(){}
int main(){nm_test_func;return 0;}
EOF
if AC_TRY_EVAL(ac_compile); then
  # Now try to grab the symbols.
  ac_nlist=conftest.nm
  if AC_TRY_EVAL(NM conftest.$ac_objext \| $ac_cv_sys_global_symbol_pipe \> $ac_nlist) && test -s "$ac_nlist"; then
    # See whether the symbols have a leading underscore.
    if egrep '^_nm_test_func' "$ac_nlist" >/dev/null; then
      ac_cv_sys_symbol_underscore=yes
    else
      if egrep '^nm_test_func ' "$ac_nlist" >/dev/null; then
        :
      else
        echo "configure: cannot find nm_test_func in $ac_nlist" >&AC_FD_CC
      fi
    fi
  else
    echo "configure: cannot run $ac_cv_sys_global_symbol_pipe" >&AC_FD_CC
  fi
else
  echo "configure: failed program was:" >&AC_FD_CC
  cat conftest.c >&AC_FD_CC
fi
rm -rf conftest*
])
else
AC_MSG_CHECKING([for _ prefix in compiled symbols])
fi
AC_MSG_RESULT($ac_cv_sys_symbol_underscore)
if test x$ac_cv_sys_symbol_underscore = xyes; then
  AC_DEFINE(WITH_SYMBOL_UNDERSCORE,1,
  [define if compiled symbols have a leading underscore])
fi
])

dnl Stolen from gcc
dnl Define MKDIR_TAKES_ONE_ARG if mkdir accepts only one argument instead
dnl of the usual 2.
AC_DEFUN(GNUPG_FUNC_MKDIR_TAKES_ONE_ARG,
[AC_CHECK_HEADERS(sys/stat.h unistd.h direct.h)
AC_CACHE_CHECK([if mkdir takes one argument], gnupg_cv_mkdir_takes_one_arg,
[AC_TRY_COMPILE([
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_DIRECT_H
# include <direct.h>
#endif], [mkdir ("foo", 0);],
        gnupg_cv_mkdir_takes_one_arg=no, gnupg_cv_mkdir_takes_one_arg=yes)])
if test $gnupg_cv_mkdir_takes_one_arg = yes ; then
  AC_DEFINE(MKDIR_TAKES_ONE_ARG)
fi
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
