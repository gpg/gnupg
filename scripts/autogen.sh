#!/bin/sh
# Run this to generate all the initial makefiles, etc.
#
# Copyright (C) 1998,1999,2000,2001,2002,2003 Free Software Foundation, Inc.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

configure_ac="configure.ac"

cvtver () {
  awk 'NR==1 {split($NF,A,".");X=1000000*A[1]+1000*A[2]+A[3];print X;exit 0}'
}

check_version () {
    if [ `("$1" --version || echo "0") | cvtver` -ge "$2" ]; then
       return 0
    fi
    echo "**Error**: "\`$1\'" not installed or too old." >&2
    echo '           Version '$3' or newer is required.' >&2
    [ -n "$4" ] && echo '           Note that this is part of '\`$4\''.' >&2
    DIE="yes"
    return 1
}

# Allow to override the default tool names
AUTOCONF=${AUTOCONF_PREFIX}${AUTOCONF:-autoconf}${AUTOCONF_SUFFIX}
AUTOHEADER=${AUTOCONF_PREFIX}${AUTOHEADER:-autoheader}${AUTOCONF_SUFFIX}

AUTOMAKE=${AUTOMAKE_PREFIX}${AUTOMAKE:-automake}${AUTOMAKE_SUFFIX}
ACLOCAL=${AUTOMAKE_PREFIX}${ACLOCAL:-aclocal}${AUTOMAKE_SUFFIX}

GETTEXT=${GETTEXT_PREFIX}${GETTEXT:-gettext}${GETTEXT_SUFFIX}
MSGMERGE=${GETTEXT_PREFIX}${MSGMERGE:-msgmerge}${GETTEXT_SUFFIX}

DIE=no

# Used to cross-compile GnuPG for Windows.
if test "$1" = "--build-w32"; then
    tmp=`dirname $0`
    tsdir=`cd "$tmp"; cd ..; pwd`
    shift
    if [ ! -f $tsdir/scripts/config.guess ]; then
        echo "$tsdir/scripts/config.guess not found" >&2
        exit 1
    fi
    build=`$tsdir/scripts/config.guess`

    # Locate the cross compiler
    crossbindir=
    for host in i586-mingw32msvc i386-mingw32msvc; do
        if ${host}-gcc --version >/dev/null 2>&1 ; then
            crossbindir=/usr/${host}/bin
            conf_CC="CC=${host}-gcc"
            break;
        fi
    done
    if [ -z "$crossbindir" ]; then
        echo "Cross compiler kit not installed" >&2
        echo "Under Debian GNU/Linux, you may install it using" >&2
        echo "  apt-get install mingw32 mingw32-runtime mingw32-binutils" >&2 
        echo "Stop." >&2
        exit 1
    fi
   
    if [ -f "$tsdir/config.log" ]; then
        if ! head $tsdir/config.log | grep "$host" >/dev/null; then
            echo "Please run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    disable_foo_tests=""
    if [ -n "$lib_config_files" ]; then
        for i in $lib_config_files; do
            j=`echo $i | tr '[a-z-]' '[A-Z_]'`
            eval "$j=${crossbindir}/$i"
            export $j
            disable_foo_tests="$disable_foo_tests --disable-`echo $i| \
                           sed 's,-config$,,'`-test"
            if [ ! -f "${crossbindir}/$i" ]; then                   
                echo "$i not installed for MingW32" >&2
                DIE=yes
            fi
        done
    fi
    [ $DIE = yes ] && exit 1

    $tsdir/configure ${conf_CC} --build=${build} --host=${host} \
                ${disable_foo_tests}  $*
    exit $?
fi


# This is the special case to build on a ColdFire platform under 
# the uClinux kernel.  Tested on a MCF4249C3 board.
if test "$1" = "--build-coldfire"; then
    tmp=`dirname $0`
    tsdir=`cd "$tmp"; cd ..; pwd`
    shift
    if [ $# -lt 1 ]; then
      echo "usage: autogen.sh --build-coldfire <crossroot>" >&2
      exit 1
    fi
    crossdir="$1"
    shift

    host=m68k-elf
    crossprefix=${host}-
    if [ ! -f $tsdir/scripts/config.guess ]; then
        echo "$tsdir/scripts/config.guess not found" >&2
        exit 1
    fi
    build=`$tsdir/scripts/config.guess`
        
    if [ -f "$tsdir/config.log" ]; then
        if ! head $tsdir/config.log | grep m68k-elf >/dev/null; then
            echo "Pease run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    crossbindir=$crossdir/bin
    CC=${crossbindir}/${crossprefix}gcc
    CPP=${crossbindir}/cpp
    AR=${crossbindir}/${crossprefix}ar
    RANLIB=${crossbindir}/${crossprefix}ranlib

    CFLAGS="-Os -g -fomit-frame-pointer"
    CFLAGS="$CFLAGS -m5307 -DCONFIG_COLDFIRE"
    CFLAGS="$CFLAGS -Dlinux -D__linux__ -Dunix -D__uClinux__ -DEMBED"
    CFLAGS="$CFLAGS -fno-builtin -msep-data"
    LDFLAGS="-Wl,-elf2flt -Wl,-move-rodata -nostartfiles"
    LDFLAGS="$LDFLAGS ${crossdir}/m68k-elf/lib/crt0.o"
    LIBS="-lc"

    disable_foo_tests=""
    if [ -n "$lib_config_files" ]; then
        for i in $lib_config_files; do
            j=`echo $i | tr '[a-z-]' '[A-Z_]'`
            eval "$j=${crossbindir}/$i"
            export $j
            disable_foo_tests="$disable_foo_tests --disable-`echo $i| \
                           sed 's,-config$,,'`-test"
            if [ ! -f "${crossbindir}/$i" ]; then                   
                echo "$i not installed for ColdFire" >&2
                DIE=yes
            fi
        done
    fi
    [ $DIE = yes ] && exit 1

    $tsdir/configure --build=${build} --host=${host} \
                ${disable_foo_tests} \
                --disable-dynload \
                --disable-exec \
                --disable-photo-viewers \
                --disable-keyserver-helpers \
                --disable-ldap \
                --disable-mailto \
                --disable-largefile \
                --disable-asm \
                --disable-nls $* \
                CC="$CC" CPP="$CPP" AR="$AR" RANLIB="$RANLIB" \
                CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" LIBS="$LIBS"
    exit $?
fi


# This is the special case to build on a ColdFire platform under 
# the uClinux kernel with uClinux-dist.  Tested on a MCF4249C3 board.
if test "$1" = "--build-uclinux"; then
    tmp=`dirname $0`
    tsdir=`cd "$tmp"; cd ..; pwd`
    shift

    if [ ! -f $tsdir/scripts/config.guess ]; then
        echo "$tsdir/scripts/config.guess not found" >&2
        exit 1
    fi
    build=`$tsdir/scripts/config.guess`
    host=m68k-elf
        
    if [ -f "$tsdir/config.log" ]; then
        if ! head $tsdir/config.log | grep m68k-elf >/dev/null; then
            echo "Please run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    $tsdir/configure --build=${build} --host=${host} \
                ${disable_foo_tests} \
                --disable-dynload \
                --disable-exec \
                --disable-photo-viewers \
                --disable-keyserver-helpers \
                --disable-ldap \
                --disable-mailto \
                --disable-largefile \
                --disable-asm \
	        --disable-nls $* \
                CC="$CC" CPP="$CPP" AR="$AR" RANLIB="$RANLIB" \
                CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" LIBS="$LDLIBS"
    exit $?
fi


# Grep the required versions from configure.ac
autoconf_vers=`sed -n '/^AC_PREREQ(/ { 
s/^.*(\(.*\))/\1/p
q
}' ${configure_ac}`
autoconf_vers_num=`echo "$autoconf_vers" | cvtver`

automake_vers=`sed -n '/^min_automake_version=/ { 
s/^.*="\(.*\)"/\1/p
q
}' ${configure_ac}`
automake_vers_num=`echo "$automake_vers" | cvtver`

gettext_vers=`sed -n '/^AM_GNU_GETTEXT_VERSION(/ { 
s/^.*(\(.*\))/\1/p
q
}' ${configure_ac}`
gettext_vers_num=`echo "$gettext_vers" | cvtver`


if [ -z "$autoconf_vers" -o -z "$automake_vers" -o -z "$gettext_vers" ]
then
  echo "**Error**: version information not found in "\`${configure_ac}\'"." >&2
  exit 1
fi


if check_version $AUTOCONF $autoconf_vers_num $autoconf_vers ; then
    check_version $AUTOHEADER $autoconf_vers_num $autoconf_vers autoconf
fi
if check_version $AUTOMAKE $automake_vers_num $automake_vers; then
  check_version $ACLOCAL $automake_vers_num $automake_vers automake
fi
if check_version $GETTEXT $gettext_vers_num $gettext_vers; then
  check_version $MSGMERGE $gettext_vers_num $gettext_vers gettext
fi

if test "$DIE" = "yes"; then
    cat <<EOF

Note that you may use alternative versions of the tools by setting 
the corresponding environment variables; see README.CVS for details.
                   
EOF
    exit 1
fi


echo "Running aclocal -I m4 ${ACLOCAL_FLAGS:+$ACLOCAL_FLAGS }..."
$ACLOCAL -I m4 $ACLOCAL_FLAGS
echo "Running autoheader..."
$AUTOHEADER
echo "Running automake --gnu --add-missing..."
$AUTOMAKE --gnu --add-missing;
echo "Running autoconf..."
$AUTOCONF

echo "You may now run \"./configure --enable-maintainer-mode && make\"."
