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

PGM=GnuPG
lib_config_files=""
autoconf_vers=2.52
automake_vers=1.6
aclocal_vers=1.6

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOHEADER=${AUTOHEADER:-autoheader}
DIE=no

# Used to cross-compile GnuPG for Windows.
if test "$1" = "--build-w32"; then
    tmp=`dirname $0`
    tsdir=`cd "$tmp"; cd ..; pwd`
    shift
    host=i386--mingw32
    if [ ! -f $tsdir/scripts/config.guess ]; then
        echo "$tsdir/scripts/config.guess not found" >&2
        exit 1
    fi
    build=`$tsdir/scripts/config.guess`
        
    if ! mingw32 --version >/dev/null; then
        echo "We need at least version 0.3 of MingW32/CPD" >&2
        exit 1
    fi

    if [ -f "$tsdir/config.log" ]; then
        if ! head $tsdir/config.log | grep i386--mingw32 >/dev/null; then
            echo "Pease run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    crossbindir=`mingw32 --install-dir`/bin
    CC=`mingw32 --get-path gcc`
    CPP=`mingw32 --get-path cpp`
    AR=`mingw32 --get-path ar`
    RANLIB=`mingw32 --get-path ranlib`
    export CC CPP AR RANLIB 

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

    $tsdir/configure --build=${build} --host=${host} \
                ${disable_foo_tests} $*
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



if ($AUTOCONF --version) < /dev/null > /dev/null 2>&1 ; then
    if ($AUTOCONF --version | awk 'NR==1 { if( $3 >= '$autoconf_vers') \
			       exit 1; exit 0; }');
    then
       echo "**Error**: "\`autoconf\'" is too old."
       echo '           (version ' $autoconf_vers ' or newer is required)'
       DIE="yes"
    fi
else
    echo
    echo "**Error**: You must have "\`autoconf\'" installed to compile $PGM."
    echo '           (version ' $autoconf_vers ' or newer is required)'
    DIE="yes"
fi

if ($AUTOMAKE --version) < /dev/null > /dev/null 2>&1 ; then
  if ($AUTOMAKE --version | awk 'NR==1 { if( $4 >= '$automake_vers') \
			     exit 1; exit 0; }');
     then
     echo "**Error**: "\`automake\'" is too old."
     echo '           (version ' $automake_vers ' or newer is required)'
     DIE="yes"
  fi
  if ($ACLOCAL --version) < /dev/null > /dev/null 2>&1; then
    if ($ACLOCAL --version | awk 'NR==1 { if( $4 >= '$aclocal_vers' ) \
						exit 1; exit 0; }' );
    then
      echo "**Error**: "\`aclocal\'" is too old."
      echo '           (version ' $aclocal_vers ' or newer is required)'
      DIE="yes"
    fi
  else
    echo
    echo "**Error**: Missing "\`aclocal\'".  The version of "\`automake\'
    echo "           installed doesn't appear recent enough."
    DIE="yes"
  fi
else
    echo
    echo "**Error**: You must have "\`automake\'" installed to compile $PGM."
    echo '           (version ' $automake_vers ' or newer is required)'
    DIE="yes"
fi


if (gettext --version </dev/null 2>/dev/null | awk 'NR==1 { split($4,A,"."); \
    X=10000*A[1]+100*A[2]+A[3]; echo X; if( X >= 1038 ) exit 1; exit 0}')
    then
    echo "**Error**: You must have "\`gettext\'" installed to compile $PGM."
    echo '           (version 0.10.38 or newer is required; get'
    echo '            ftp://alpha.gnu.org/gnu/gettext/gettext-0.10.38.tar.gz'
    echo '            or install the latest Debian package)'
    DIE="yes"
fi


if test "$DIE" = "yes"; then
    exit 1
fi

echo "Running aclocal..."
$ACLOCAL
echo "Running autoheader..."
$AUTOHEADER
echo "Running automake --gnu ..."
$AUTOMAKE --gnu;
echo "Running autoconf..."
$AUTOCONF

echo "You can now run \"./configure --enable-maintainer-mode\" and then \"make\"."

