#!/bin/sh
# Run this to generate all the initial makefiles, etc.
# It is only needed for the CVS version.

# have_version(prog, list of executables, required version) 
#
# Returns true and sets $prog to the first executable with the
# required minimum major.minor.
have_version ()
{
  found=0

  for prog in $2 :
  do
    ver=$($prog --version \
  	  | gawk '{ if (match($0, /[0-9]+\.[0-9]+/))
                      {
                        print substr($0, RSTART, RLENGTH); ok=1; exit 0;
                      }
                  }
  
                  END {
                        if (! ok)
                          exit 1;
                      }')
  
    if test $? = 0
    then
      if expr 0$ver '>=' 0$3 >/dev/null 2>&1
      then
        echo Using $prog
	found=1
	export $1="$prog"
	break
      fi
    fi
  done

  if test 0$found = 01
  then
    true
  else
    echo "*** Error.  Could not find an appropriate executable for $1 with "
    echo "at least version $3."
    false
  fi
}

PGM=NEWPG
lib_config_files=""
autoconf_vers=2.52
automake_vers=1.5
aclocal_vers=1.5
#libtool_vers=1.3

DIE=no
if test "$1" = "--build-w32"; then
    shift
    target=i386--mingw32
    if [ ! -f ./config.guess ]; then
        echo "./config.guess not found" >&2
        exit 1
    fi
    host=`./config.guess`
        
    if ! mingw32 --version >/dev/null; then
        echo "We need at least version 0.3 of MingW32/CPD" >&2
        exit 1
    fi

    if [ -f config.h ]; then
        if grep HAVE_DOSISH_SYSTEM config.h | grep undef >/dev/null; then
            echo "Pease run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    crossinstalldir=`mingw32 --install-dir`
    crossbindir=`mingw32 --get-bindir 2>/dev/null` \
               || crossbindir="$crossinstalldir/bin"
    crossdatadir=`mingw32 --get-datadir 2>/dev/null` \
               || crossdatadir="$crossinstalldir/share"
    crosslibdir=`mingw32 --get-libdir 2>/dev/null` \
               || crosslibdir="$crossinstalldir/i386--mingw32/lib"
    crossincdir=`mingw32 --get-includedir 2>/dev/null` \
               || crossincdir="$crossinstalldir/i386--mingw32/include"
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

    ./configure --host=${host} --target=${target}  ${disable_foo_tests} \
                --bindir=${crossbindir} --libdir=${crosslibdir} \
                --datadir=${crossdatadir} --includedir=${crossincdir} \
                --enable-maintainer-mode $*
    exit $?
fi

if ! have_version autoconf "$autoconf autoconf" $autoconf_vers
then
  DIE="yes"
fi

if have_version automake "$automake automake automake-1.6" $automake_vers
then
  if ! have_version aclocal "$aclocal aclocal aclocal-1.6" $aclocal_vers
  then
    DIE='yes'
  fi
else
    DIE='yes'
fi

#if (libtool --version) < /dev/null > /dev/null 2>&1 ; then
#    if (libtool --version | awk 'NR==1 { if( $4 >= '$libtool_vers') \
#                               exit 1; exit 0; }');
#    then
#       echo "**Error**: "\`libtool\'" is too old."
#       echo '           (version ' $libtool_vers ' or newer is required)'
#       DIE="yes"
#    fi
#else
#    echo
#    echo "**Error**: You must have "\`libtool\'" installed to compile $PGM."
#    echo '           (version ' $libtool_vers ' or newer is required)'
#    DIE="yes"
#fi

if test "$DIE" = "yes"; then
    exit 1
fi

#echo "Running libtoolize...  Ignore non-fatal messages."
#echo "no" | libtoolize

echo "Running gettextize...  Ignore non-fatal messages."
echo "no" | gettextize 

echo "Running $aclocal"
$aclocal
echo "Running autoheader..."
autoheader
echo "Running $automake --gnu -a"
$automake --gnu -a
echo "Running $autoconf"
$autoconf
