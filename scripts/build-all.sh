#! /bin/bash
# A simple script to build all parts of GnuPG from the git repos.
#
# Copyright 2011 Free Software Foundation, Inc.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# Run this in another window:
#tail -n0 -F ~/tmp/gpg-tmp/b/{libgpg-error,libksba,libassuan,libgcrypt,gnupg}.log &

p=$HOME/tmp/gpg-tmp
parts="libgpg-error libassuan libksba libgcrypt gnupg"
die=no
here="`pwd`"

# Reject unsafe characters in $PWD and $HOME.  We consider spaces as
# unsafe because it is too easy to get scripts wrong in this regard.
am_lf='
'
case $here in
  *[\;\\\"\#\$\&\'\`$am_lf\ \	]*)
    echo "unsafe working directory: \`$here'"; die=yes;;
esac
case $HOME in
  *[\;\\\"\#\$\&\'\`$am_lf\ \	]*)
    echo "unsafe home directory: \`$HOME'"; die=yes;;
esac
test $die = yes && exit 1

# Check that all components are available
for i in $parts; do
  if test -d $i ; then
    :
  else
    die=yes
    echo "component $i missing"
  fi
done
test $die = yes && exit 1

mkdir $p || exit 1
mkdir $p/b || exit 1
for i in $parts; do
  mkdir $p/b/$i || exit 1
done

export PATH=$p/bin:$PATH
export LD_LIBRARY_PATH=$p/lib

prev=
cfg="configure --enable-maintainer-mode --prefix=$p"
for i in $parts; do
  echo $i...
  test -n "$prev" && cfg="$cfg --with-$prev-prefix=$p"
  (cd $p/b/$i && eval $here/$i/$cfg && make && make check && make install) \
      > $p/b/$i.log 2>&1 \
      || { echo FAIL; break; }
  prev=$i
done
