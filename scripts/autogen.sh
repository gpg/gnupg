#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PGM=GnuPG
DIE=no

if (autoconf --version) < /dev/null > /dev/null 2>&1 ; then
    :
else
    echo
    echo "**Error**: You must have "\`autoconf\'" installed to compile $PGM."
    echo '           (version 2.10 or newer is required)'
    DIE="yes"
fi

if (automake --version) < /dev/null > /dev/null 2>&1 ; then
  if (aclocal --version) < /dev/null > /dev/null 2>&1; then
    if (aclocal --version | awk 'NR==1 { if( $4 >= 1.3 ) exit 1; exit 0; }');
    then
      echo "**Error**: "\`aclocal\'" is too old."
      echo '           (version 1.3 or newer is required)'
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
    echo '           (version 1.3 or newer is required)'
    DIE="yes"
fi

if test "$DIE" = "yes"; then
    exit 1
fi


aclocal
autoheader
automake --gnu;
autoheader
autoconf

echo "Ready to run ./configure"

