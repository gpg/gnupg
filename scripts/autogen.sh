#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PGM=GnuPG
DIE=no

autoconf_vers=2.13
automake_vers=1.4
aclocal_vers=1.4
libtool_vers=1.3

if (autoconf --version) < /dev/null > /dev/null 2>&1 ; then
    if (autoconf --version | awk 'NR==1 { if( $3 >= '$autoconf_vers') \
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

if (automake --version) < /dev/null > /dev/null 2>&1 ; then
  if (automake --version | awk 'NR==1 { if( $4 >= '$automake_vers') \
			     exit 1; exit 0; }');
     then
     echo "**Error**: "\`automake\'" is too old."
     echo '           (version ' $automake_vers ' or newer is required)'
     DIE="yes"
  fi
  if (aclocal --version) < /dev/null > /dev/null 2>&1; then
    if (aclocal --version | awk 'NR==1 { if( $4 >= '$aclocal_vers' ) \
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


if (gettext --version </dev/null 2>/dev/null | awk 'NR==1 { split($4,A,"\."); \
    X=10000*A[1]+100*A[2]+A[3]; echo X; if( X >= 1035 ) exit 1; exit 0}')
    then
    echo "**Error**: You must have "\`gettext\'" installed to compile $PGM."
    echo '           (version 0.10.35 or newer is required; get'
    echo '            ftp://alpha.gnu.org/gnu/gettext-0.10.35.tar.gz'
    echo '            or install the latest Debian package)'
    DIE="yes"
fi


if (libtool --version) < /dev/null > /dev/null 2>&1 ; then
    if (libtool --version | awk 'NR==1 { if( $4 >= '$libtool_vers') \
			       exit 1; exit 0; }');
    then
       echo "**Error**: "\`libtool\'" is too old."
       echo '           (version ' $libtool_vers ' or newer is required)'
       DIE="yes"
    fi
else
    echo
    echo "**Error**: You must have "\`libtool\'" installed to compile $PGM."
    echo '           (version ' $libtool_vers ' or newer is required)'
    DIE="yes"
fi


if test "$DIE" = "yes"; then
    exit 1
fi

echo "Running gettextize...  Ignore non-fatal messages."
echo "no" | gettextize --force


echo "Running aclocal..."
aclocal
echo "Running autoheader..."
autoheader
echo "Running automake --gnu ..."
automake --gnu;
echo "Running autoconf..."
autoconf

echo "You can now run \"./configure\" and then \"make\"."

