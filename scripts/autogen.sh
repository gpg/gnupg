#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PGM=GnuPG

DIE=no
NO_AUTOMAKE=no

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: You must have "\`autoconf\'" installed to compile $PGM."
    echo '           (version 2.10 or newer is required'
    DIE=yes
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: You must have "\`automake\'" installed to compile $PGM."
    echo '           (version 1.3 or newer is required)'
    DIE=yes
    NO_AUTOMAKE=yes
}


# if no automake, don't bother testing for aclocal
test "$NO_AUTOMAKE" = "no" \
     || (aclocal --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: Missing "\`aclocal\'".  The version of "\`automake\'
    echo "           installed doesn't appear recent enough."
    DIE=yes
}

if test "$DIE" = "yes"; then
    exit 1
fi


aclocal
autoheader
automake --gnu;
autoheader
autoconf

