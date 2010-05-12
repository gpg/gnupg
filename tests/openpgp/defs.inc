# Definitions for the OpenPGP test scripts                     -*- sh -*-
# Copyright 1998,1999,2000,2001,2002,2003,2004,2005,2006,
#           2007, 2010 Free Software Foundation, Inc.
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.  This file is
# distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY, to the extent permitted by law; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

#--------------------------------
#------ constants ---------------
#--------------------------------

# Note that usrpass1 is also used in Makefile.am
usrname1="one"
usrpass1="def"
usrname2="two"
usrpass2=""
usrname3="three"
usrpass3=""


dsa_usrname1="pgp5"
# we use the sub key because we do not yet have the logic to
# to derive the first encryption key from a keyblock (I guess)
dsa_usrname2="0xCB879DE9"

dsa_keyrings="--keyring ./pubring.pkr --secret-keyring ./secring.skr"


plain_files="plain-1 plain-2 plain-3"
data_files="data-500 data-9000 data-32000 data-80000"
exp_files=""

# The testscripts expect the original language
LANG=
LANGUAGE=
LC_ALL=
LC_MESSAGES=

# Internal use.
defs_stop_on_error=no
defs_error_seen=no

#--------------------------------
#------ utility functions -------
#--------------------------------

fatal () {
    echo "$pgmname: fatal:" $* >&2
    echo "$pgmname: fatal:" $* >&5
    exit 1;
}

error () {
    echo "$pgmname:" $* >&2
    defs_error_seen=yes
    echo "$pgmname:" $* >&5
    if [ x$defs_stop_on_error != xyes ]; then
      exit 1 
    fi
}

# Call this at the start of a test and resume_error at the end to keep
# on running all subtests without immediately exiting on error.
suspend_error () {
   defs_stop_on_error=yes
}

resume_error () {
    if [ x$defs_error_seen = xyes ]; then
        exit 1
    fi
    defs_stop_on_error=no
    defs_error_seen=no
}

info () {
    echo "$pgmname:" $* >&2
    if [ -n "${verbose+set}" ]; then
      echo "$pgmname:" $* >&5
    fi
}

linefeed () {
    echo >&2
}


echo_n_init=no
echo_n () {
  if test "$echo_n_init" = "no"; then
    if (echo "testing\c"; echo 1,2,3) | grep c >/dev/null; then
      if (echo -n testing; echo 1,2,3) | sed s/-n/xn/ | grep xn >/dev/null; then
	echo_n_n=
	echo_n_c='
'
      else
	echo_n_n='-n'
	echo_n_c=
      fi
    else
      echo_n_n=
      echo_n_c='\c'
    fi
    echo_n_init=yes
  fi
  echo $echo_n_n "${1}$echo_n_c"
}


#cleanup () {
#    rm $cleanup_files 2>/dev/null || true
#    echo "#empty" >./gpg.conf
#}


#add_cleanup () {
#    cleanup_files="$cleanup_files $*"
#}

have_pubkey_algo () {
  if  ../../g10/gpg2 --homedir .  --version | grep "Pubkey:.*$1" >/dev/null
  then
	true
  else
	false
  fi
}

have_cipher_algo () {
  if  ../../g10/gpg2 --homedir .  --version | grep "Cipher:.*$1" >/dev/null
  then
	true
  else
	false
  fi
}

have_hash_algo () {
  if  ../../g10/gpg2 --homedir .  --version | grep "Hash:.*$1" >/dev/null
  then
	true
  else
	false
  fi
}

all_cipher_algos () {
  ../../g10/gpg2 --homedir . --with-colons --list-config ciphername | sed 's/^cfg:ciphername://; s/;/ /g'
}

all_hash_algos () {
  ../../g10/gpg2 --homedir . --with-colons --list-config digestname | sed 's/^cfg:digestname://; s/;/ /g'
}

set -e
pgmname=`basename $0`
#trap cleanup SIGHUP SIGINT SIGQUIT

[ -z "$srcdir" ] && fatal "not called from make"

# Make sure we have a valid option file even with VPATH builds.
for f in gpg.conf ; do 
  if [ -f ./$f ]; then
    :
  elif [ -f $srcdir/$f.tmpl ]; then
    cat $srcdir/$f.tmpl >$f
  fi
done

# Always work in the current directory.  We set GNUPGHOME only if it
# has not been set already.  Usually it is set through the Makefile's
# TESTS_ENVIRONMENT macro.
if [ -z "$GNUPGHOME" ]; then
  GNUPGHOME=`pwd`
  export GNUPGHOME
elif [ "$GNUPGHOME" != `pwd` ]; then
  echo "$pgmname: GNUPGHOME not set to the cwd" $* >&2
  exit 1
fi


GPG="../../g10/gpg2 --no-permission-warning "

echo "Test: $pgmname"                  >  ${pgmname}.log
echo "GNUPGHOME=$GNUPGHOME"            >> ${pgmname}.log
echo "GPG_AGENT_INFO=$GPG_AGENT_INFO"  >> ${pgmname}.log
exec 5>&2 2>>${pgmname}.log

:
# end
