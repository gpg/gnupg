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

usrname1="one@example.com"
usrpass1="def"
usrname2="two@example.com"
usrpass2=""
usrname3="three@example.com"
usrpass3=""


dsa_usrname1="pgp5"
# we use the sub key because we do not yet have the logic to to derive
# the first encryption key from a keyblock (I guess) (Well of course
# we have this by now and the notation below will lookup the primary
# first and then search for the encryption subkey.)
dsa_usrname2="0xCB879DE9"


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
defs_progress_active=no

#--------------------------------
#------ utility functions -------
#--------------------------------

progress_cancel () {
    if [ x$defs_progress_active = xyes ]; then
        echo
        defs_progress_active=no
    fi
}

fatal () {
    progress_cancel
    echo "$pgmname: fatal:" $* >&2
    echo "$pgmname: fatal:" $* >&5
    echo stop >gnupg-test.stop
    exit 1;
}

error () {
    progress_cancel
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
    progress_cancel
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


progress_end () {
    if [ x$defs_progress_active = xyes ]; then
        echo "<"
        defs_progress_active=no
    fi
}

progress () {
    if [ x$defs_progress_active != xyes ]; then
        echo_n "    > "
        defs_progress_active=yes
    fi
    echo_n "$* "
}



#cleanup () {
#    rm $cleanup_files 2>/dev/null || true
#    echo "#empty" >./gpg.conf
#}


#add_cleanup () {
#    cleanup_files="$cleanup_files $*"
#}

have_pubkey_algo () {
  if  $GPG --version | grep "Pubkey:.*$1" >/dev/null
  then
	true
  else
	false
  fi
}

have_cipher_algo () {
  if $GPG --version | grep "Cipher:.*$1" >/dev/null
  then
	true
  else
	false
  fi
}

have_hash_algo () {
  if $GPG --version | grep "Hash:.*$1" >/dev/null
  then
	true
  else
	false
  fi
}

all_cipher_algos () {
  $GPG --with-colons --list-config ciphername \
       | sed 's/^cfg:ciphername://; s/;/ /g'
}

all_hash_algos () {
  $GPG --with-colons --list-config digestname \
       | sed 's/^cfg:digestname://; s/;/ /g'
}

set -e
pgmname=`basename $0`
#trap cleanup SIGHUP SIGINT SIGQUIT

[ -z "$srcdir" ] && fatal "not called from make"

#
if [ -f gnupg-test.stop ]; then
    if [ $pgmname = "version.test" ]; then
        rm gnupg-test.stop
    else
        # Skip the rest of the tests.
        exit 77
    fi
fi

# Always work in the current directory.  We set GNUPGHOME only if it
# has not been set already.  Usually it is set through the Makefile's
# TESTS_ENVIRONMENT macro.
if [ -z "$GNUPGHOME" ]; then
  GNUPGHOME=`/bin/pwd`
  export GNUPGHOME
elif [ "$GNUPGHOME" != `/bin/pwd` ]; then
  echo "$pgmname: GNUPGHOME not set to the cwd" $* >&2
  exit 1
fi

# We don't use GPG_AGENT_INFO anymore - better reset it.
unset GPG_AGENT_INFO

# (--no-permission-warning makes only sense on the commandline)
GPG="../../g10/gpg2 --no-permission-warning "
# (We may not use a relative name for gpg-agent.)
GPG_AGENT="$(cd ../../agent && /bin/pwd)/gpg-agent"
GPG_CONNECT_AGENT="../../tools/gpg-connect-agent"
GPGCONF="../../tools/gpgconf"
GPG_PRESET_PASSPHRASE="../../agent/gpg-preset-passphrase"
MKTDATA="../../tools/mk-tdata"
PINENTRY="$(cd $srcdir && /bin/pwd)/pinentry.sh"
# Default to empty passphrase for pinentry.sh
PINENTRY_USER_DATA=

# If --check-trustdb is not an option, GPG has been build without
# trust model support.  Thus we can't use --always-trust and some
# other options.
if $GPG --dump-options | grep '^--check-trustdb$' >/dev/null ; then
  opt_always="--always-trust"
else
  opt_always=
fi

# Make sure we have a valid option files even with VPATH builds.
for f in gpg.conf gpg-agent.conf ; do
  if [ -f ./$f ]; then
    :
  elif [ -f $srcdir/$f.tmpl ]; then
    cat $srcdir/$f.tmpl >$f
    case "$f" in
      gpg.conf)
        [ -n "${opt_always}" ] && echo "no-auto-check-trustdb" >>"$f"
        echo "agent-program ${GPG_AGENT}|--debug-quick-random" >>"$f"
        echo "allow-weak-digest-algos" >>"$f"
        ;;
      gpg-agent.conf)
        echo "pinentry-program $PINENTRY" >>"$f"
        ;;
    esac
  fi
done

if [ "${verbose:-0}" -gt "1" ]; then
  exec 5>/dev/null
else
  echo "Test: $pgmname"                  >  ${pgmname}.log
  echo "GNUPGHOME=$GNUPGHOME"            >> ${pgmname}.log
  exec 5>&2 2>>${pgmname}.log
fi
:
# end
