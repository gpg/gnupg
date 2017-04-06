# common.sh - common defs for all tests         -*- sh -*-
# Copyright (C) 2004, 2008 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
# 
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# reset some environment variables because we do not want to test locals
LANG=C
LANGUAGE=C
LC_ALL=C
export LANG LANGUAGE LC_ALL

pgmname=`basename $0`

if [ "$1" = "--debug" ]; then
  debug=yes
  set -x
else
  debug=
fi
[ -z "$srcdir" ] && srcdir="."
[ -z "$top_srcdir" ] && top_srcdir=".."
[ -z "$GPGSM" ] && GPGSM="../../sm/gpgsm"
[ -z "$silent" ] && silent=no

AWK=awk
SCRATCH="scratch.$$.tmp"

# We use this as the faked system time for certain tests.
MYTIME="20080508T120000"


if [ "$GNUPGHOME" != "`/bin/pwd`" ]; then
    echo "inittests: please set GNUPGHOME to the tests/pkits directory" >&2
    exit 1
fi

if [ -n "$GPG_AGENT_INFO" ]; then
    echo "inittests: please unset GPG_AGENT_INFO" >&2
    exit 1
fi

if [ -f "$srcdir/PKITS_data.tar.bz2" ]; then
  :
else
    if [ "$pgmname" = "import-all-certs" ]; then
        if [ "$silent" = "yes" ]; then tmp1="Note: "; tmp2='      '
        else tmp1="- ____ "; tmp2="$tmp1"
        fi
        echo "${tmp1}PKITS_data.tar.bz2 is not installed"
        echo "${tmp2}All tests will be skipped (this is not an error)"
    fi
    # Exit code 77 is used by the Makefile for skipping a tests.
    exit 77
fi

#--------------------------------
#------ utility functions -------
#--------------------------------

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

setup_output () {
  if [ -z "$first_section_set" ]; then
      first_section_set=$section
  fi
  section_out="$(echo $section)"
  if [ -z "$section_out" ]; then
      section_out="-"
  fi
}

fatal () {
    echo "$pgmname: fatal:" $* >&2
    if [ "$silent" != "yes" ]; then
        echo "$section_out ERROR: $* (fatal)"
    fi
    exit 1;
}

error () {
    echo "$pgmname:" $* >&2
    if [ "$silent" != "yes" ]; then
        echo "$section_out ERROR: $*"
    fi
    exit 1
}

info () {
    setup_output
    echo "$pgmname:" $* >&2
    if [ "$silent" != "yes" ]; then
        echo "$section_out ____ $*"
    fi
}

info_n () {
    setup_output
    echo_n "$pgmname:" $* >&2
}

pass () {
    setup_output
    echo "PASS: " $* >&2
    pass_count=`expr ${pass_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out PASS"
        if [ -n "$1" ]; then echo_n " $1"
        elif [ -n "$description" ]; then echo_n " ($description)"
        fi
        echo
    fi
}

fail () {
    setup_output
    echo "FAIL: " $* >&2
    fail_count=`expr ${fail_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out FAIL"
        if [ -n "$1" ]; then echo_n " $1"
        elif [ -n "$description" ]; then echo_n " ($description)"
        fi
        echo
    fi
}

skip () {
    setup_output
    echo "SKIP: " $* >&2
    skip_count=`expr ${skip_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out SKIP"
        if [ -n "$1" ]; then echo_n " $1"
        elif [ -n "$description" ]; then echo_n " ($description)"
        fi
        echo
    fi
}

unresolved () {
    setup_output
    echo "UNRESOLVED: " $* >&2
    unresolved_count=`expr ${unresolved_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out UNRESOLVED"
        if [ -n "$1" ]; then echo_n " $1"
        elif [ -n "$description" ]; then echo_n " ($description)"
        fi
        echo
    fi
}


final_result () {
    section=$first_section_set
    [ $pass_count = 0 ]        || info "$pass_count tests passed"
    [ $fail_count = 0 ]        || info "$fail_count tests failed"
    [ $skip_count = 0 ]        || info "$unsupported_count tests skipped"
    [ $unresolved_count = 0 ]  || info "$unresolved_count tests unresolved"
    [ -z "$debug" -a -f "$SCRATCH" ] && rm "$SCRATCH"
    if [ $fail_count = 0 ]; then
        info "all tests passed"
    else
        exit 1
    fi
}


clean_homedir () {
    [ -f pubring.kbx ] && rm pubring.kbx
    if [ -d private-keys-v1.d ]; then
        rm private-keys-v1.d/* 2>/dev/null || true
        rmdir private-keys-v1.d
    fi
}

start_test () {
    section="$1"
    description="$2"
    test_status=none
    echo "BEGIN TEST $section ($description)" >&2
}

end_test () {
   case "$test_status" in
      none) skip "($description) - test not implemented";;
      pass) pass "($description)";;
      fail) fail "($description)";;
     setup) fail "($description) - setup failed";;
        ns) skip "($description) - not supported";;
       nys) skip "($description) - not yet supported";;
         *) unresolved "$(description)";; 
   esac
   echo "END TEST $section" >&2
}

set_status () {
    if [ "$test_status" = "none" ]; then
        test_status=$1
    fi
}

need_cert () {
    if [ "$2" = "--import-anyway" ]; then
        if ! ${GPGSM} -q --debug-no-chain-validation --import certs/$1.crt
          then 
            set_status setup
        fi
    else
        if ! ${GPGSM} -q --import certs/$1.crt; then 
            set_status setup
        fi
    fi
}

need_crl () {
    # CRL are not yet implemented
    #set_status setup
    :
}



set -e

pass_count=0
fail_count=0
skip_count=0
unresolved_count=0
first_section_set=""
section_out=""
test_status=none

# User settable variables
section=""
description=""


#trap cleanup SIGHUP SIGINT SIGQUIT
[ -z "$debug" ] && exec 2> ${pgmname}.log

:
# end
