#!/bin/sh
# common.sh - common defs for all tests         -*- sh -*-
# Copyright (C) 2004 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
# 
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

# reset some environment variables because we do not want to test locals
export LANG=C
export LANGUAGE=C
export LC_ALL=C


[ "$VERBOSE" = yes ] && set -x
[ -z "$srcdir" ] && srcdir="."
[ -z "$top_srcdir" ] && top_srcdir=".."
[ -z "$GPGSM" ] && GPGSM="../../sm/gpgsm"


if [ "$GNUPGHOME" != "`pwd`" ]; then
    echo "inittests: please set GNUPGHOME to the tests/pkits directory" >&2
    exit 1
fi

if [ -n "$GPG_AGENT_INFO" ]; then
    echo "inittests: please unset GPG_AGENT_INFO" >&2
    exit 1
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

fatal () {
    echo "$pgmname: fatal:" $* >&2
    exit 1;
}

error () {
    echo "$pgmname:" $* >&2
    exit 1
}

info () {
    echo "$pgmname:" $* >&2
}

info_n () {
    $echo_n "$pgmname:" $* >&2
}

pass () {
    echo "PASS: " $* >&2
    pass_count=`expr ${pass_count} + 1`
}

fail () {
    echo "FAIL: " $* >&2
    fail_count=`expr ${fail_count} + 1`
}

unresolved () {
    echo "UNRESOLVED: " $* >&2
    unresolved_count=`expr ${unresolved_count} + 1`
}

unsupported () {
    echo "UNSUPPORTED: " $* >&2
    unsupported_count=`expr ${unsupported_count} + 1`
}


final_result () {
    [ $pass_count = 0 ]        || info "$pass_count tests passed"
    [ $fail_count = 0 ]        || info "$fail_count tests failed"
    [ $unresolved_count = 0 ]  || info "$unresolved_count tests unresolved"
    [ $unsupported_count = 0 ] || info "$unsupported_count tests unsupported"
    if [ $fail_count = 0 ]; then
        info "all tests passed"
    else
        exit 1
    fi
}

set -e

pgmname=`basename $0`

pass_count=0
fail_count=0
unresolved_count=0
unsupported_count=0


#trap cleanup SIGHUP SIGINT SIGQUIT
exec 2> ${pgmname}.log

:
# end
