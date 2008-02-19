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
export LANG=C
export LANGUAGE=C
export LC_ALL=C


[ "$VERBOSE" = yes ] && set -x
[ -z "$srcdir" ] && srcdir="."
[ -z "$top_srcdir" ] && top_srcdir=".."
[ -z "$GPGSM" ] && GPGSM="../../sm/gpgsm"
[ -z "$silent" ] && silent=no

if [ "$GNUPGHOME" != "`pwd`" ]; then
    echo "inittests: please set GNUPGHOME to the tests/pkits directory" >&2
    exit 1
fi

if [ -n "$GPG_AGENT_INFO" ]; then
    echo "inittests: please unset GPG_AGENT_INFO" >&2
    exit 1
fi

if [ -f PKITS_data.tar.bz2 ]; then
  :
else
    # Exit code 77 is used by the makefile for skipping a tests.
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
        [ -n "$description" ] && echo_n " ($description)"
        echo
    fi
}

fail () {
    setup_output
    echo "FAIL: " $* >&2
    fail_count=`expr ${fail_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out FAIL"
        [ -n "$description" ] && echo_n " ($description)"
        echo
    fi
}

unresolved () {
    setup_output
    echo "UNRESOLVED: " $* >&2
    unresolved_count=`expr ${unresolved_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out UNRESOLVED"
        [ -n "$description" ] && echo_n " ($description)"
        echo
    fi
}

unsupported () {
    setup_output
    echo "UNSUPPORTED: " $* >&2
    unsupported_count=`expr ${unsupported_count} + 1`
    if [ "$silent" != "yes" ]; then
        echo_n "$section_out UNSUPPORTED"
        [ -n "$description" ] && echo_n " ($description)"
        echo
    fi
}


final_result () {
    section=$first_section_set
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
first_section_set=""
section_out=""
section=""
description=""

#trap cleanup SIGHUP SIGINT SIGQUIT
exec 2> ${pgmname}.log

:
# end
