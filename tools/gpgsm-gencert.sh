#!/bin/sh
#                                                              -*- sh -*-
# gpgsm-gencert.c - Generate X.509 certificates through GPGSM.  
#	Copyright (C) 2004 Free Software Foundation, Inc.
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

set -e

ASSUAN_FP_IN=4
ASSUAN_FP_OUT=5

ASSUAN_COMMANDS="\
INPUT FD=$ASSUAN_FP_IN\n\
OUTPUT FD=$ASSUAN_FP_OUT --armor\n\
GENKEY\n\
BYE"

ANSWER=""

query_user()
{
    message=$1; shift
    
    echo "$message" >&2
    echo -n "> " >&2
    read answer

    ANSWER=$answer;
}

query_user_menu()
{
    message=$1; shift
    i=0
    
    echo "$message" >&2
    for choice in "$@"; do
	i=$(expr $i + 1)
	echo " [$i] $choice" >&2
    done

    while true; do
	j=1
	echo -n "Your selection: " >&2
	read idx

	while [ $j -lt $i -o $j -eq $i ]; do
	    if [ "$idx" = $j ]; then
		break
	    fi
	    j=$(expr $j + 1)
	done
	if [ $j -lt $i -o $j -eq $i ]; then
	    break
	fi
    done

    i=0
    for choice in "$@"; do
	i=$(expr $i + 1)
	if [ $i -eq $idx ]; then
	    ANSWER=$1
	    break;
	fi
	shift
    done
    
    echo "You selected: $ANSWER" >&2
}

query_user_menu "Key type" "RSA"
KEY_TYPE=$ANSWER

query_user_menu "Key length" "1024" "2048"
KEY_LENGTH=$ANSWER

query_user_menu "Key usage" "sign, encrypt" "sign" "encrypt"
KEY_USAGE=$ANSWER

query_user "Name"
NAME=$ANSWER

query_user "E-Mail address"
EMAIL_ADDRESS=$ANSWER

file_parameter=$(mktemp "/tmp/gpgsm.XXXXXX")
outfile=$(mktemp "/tmp/gpgsm.XXXXXX")

cat > "$file_parameter" <<EOF
Key-Type: $KEY_TYPE
Key-Length: $KEY_LENGTH
Key-Usage: $KEY_USAGE
Name-DN: $NAME
Name-Email: $EMAIL_ADDRESS
EOF

echo -e "$ASSUAN_COMMANDS" | \
   gpgsm --server 4< "$file_parameter" 5>"$outfile" >/dev/null

cat "$outfile"

rm "$file_parameter" "$outfile"
exit 0
