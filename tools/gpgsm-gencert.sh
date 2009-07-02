#!/bin/sh
#                                                              -*- sh -*-
# gpgsm-gencert.c - Generate X.509 certificates through GPGSM.  
#	Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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

set -e

ASSUAN_FP_IN=4
ASSUAN_FP_OUT=5

ASSUAN_COMMANDS="\
INPUT FD=$ASSUAN_FP_IN\n\
OUTPUT FD=$ASSUAN_FP_OUT --armor\n\
GENKEY\n\
BYE\n"

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


echo "WARNING: This script is deprecated; please use" >&2
echo "           gpgsm --gen-key" >&2
echo "         instead." >&2
KEY_TYPE=""
while [ -z "$KEY_TYPE" ]; do
  query_user_menu "Key type" "RSA" "Existing key" "Direct from card"
  case "$ANSWER" in
    RSA)
      KEY_TYPE=$ANSWER
      query_user_menu "Key length" "1024" "2048"
      KEY_LENGTH=$ANSWER
      KEY_GRIP=
      ;;
    Existing*)
      # User requested to use an existing key; need to set some dummy defaults
      query_user "Keygrip "
      if [ -n "$ANSWER" ]; then
        KEY_TYPE=RSA 
        KEY_LENGTH=1024
        KEY_GRIP=$ANSWER
      fi
      ;;
    Direct*)
      tmp=$(echo 'SCD SERIALNO' | gpg-connect-agent | \
            awk '$2 == "SERIALNO" {print $3}') 
      if [ -z "$tmp" ]; then
          echo "No card found" >&2
      else
        echo "Card with S/N $tmp found" >&2
        tmp=$(echo 'SCD LEARN --force' | gpg-connect-agent | \
              awk '$2 == "KEYPAIRINFO" {printf " %s", $4}')
        sshid=$(echo 'SCD GETATTR $AUTHKEYID' | gpg-connect-agent | \
                awk '$2 == "$AUTHKEYID" {print $3}') 
        [ -n "$sshid" ] && echo "gpg-agent uses $sshid as ssh key" >&2
        query_user_menu "Select key " $tmp "back"
        if [ "$ANSWER" != "back" ]; then
          KEY_TYPE="card:$ANSWER"
          KEY_LENGTH=
          KEY_GRIP=
        fi
      fi
      ;;
    *)
      exit 1
      ;;   
  esac
done

query_user_menu "Key usage" "sign, encrypt" "sign" "encrypt"
KEY_USAGE=$ANSWER

query_user "Name (DN)"
NAME=$ANSWER

EMAIL_ADDRESSES=
LF=
while : ; do
  query_user "E-Mail addresses (end with an empty line)"
  [ -z "$ANSWER" ] && break
  EMAIL_ADDRESSES="${EMAIL_ADDRESSES}${LF}Name-Email: $ANSWER"
  LF='
'
done

DNS_ADDRESSES=
LF=
while : ; do
  query_user "DNS Names (optional; end with an empty line)"
  [ -z "$ANSWER" ] && break
  DNS_ADDRESSES="${DNS_ADDRESSES}${LF}Name-DNS: $ANSWER"
  LF='
'
done

URI_ADDRESSES=
LF=
while : ; do
  query_user "URIs (optional; end with an empty line)"
  [ -z "$ANSWER" ] && break
  URI_ADDRESSES="${URI_ADDRESSES}${LF}Name-URI: $ANSWER"
  LF='
'
done

file_parameter=$(mktemp "/tmp/gpgsm.XXXXXX")
outfile=$(mktemp "/tmp/gpgsm.XXXXXX")


(
cat <<EOF
Key-Type: $KEY_TYPE
Key-Length: $KEY_LENGTH
Key-Usage: $KEY_USAGE
Name-DN: $NAME
EOF
[ -n "$KEY_GRIP" ] && echo "Key-Grip: $KEY_GRIP"
[ -n "$EMAIL_ADDRESSES" ] && echo "$EMAIL_ADDRESSES"
[ -n "$DNS_ADDRESSES" ] && echo "$DNS_ADDRESSES"
[ -n "$URI_ADDRESSES" ] && echo "$URI_ADDRESSES"
) > "$file_parameter"


echo 'Parameters for certificate request to create:' >&2
cat -n "$file_parameter" >&2
echo  >&2

query_user_menu "Really create such a CSR?" "yes" "no"
[ "$ANSWER" != "yes" ] && exit 1
    

printf "$ASSUAN_COMMANDS" | \
     gpgsm --no-log-file --debug-level none --debug-none \
           --server 4< "$file_parameter" 5>"$outfile" >/dev/null

cat "$outfile"

rm "$file_parameter" "$outfile"
exit 0
