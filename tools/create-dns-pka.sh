#!/bin/bash

## Unsure why this offset is needed and present in make-dns-cert
TOTAL_LENGTH=6

function usage {
	echo "Usage: "$0" -f [fingerprint of a key in your keyring] -u [url where to fetch the key from]"
	echo "Example: create-dns-pka.sh -f 0BE0E990E02DF48CE0A1F199530843F3420AC0D3 -u https://bobdomain.com/gpg/bobkey.pub"
	echo "Will return : mzbi7kpidyqxg7gzxmpyf7b8n52fmm1n._pka   TYPE37  \# 67 0006 0000 00 14 0CE0E980E01DF48CE0B1F199540843F3420AD0D3 68747470733a2f2f3230303031332e6e65742f6770672f6c756340323030
4031332e6e65742e707562 "
	echo '   -f   fingerprint of a gpg key already imported in your local keyring.'
	echo '   -u   the url that points to your public key'
        exit 1
}

while getopts "f:u:" opt; do
  case $opt in
    f)
      FINGERPRINT=${OPTARG}
      ;;
    u)
      URL=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "$FINGERPRINT" ] || [[ "$FINGERPRINT" == "?" ]] || [ -z "$URL" ] || [[ "$URL" == "?" ]]
  then 
    usage
else
  Z_BASE32_SHA1=$(gpg --list-keys --with-wkd-hash ${FINGERPRINT} | grep -E -v "^pub|^uid|^sub" | grep "@" | sed s/\ //g | awk -F'@' '{print $1}')
fi

LENGTH_FINGERPRINT=${#FINGERPRINT}
HEX_LENGTH_FINGERPRINT=$(printf '%x' $LENGTH_FINGERPRINT)
HEX_LENGTH_FINGERPRINT_BY_TWO=$((HEX_LENGTH_FINGERPRINT/2))
TOTAL_LENGTH=$((${TOTAL_LENGTH}+$((${#FINGERPRINT}/2))+${#URL}))
HEX_URL=$(echo -n ${URL} | xxd -p | awk '{ print toupper($0) }')

printf "${Z_BASE32_SHA1}._pka\tTYPE37\t\# ${TOTAL_LENGTH} 0006 0000 00 ${HEX_LENGTH_FINGERPRINT_BY_TWO} ${FINGERPRINT} $(echo ${HEX_URL} | sed s/\ //g)\n"
