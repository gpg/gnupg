#!/bin/sh
# Get the online version of the GnuPG software version database
# Copyright (C) 2014  Werner Koch
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# The URL of the file to retrieve.
urlbase="https://versions.gnupg.org/"

WGET=wget
GPGV=gpgv

srcdir=$(dirname "$0")
distsigkey="$srcdir/../g10/distsigkey.gpg"

# Convert a 3 part version number it a numeric value.
cvtver () {
  awk 'NR==1 {split($NF,A,".");X=1000000*A[1]+1000*A[2]+A[3];print X;exit 0}'
}

# Prints usage information.
usage()
{
    cat <<EOF
Usage: $(basename $0) [OPTIONS] [packages]
Get the online version of the GnuPG software version database
and optionally download packages and verify their signatures.

Options:
    --info             Print only infos about packages
    --skip-download    Assume download has already been done.
    --skip-verify      Do not check signatures
    --skip-selfcheck   Do not check GnuPG version
                       (default if not used in the GnuPG tree)
    --find-sha1sum     Print the name of the sha1sum utility
    --find-sha256sum   Print the name of the sha256sum utility
    --help             Print this help.

Example:

  getswdb.sh gnupg24 gpgme libksba libassuan

EOF
    exit $1
}

#
# Parse options
#
skip_download=no
skip_verify=no
skip_selfcheck=no
find_sha1sum=no
find_sha256sum=no
info_mode=no
packages=
die=no
while test $# -gt 0; do
    case "$1" in
	# Set up `optarg'.
	--*=*)
	    optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'`
	    ;;
	*)
	    optarg=""
	    ;;
    esac

    case $1 in
        --help|-h)
	    usage 0
	    ;;
        --skip-download)
            skip_download=yes
            ;;
        --skip-verify)
            skip_verify=yes
            ;;
        --skip-selfcheck)
            skip_selfcheck=yes
            ;;
        --find-sha1sum)
            find_sha1sum=yes
            ;;
        --find-sha256sum)
            find_sha256sum=yes
            ;;
        --info)
            info_mode=yes
            ;;
	--*)
	    usage 1 1>&2
	    ;;
        *)
            packages="$packages $1"
            ;;
    esac
    shift
done


# Mac OSX has only a shasum and not sha1sum
if [ ${find_sha1sum} = yes ]; then
    for i in sha1sum shasum ; do
       tmp=$($i </dev/null 2>/dev/null | cut -d ' ' -f1)
       if [ x"$tmp" = x"da39a3ee5e6b4b0d3255bfef95601890afd80709" ]; then
           echo "$i"
           exit 0
       fi
    done
    echo "false"
    exit 1
fi

# Mac OSX has only a shasum and not sha256sum
if [ ${find_sha256sum} = yes ]; then
    for i in 'shasum -a 256' sha256sum ; do
       tmp=$($i </dev/null 2>/dev/null | cut -d ' ' -f1)
       tmp2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
       if [ x"$tmp" = x"$tmp2" ]; then
           echo "$i"
           exit 0
       fi
    done
    echo "false"
    exit 1
fi


if [ $skip_verify = no ]; then
  if [ ! -f "$distsigkey" ]; then
     distsigkey="/usr/local/share/gnupg/distsigkey.gpg"
     if [ ! -f "$distsigkey" ]; then
       distsigkey="/usr/share/gnupg/distsigkey.gpg"
       if [ ! -f "$distsigkey" ]; then
         echo "no keyring with release keys found!" >&2
         exit 1
       fi
     fi
     echo "using release keys from $distsigkey" >&2
     skip_selfcheck=yes
  fi
fi


# Get GnuPG version from VERSION file.  For a GIT checkout this means
# that ./autogen.sh must have been run first.  For a regular tarball
# VERSION is always available.
if [ $skip_selfcheck = no ]; then
  if [ ! -f "$srcdir/../VERSION" ]; then
    echo "VERSION file missing - run autogen.sh first." >&2
    exit 1
   fi
  version=$(cat "$srcdir/../VERSION")
else
  version="0.0.0"
fi
version_num=$(echo "$version" | cvtver)


if [ $skip_verify = no ]; then
  if ! $GPGV --version >/dev/null 2>/dev/null ; then
    echo "command \"gpgv\" is not installed" >&2
    echo "(please install an older version of GnuPG)" >&2
    exit 1
  fi
fi

#
# Download the list and verify.
#
if [ $skip_download = yes ]; then
  if [ ! -f swdb.lst ]; then
      echo "swdb.lst is missing." >&2
      exit 1
  fi
  if [ $skip_verify = no ]; then
    if [ ! -f swdb.lst.sig ]; then
      echo "swdb.lst.sig is missing." >&2
      exit 1
    fi
  fi
else
  if ! $WGET --version >/dev/null 2>/dev/null ; then
      echo "command \"wget\" is not installed" >&2
      exit 1
  fi

  if ! $WGET -q -O swdb.lst "$urlbase/swdb.lst" ; then
      echo "download of swdb.lst failed." >&2
      exit 1
  fi
  if [ $skip_verify = no ]; then
    if ! $WGET -q -O swdb.lst.sig "$urlbase/swdb.lst.sig" ; then
      echo "download of swdb.lst.sig failed." >&2
      exit 1
    fi
  fi
fi
if [ $skip_verify = no ]; then
  if ! $GPGV --keyring "$distsigkey" swdb.lst.sig swdb.lst 2>/dev/null; then
    echo "list of software versions is not valid!" >&2
    exit 1
  fi
fi

#
# Check that the online version of GnuPG is not less than this version
# to help detect rollback attacks.
#
if [ $skip_selfcheck = no ]; then
  gnupg_ver=$(awk '$1=="gnupg24_ver" {print $2;exit}' swdb.lst)
  if [ -z "$gnupg_ver" ]; then
      echo "GnuPG 2.4 version info missing in swdb.lst!" >&2
      exit 1
  fi
  gnupg_ver_num=$(echo "$gnupg_ver" | cvtver)
  if [ $(( $gnupg_ver_num >= $version_num )) = 0 ]; then
      echo "GnuPG version in swdb.lst is less than this version!" >&2
      echo "  This version: $version" >&2
      echo "  SWDB version: $gnupg_ver" >&2
      exit 1
  fi
fi


# Download a package and check its signature.
download_pkg () {
    local url="$1"
    local file="${url##*/}"

    if ! $WGET -q -O -  "$url" >"${file}.tmp" ; then
      echo "download of $file failed." >&2
      [ -f "${file}.tmp" ] && rm "${file}.tmp"
      return 1
    fi
    if [ $skip_verify = no ]; then
        if ! $WGET -q -O - "${url}.sig" >"${file}.tmpsig" ; then
            echo "download of $file.sig failed." >&2
            [ -f "${file}.tmpsig" ] && rm "${file}.tmpsig"
            return 1
        fi
        if ! $GPGV -q --keyring "$distsigkey" \
             "${file}.tmpsig" "${file}.tmp" 2>/dev/null;  then
           echo "signature of $file is not valid!" >&2
           return 1
        fi
        mv "${file}.tmpsig" "${file}.sig"
    else
        [ -f "${file}.sig" ] && rm "${file}.sig"
    fi
    mv "${file}.tmp" "${file}"
    return 0
}



baseurl=$(awk '$1=="gpgorg_base" {print $2; exit 0}' swdb.lst)
for p in $packages; do
    pver=$(awk '$1=="'"$p"'_ver" {print $2}' swdb.lst)
    if [ -z "$pver" ]; then
        echo "package '$p' not found" >&2
        die=yes
    else
        pdir=$(awk '$1=="'"$p"'_dir" {print $2":"$3":"$4}' swdb.lst)
        if [ -n "$pdir" ]; then
            psuf=$(echo "$pdir" | cut -d: -f3)
            pname=$(echo "$pdir" | cut -d: -f2)
            pdir=$(echo "$pdir" | cut -d: -f1)
        else
            psuf=
            pdir="$p"
            pname="$p"
        fi
        if [ -z "$psuf" ]; then
            psuf=$(awk 'BEGIN {suf="bz2"};
                    $1=="'"$p"'_sha1_gz" {suf="gz"; exit 0};
                    $1=="'"$p"'_sha1_xz" {suf"xz"; exit 0};
                    END {print suf}' swdb.lst)
        fi
        pfullname="$pname-$pver.tar.$psuf"
        if [ $info_mode = yes ]; then
            echo "$baseurl/$pdir/$pfullname"
        else
            echo "downloading $pfullname"
            download_pkg "$baseurl/$pdir/$pfullname" || die=yes
        fi
    fi
done
if [ $die = yes ]; then
    echo "errors found!" >&2
    exit 1
fi
exit 0
