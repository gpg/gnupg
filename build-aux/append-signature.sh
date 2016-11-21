#!/bin/sh
# Append a signature to an existing detached signature.
# Copyright (C) 2016 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

set -e
PGM="$(basename $0)"
GPGV=gpgv

# Prints usage information.
usage()
{
    cat <<EOF
Usage: $PGM TARBALL NEWSIGNATURE
Append a signature to an existing detached signature.
Options:
    --verbose          Print some extra information.
    --help             Print this help.
EOF
    exit $1
}

#
# Parse options
#
verbose=""
while [ $# -gt 0 ]; do
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
        --verbose|-v)
            verbose="-v"
            ;;
        --)
            break
            ;;
	-*)
	    usage 1 1>&2
	    ;;
        *)
            break;
            ;;
    esac
    shift
done

if [ $# -ne 2 ]; then
    usage 1 1>&2
fi
tarball="$1"
tarballsig="$1".sig
newsig="$2"

[ -n "$verbose" ] && echo "tarball: $tarball"
[ -n "$verbose" ] && echo "sig ...: $tarballsig"
[ -n "$verbose" ] && echo "newsig : $newsig"

if ! $GPGV --version >/dev/null 2>/dev/null ; then
    echo "${PGM}: Command \"gpgv\" is not installed" >&2
    exit 1
fi

distsigkey="/usr/local/share/gnupg/distsigkey.gpg"
if [ ! -f "$distsigkey" ]; then
    distsigkey="/usr/share/gnupg/distsigkey.gpg"
fi
if [ ! -f "$distsigkey" ]; then
    echo "${PGM}: File \"$distsigkey\" is not installed" >&2
    exit 1
fi

if ! $GPGV $verbose --keyring "$distsigkey" \
           -- "$tarballsig" "$tarball" 2>/dev/null ; then
    echo "${PGM}: Existing signature '$tarballsig' does not verify" >&2
    exit 1
fi

if ! $GPGV $verbose --keyring "$distsigkey" \
           -- "$newsig" "$tarball" 2>/dev/null; then
    echo "${PGM}: New signature '$newsig' does not verify" >&2
    exit 1
fi

cat "$newsig" >> "$tarballsig"

if ! $GPGV $verbose --keyring "$distsigkey" \
           -- "$tarballsig" "$tarball"; then
    echo "${PGM}: Update signature '$tarballsig' does not verify" >&2
    exit 1
fi
