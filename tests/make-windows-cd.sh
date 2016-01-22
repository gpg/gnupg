#!/bin/sh

set -e

if ! [ -f config.log ] || ! grep -q mingw config.log; then
    echo "must be run from a configured windows build environment"
fi

[ -z "$w32root" ] && w32root="$HOME/w32root"
ADDITIONAL_FILES=
IMAGE=gnupg-test.iso

[ -f make-windows-cd.rc ] && . make-windows-cd.rc

# we pick binaries from the prefix, so make sure they are current.
make install

WORKDIR="$(mktemp --directory)"
TARGET="${WORKDIR}/gnupg"

mkdir "$TARGET"

[ "$ADDITIONAL_FILES" ] && cp -v $(ls -1 $ADDITIONAL_FILES) $TARGET
cp -v $w32root/bin/*.exe $w32root/bin/*.dll $TARGET
cp -v tests/gpgscm/*.exe $TARGET
cp -v tools/mk-tdata.exe $TARGET
cp -v agent/gpg-preset-passphrase.exe $TARGET
cp -v -a ../tests $TARGET
cp -v tests/openpgp/fake-pinentry.exe $TARGET/tests/openpgp
cp -v ../tests/run-tests.bat $WORKDIR
genisoimage --output "$IMAGE" -J "$WORKDIR"
[ "${WORKDIR}" ] && rm -rf -- "${WORKDIR}"
