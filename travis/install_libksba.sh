#!/usr/bin/env bash

TOP_DIR=$(pwd)

cd "${HOME}" || exit 1

if ! git clone --depth=1 \
     https://github.com/gpg/libksba.git;
then
    echo "Failed to clone libksba"
    exit 1
fi

cd libksba || exit 1

if ! ./autogen.sh;
then
    echo "Failed to bootstrap libksba"
    exit 1
fi

# Required per README.git
if ! ./configure --enable-maintainer-mode;
then
    echo "Failed to configure libksba"
    cat config.log
    exit 1
fi

if ! make -j 3;
then
    echo "Failed to build libksba"
    exit 1
fi

if ! make check;
then
    echo "Failed to test libksba"
    exit 1
fi

if ! sudo make install;
then
    echo "Failed to install libksba"
    exit 1
fi

cd "${TOP_DIR}" || exit 1

exit 0
