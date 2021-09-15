#!/bin/sh
# Copyright (C) 2021 g10 Code GmbH
#
# Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>
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
# along with this program; if not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0+

set -e

# Needed for below HACK
sourcedir=$(cd $(dirname $0)/..; pwd)

tag_or_branch=gnupg-2.2.30
buildroot=$(mktemp -d --tmpdir gnupg-appimage.XXXXXXXXXX)
echo Using ${buildroot}

cd ${buildroot}

git clone -b ${tag_or_branch} https://dev.gnupg.org/source/gnupg

# run autogen.sh outside of the container because automake in Centos 7 is too old
cd gnupg
./autogen.sh
# download swdb.lst outside of the container because gpgv in Centos 7 is too old
# to verify the signature
build-aux/getswdb.sh

# HACK copy appimage.desktop to make it available in the Docker container
mkdir -p ${buildroot}/gnupg/appimage
cp ${sourcedir}/appimage/appimage.desktop ${buildroot}/gnupg/appimage
# HACK replace with speedo.mk that supports appimage
cp ${sourcedir}/build-aux/speedo.mk ${buildroot}/gnupg/build-aux
# HACK copy patch to make it available in the Docker container
cp ${sourcedir}/appimage/0001-qt-Support-building-with-Qt-5.9.patch ${buildroot}/gnupg

cd ${buildroot}
mkdir -p build

# run the build-appimage.sh script in the Docker container to build the sources
# using CentOS 7; run the container with the same user/group as the current
# user to ensure that all files created inside the container are writeable
# by the current user
docker run -it --rm --user "$(id -u):$(id -g)" \
    --volume ${buildroot}/gnupg:/src \
    --volume ${buildroot}/build:/build \
    g10-build-appimage-gnupg:centos7 \
    /build-appimage.sh

echo The AppImage should now be available at ${buildroot}/build:
ls ${buildroot}/build/*.AppImage
