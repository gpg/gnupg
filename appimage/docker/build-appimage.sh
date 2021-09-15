#!/bin/sh
# Build an AppImage of gpg
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

mkdir -p /build/AppDir
cd /src
source /opt/rh/devtoolset-7/enable

make -f build-aux/speedo.mk INSTALL_PREFIX=/build/AppDir/usr CUSTOM_SWDB=1 appimage

mkdir -p /build/download
cd /build/download
wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
wget https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage
chmod +x linuxdeploy-*
cd /build
# extract the AppImages because we have no fuse in the container
download/linuxdeploy-plugin-qt-x86_64.AppImage --appimage-extract
download/linuxdeploy-x86_64.AppImage --appimage-extract
export PATH=squashfs-root/usr/bin:$PATH
export LD_LIBRARY_PATH=/build/AppDir/usr/lib
linuxdeploy --appdir AppDir --desktop-file /src/appimage/appimage.desktop --icon-file /src/artwork/gnupg-lock-256x256tr.png --icon-filename gpg --plugin qt --output appimage
