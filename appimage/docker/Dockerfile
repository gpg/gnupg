# Dockerfile - appimage/docker
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

FROM centos:7

# Import the CentOS 7 package signing key after verifying its fingerprint.
# Then add the software collections repository from the CentOS SCLo SIG and
# import its package signing key after verifying the fingerprint.

RUN test $(gpg --with-colons --with-fingerprint < /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 | grep ^pub: | wc -l) = 1 \
    && gpg --with-colons --with-fingerprint < /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 | grep -q ^fpr:::::::::6341AB2753D78A78A7C27BB124C6A8A7F4A80EB5 \
    && rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 \
    && yum -y update \
    && yum -y install \
        centos-release-scl \
    && test $(gpg --with-colons --with-fingerprint < /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-SCLo | grep ^pub: | wc -l) = 1 \
    && gpg --with-colons --with-fingerprint < /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-SCLo | grep -q ^fpr:::::::::C4DBD535B1FBBA14F8BA64A84EB84E71F2EE9D55 \
    && rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-SCLo \
    && yum -y update

RUN yum -y install \
        automake \
        bzip2 \
        devtoolset-7-binutils \
        devtoolset-7-gcc \
        devtoolset-7-gcc-c++ \
        devtoolset-7-make \
        file \
        gnutls-devel \
        openldap-devel \
        qt5-qtbase-devel \
        readline-devel \
        sqlite-devel \
        wget

# Install patch; this is needed for a temporary HACK
RUN yum -y install \
        patch

COPY build-appimage.sh /

RUN chmod +x build-appimage.sh
