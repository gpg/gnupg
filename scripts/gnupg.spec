#
# gnupg -- gnu privacy guard
# This is a template.  The dist target uses it to create the real file.
#
%define version @pkg_version@
Summary: GPL public key crypto
Name: gnupg
Version: %{version}
Release: 1
Copyright: GPL
Group: Applications/Cryptography
Source: ftp://ftp.gnupg.org/pub/gcrypt/gnupg-%{version}.tar.gz
URL: http://www.gnupg.org
Provides: gpg openpgp
BuildRoot: /tmp/gnupg

%description
GnuPG is a complete and free replacement for PGP. Because it does not use
IDEA or RSA it can be used without any restrictions. GnuPG is in
compliance with the OpenPGP specification (RFC2440).

%prep
%setup

rm -rf $RPM_BUILD_ROOT

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure  --prefix=/usr
make

%install
make prefix="${RPM_BUILD_ROOT}/usr" install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(-,root,root) %doc doc/DETAILS
%attr(-,root,root) %doc INSTALL
%attr(-,root,root) %doc AUTHORS
%attr(-,root,root) %doc ABOUT-NLS
%attr(-,root,root) %doc COPYING
%attr(-,root,root) %doc ChangeLog
%attr(-,root,root) %doc NEWS
%attr(-,root,root) %doc README
%attr(-,root,root) %doc THANKS
%attr(-,root,root) %doc TODO
%attr(-,root,root) /usr/man/man1/gpg.1
%attr (4755,root,root) /usr/bin/gpg
%attr (755,root,root) /usr/bin/gpgm
%attr(-,root,root) /usr/share/locale/en/LC_MESSAGES/gnupg.mo
%attr(-,root,root) /usr/share/locale/de/LC_MESSAGES/gnupg.mo
%attr(-,root,root) /usr/share/locale/it/LC_MESSAGES/gnupg.mo
%attr(-,root,root) /usr/share/locale/fr/LC_MESSAGES/gnupg.mo
%attr(-,root,root) /usr/lib/gnupg/tiger
%attr(-,root,root) /usr/lib/gnupg/twofish
%attr(-,root,root) /usr/share/gnupg/options.skel

