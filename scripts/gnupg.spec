#
# gnupg -- gnu privacy guard
# This is a template.  The dist target uses it to create the real file.
#
Summary: GPL public key crypto
Name: gnupg
Version: @pkg_version@
Release: 3
Copyright: GPL
Group: Applications/Cryptography
Source: ftp://ftp.guug.de/pub/gcrypt/
URL: http://www.d.shuttle.de/isil/crypt/gnupg.html
Vendor: TechnoCage
Packager: Caskey L. Dickson <caskey-at-technocage.com>
Provides: gpg openpgp

%description
GNUPG is a complete and free replacement for PGP. Because it does not use
IDEA or RSA it can be used without any restrictions. GNUPG is nearly in
compliance with the OpenPGP draft.

%prep
rm -rf $RPM_BUILD_DIR/gnupg-@pkg_version@
tar -xvzf $RPM_SOURCE_DIR/gnupg-@pkg_version@.tar.gz

%build
cd gnupg-@pkg_version@
chown -R root.root *
./configure
make

%install
cd gnupg-@pkg_version@
make install
chmod +s /usr/local/bin/gpg
chmod +s /usr/local/bin/gpgm

%files
%doc gnupg-@pkg_version@/doc/DETAILS
%doc gnupg-@pkg_version@/INSTALL
%doc gnupg-@pkg_version@/doc/rfcs
%doc gnupg-@pkg_version@/AUTHORS
%doc gnupg-@pkg_version@/ABOUT-NLS
%doc gnupg-@pkg_version@/COPYING
%doc gnupg-@pkg_version@/ChangeLog
%doc gnupg-@pkg_version@/NEWS
%doc gnupg-@pkg_version@/README
%doc gnupg-@pkg_version@/THANKS
%doc gnupg-@pkg_version@/TODO
/usr/local/man/man1/gpg.1
/usr/local/bin/gpg
/usr/local/bin/gpgm
/usr/local/share/locale/en/LC_MESSAGES/gnupg.mo
/usr/local/share/locale/de/LC_MESSAGES/gnupg.mo
/usr/local/share/locale/it/LC_MESSAGES/gnupg.mo
/usr/local/share/locale/fr/LC_MESSAGES/gnupg.mo
/usr/local/lib/gnupg/tiger
/usr/local/lib/gnupg/twofish

