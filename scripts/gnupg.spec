#
# gnupg -- gnu privacy guard
# This is a template.  The dist target uses it to create the real file.
#
%define version @pkg_version@
%define name gnupg
Summary: GPL public key crypto
Name: %{name}
Version: %{version}
Release: 1
Copyright: GPL
Group: Applications/Cryptography
Source: ftp://ftp.gnupg.org/pub/gcrypt/%{name}-%{version}.tar.gz
URL: http://www.gnupg.org
Provides: gpg openpgp
BuildRoot: /tmp/rpmbuild_%{name}

%changelog
* Sat Jan 02 1999 Fabio Coatti <cova@felix.unife.it>
- Added pl language file.
- Included g10/pubring.asc in documentation files.

* Sat Dec 19 1998 Fabio Coatti <cova@felix.unife.it>
- Modified the spec file provided by Caskey L. Dickson <caskey-at-technocage.com>
- Now it can be built also by non-root. Installation has to be done as
root, gpg is suid.
- Added some changes by  Ross Golder <rossigee@bigfoot.com>
- Updates for version 0.4.5 of GnuPG (.mo files)

%description
GnuPG is a complete and free replacement for PGP. Because it does not
use IDEA or RSA it can be used without any restrictions. GnuPG is in
compliance with the OpenPGP specification (RFC2440).

%description -l it
GnuPG è un sostituto completo e gratuito per il PGP. Non utilizzando
IDEA o RSA può essere utilizzato senza restrizioni. GnuPG è conforme
alle specifiche OpenPGP (RFC2440).

%prep
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%setup

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr
make

%install
make install-strip prefix=$RPM_BUILD_ROOT/usr
rm $RPM_BUILD_ROOT/usr/man/man1/gpgm.1
cd $RPM_BUILD_ROOT/usr/man/man1/
ln -s gpg.1 gpgm.1

%files

%doc %attr (-,root,root) INSTALL
%doc %attr (-,root,root) AUTHORS
%doc %attr (-,root,root) COPYING
%doc %attr (-,root,root) ChangeLog
%doc %attr (-,root,root) NEWS
%doc %attr (-,root,root) README
%doc %attr (-,root,root) THANKS
%doc %attr (-,root,root) TODO
%doc %attr (-,root,root) doc/DETAILS
%doc %attr (-,root,root) doc/FAQ
%doc %attr (-,root,root) doc/HACKING
%doc %attr (-,root,root) doc/OpenPGP
%doc %attr (-,root,root) g10/pubring.asc

%attr (-,root,root) /usr/man/man1/gpg.1
%attr (-,root,root) /usr/man/man1/gpgm.1
%attr (4755,root,root) /usr/bin/gpg
%attr (755,root,root) /usr/bin/gpgm

%attr (-,root,root) /usr/share/locale/de/LC_MESSAGES/%{name}.mo
%attr (-,root,root) /usr/share/locale/it/LC_MESSAGES/%{name}.mo
%attr (-,root,root) /usr/share/locale/fr/LC_MESSAGES/%{name}.mo
%attr (-,root,root) /usr/share/locale/ru/LC_MESSAGES/%{name}.mo
%attr (-,root,root) /usr/share/locale/es_ES/LC_MESSAGES/%{name}.mo
%attr (-,root,root) /usr/share/locale/pt_BR/LC_MESSAGES/%{name}.mo
%attr (-,root,root) /usr/share/locale/pl/LC_MESSAGES/%{name}.mo


%attr (-,root,root) /usr/lib/%{name}
%attr (-,root,root) /usr/share/%{name}

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}
