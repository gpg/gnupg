                       The GNU Privacy Guard 2
                      =========================
                             Version 2.0

   Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004,
             2005, 2006, 2007, 2008, 2009, 2010, 2011,
             2012, 2013 Free Software Foundation, Inc.


INTRODUCTION
============

GnuPG is GNU's tool for secure communication and data storage.  It can
be used to encrypt data and to create digital signatures.  It includes
an advanced key management facility and is compliant with the proposed
OpenPGP Internet standard as described in RFC4880 and the S/MIME
standard as described by several RFCs.

GnuPG is distributed under the terms of the GNU General Public
License.  See the file COPYING for details.  GnuPG works best on
GNU/Linux or *BSD systems.  Most other Unices are also supported but
are not as well tested as the Free Unices.

GnuPG 2.0 is the stable version of GnuPG integrating support for
OpenPGP and S/MIME.  It does not conflict with an installed 1.4
OpenPGP-only version.



BUILD INSTRUCTIONS
==================

GnuPG 2.0 depends on the following packages:

  libgpg-error     (ftp://ftp.gnupg.org/gcrypt/libgpg-error/)
  libgcrypt        (ftp://ftp.gnupg.org/gcrypt/libgcrypt/)
  libksba          (ftp://ftp.gnupg.org/gcrypt/libksba/)
  libassuan >= 2.0 (ftp://ftp.gnupg.org/gcrypt/libassuan/)

You also need the Pinentry package for most function of GnuPG; however
it is not a build requirement.  Pinentry is available at
ftp://ftp.gnupg.org/gcrypt/pinentry/ .

You should get the latest versions of course, the GnuPG configure
script complains if a version is not sufficient.

After building and installing the above packages in the order as given
above, you may now continue with GnuPG installation (you may also just
try to build GnuPG to see whether your already installed versions are
sufficient).

As with all packages, you just have to do

 ./configure
 make
 make install

(Before doing install you might need to become root.)

If everything succeeds, you have a working GnuPG with support for
S/MIME and smartcards.  Note that there is no binary gpg but a gpg2 so
that this package won't conflict with a GnuPG 1.4 installation.  gpg2
behaves just like gpg.

In case of problem please ask on gnupg-users@gnupg.org for advise.

Note that the PKITS tests are always skipped unless you copy the PKITS
test data file into the tests/pkits directory.


INCOMPATIBLE CHANGES
====================

- With 2.0.20 the scdaemon option 'disable-keypad' has been renamed to
  'disable-pinpad'.  If you are using this option in scdaemon.conf you
  should rename it there.  In case you are using this option to work
  around a problem with your card reader, you may want to test whether
  this version of GnuPG works better with your reader.


DOCUMENTATION
=============

The complete documentation is in the texinfo manual named
`gnupg.info'.  Run "info gnupg" to read it.  If you want a a printable
copy of the manual, change to the "doc" directory and enter "make pdf"
For a HTML version enter "make html" and point your browser to
gnupg.html/index.html.  Standard man pages for all components are
provided as well.  An online version of the manual is available at
http://www.gnupg.org/documentation/manuals/gnupg/ .  A version of the
manual pertaining to the current development snapshot is at
http://www.gnupg.org/documentation/manuals/gnupg-devel/ .


GNUPG 1.4 AND GNUPG 2.0
=======================

GnuPG 2.0 is a newer version of GnuPG with additional support for
S/MIME.  It has a different design philosophy that splits
functionality up into several modules.  Both versions may be installed
simultaneously without any conflict (gpg is called gpg2 in GnuPG 2).
In fact, the gpg version from GnuPG 1.4 is able to make use of the
gpg-agent as included in GnuPG 2 and allows for seamless passphrase
caching.  The advantage of GnuPG 1.4 is its smaller size and no
dependency on other modules at run and build time.


HOW TO GET MORE INFORMATION
===========================

The primary WWW page is "http://www.gnupg.org"
The primary FTP site is "ftp://ftp.gnupg.org/gcrypt/"

See http://www.gnupg.org/download/mirrors.html for a list of mirrors
and use them if possible.  You may also find GnuPG mirrored on some of
the regular GNU mirrors.

We have some mailing lists dedicated to GnuPG:

   gnupg-announce@gnupg.org   For important announcements like new
                              versions and such stuff.  This is a
                              moderated list and has very low traffic.
                              Do not post to this list.

   gnupg-users@gnupg.org      For general user discussion and
                              help (English).

   gnupg-de@gnupg.org         German speaking counterpart of
                              gnupg-users.

   gnupg-ru@gnupg.org         Russian speaking counterpart of
                              gnupg-users.

   gnupg-devel@gnupg.org      GnuPG developers main forum.

You subscribe to one of the list by sending mail with a subject of
"subscribe" to x-request@gnupg.org, where x is the name of the mailing
list (gnupg-announce, gnupg-users, etc.).  An archive of the mailing
lists is available at <http://www.gnupg.org/documentation/mailing-lists.html>.

Please direct bug reports to http://bugs.gnupg.org or post them direct
to the mailing list <gnupg-devel@gnupg.org>.

Please direct questions about GnuPG to the users mailing list or one
of the pgp newsgroups; please do not direct questions to one of the
authors directly as we are busy working on improvements and bug fixes.
The English and German mailing lists are watched by the authors and we
try to answer questions when time allows us to do so.

Commercial grade support for GnuPG is available; please see
<http://www.gnupg.org/service.html>.


  This file is Free Software; as a special exception the authors gives
  unlimited permission to copy and/or distribute it, with or without
  modifications, as long as this notice is preserved. For conditions
  of the whole package, please see the file COPYING.  This file is
  distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY, to the extent permitted by law; without even the implied
  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

