;; README.txt                               -*- coding: latin-1; -*-
;; This is the README installed for Windows.  Lines with a
;; semicolon in the first column are considered a comment and not
;; included in the actually installed version.  Certain keywords are
;; replaced by the Makefile; those words are enclosed by exclamation
;; marks.


                    GNU Privacy Guard for Windows
                   ===============================

This is GnuPG for Windows, version !VERSION!.

Content:

     1. Important notes
     2. Changes
     3. GnuPG README file
     4. Package versions
     5. Legal notices


1. Important Notes
==================

This is the core part of the GnuPG system as used by several other
frontend programs.  This installer does not provide any graphical
frontend and thus almost everything needs to be done on the command
line.  However, a small native Windows GUI tool is included which is
used by GnuPG to ask for passphrases.  It provides only the basic
functionality and is installed under the name "pinentry-basic.exe".
Other software using this core component may install a different
version of such a tool under the name "pinentry.exe" or configure the
gpg-agent to use that version.

See https://gnupg.org for latest news.  HowTo documents and manuals
can be found there but some have also been installed on your machine.

Development and maintenance of GnuPG is mostly financed by donations;
please see https://gnupg.org/donate/ for details.


2. Record of Changes
====================

This is a list of changes to the GnuPG core for this and the previous
release.

!NEWSFILE!


3. GnuPG README File
====================

Below is the README file as distributed with the GnuPG source.

!GNUPGREADME!


4. Software Versions of the Included Packages
=============================================

GnuPG for Windows depends on several independet developed packages
which are part of the installation.  These packages along with their
version numbers and the SHA-1 checksums of their compressed tarballs
are listed here:

!PKG-VERSIONS!


5. Legal Notices Pertaining to the Individual Packages
======================================================

GnuPG for Windows consist of several independent developed packages,
available under different license conditions.  Most of these packages
are however available under the GNU General Public License (GNU GPL).
Common to all is that they are free to use without restrictions, may
be modified and that modifications may be distributed.  If the source
file (i.e. gnupg-w32-VERSION_DATE.tar.xz) is distributed along with
the installer and the use of the GNU GPL has been pointed out,
distribution is in all cases possible.

What follows is a list of copyright statements.

!PKG-COPYRIGHT!


***end of file ***
