README.W32                                                -*- text -*-

This is a binary package with GnuPG for MS-Windows NT-4, W2000, XP and
Vista.  A native version for 64 bit is not available.  See the file
README for generic instructions and usage hints.

A FAQ comes with this package and a probably more recent one can be
found online at http://www.gnupg.org/faq.html.  See
http://www.gnupg.org/docs-mls.html for a list of mailing lists. In
particular the list gnupg-users@gnupg.org might be useful to answer
questions - but please read the FAQ first.


Installation directory:
=======================

The installation directory of GnuPG is stored in the Registry under
the key HKEY_LOCAL_MACHINE\Software\GNU\GnuPG with the name "Install
Directory".  The installer does not change the PATH environment
variable to include this directory.  You might want to do this
manually.

Note, that this registry entry is also used to locate the keyserver
helper programs (e.g. gpgkeys_ldap).

Below the Installation directory, you will find directories named
"Doc", "gnupg.nls" and "Src".  The latter will be used for distributed
patched, if any, and to store the source file if they have been
included in this package.  The source files usually require further
unpacking using the TAR utility.


Internationalization support:
=============================

Store the locale id (like "de") into the Registry under the key
HKEY_CURRENT_USER\Software\GNU\GnuPG with the name "Lang".  This must
match one of the installed languages files in the directory named
"gnupg.nls" below the installation directory.  Note, that the ".mo"
extension is not part of the locale id.


Home directory:
===============

GnuPG makes use of a per user home directory to store its keys as well
as configuration files.  The default home directory is a directory
named "gnupg" below the application data directory of the user.  This
directory will be created if it does not exist.  Being only a default,
it may be changed by setting the name of the home directory into the
Registry under the key HKEY_CURRENT_USER\Software\GNU\GnuPG using the
name "HomeDir".  If an environment variable "GNUPGHOME" exists, this
even overrides the registry setting.  The command line option
"--homedir" may be used to override all other settings of the home
directory.


Reporting bugs:
===============

Please check the documentation first before asking or reporting a
bugs.  In particular check the archives of the mailing lists (see
www.gnupg.org) and the bug tracking system at http://bugs.gnupg.org
(login is "guest" password is "guest") whether the problem is already
known.  Asking on the gnupg-users mailing list is also strongly
encouraged; if you are not subscribed it may some time until a posting
is approved (this is an anti-spam measure). Bug reporting addresses
are listed in the file AUTHORS.

If you want to report a bug or have other problems, always give
detailed description of the problem, the version of GnuPG you used,
the version of the OS, whether it is the official version from
gnupg.org or how you built it.  Don't edit error messages - replacing
sensitive information like user IDs, fingerprints and keyids is okay.
If possible, switch to English messages by changing the "Lang" entry
to empty (see under Internationalization support).


How to build GnuPG from the source:
===================================

Until recently all official GnuPG versions have been build using the
Mingw32/CPD kit as available at
ftp://ftp.gnupg.org/people/werner/cpd/mingw32-cqpd-0.3.2.tar.gz .
However, for maintenance reasons we switched to Debian's mingw32 cross
compiler package and that is now the recommended way of building GnuPG
for W32 platforms.  It might be possible to build it nativly on a W32
platform but this is not supported.  Please don't file any bug reports
if it does not build with any other system than the recommended one.

According to the conditions of the GNU General Public License you
either got the source files with this package, a written offer to send
you the source on demand or the source is available at the same site
you downloaded the binary package.  If you downloaded the package from
the official GnuPG site or one of its mirrors, the corresponding
source tarball is available in the sibling directory named gnupg.  The
source used to build all versions is always the same and the version
numbers should match.  If the version number of the binary package has
a letter suffix, you will find a patch file installed in the "Src"
directory with the changes relative to the generic version.

The source is distributed as a BZIP2 or GZIP compressed tar archive.
See the instructions in file README on how to check the integrity of
that file.  Wir a properly setup build environment, you unpack the
tarball change to the created directory and run

 $ ./autogen.sh --build-w32
 $ make
 $ cp g10/gpg*.exe  /some_windows_drive/

Building a version with the installer is a bit more complex and
basically works by creating a top directory, unpacking in that top
directory, switching to the gnupg-1.x.y directory, running
"./autogen.sh --build-w32" and "make", switching back to the top
directory, running a "mkdir dist-w32; mkdir iconv", copying the
required iconv files (iconv.dll, README.iconv, COPYING.LIB) into the
iconv directory, running gnupg-1.x.y/scripts/mk-w32-dist and voila,
the installer package will be available in the dist-w32 directory.


Copying:
========

GnuPG is

  Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004, 
            2005, 2006, 2007 Free Software Foundation, Inc.

  GnuPG is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  GnuPG is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <http://www.gnu.org/licenses/>.


See the files AUTHORS and THANKS for credits, further legal
information and bug reporting addresses pertaining to GnuPG.

For copying conditions of the GNU LIBICONV library see the file
README.iconv.
  
The installer software used to create the official binary packages for
W32 is NSIS (http://nsis.sourceforge.net/):

  Copyright (C) 1999-2005 Nullsoft, Inc.

  This license applies to everything in the NSIS package, except where
  otherwise noted.

  This software is provided 'as-is', without any express or implied
  warranty. In no event will the authors be held liable for any
  damages arising from the use of this software.

  Permission is granted to anyone to use this software for any
  purpose, including commercial applications, and to alter it and
  redistribute it freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must
     not claim that you wrote the original software. If you use this
     software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  2. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  3. This notice may not be removed or altered from any source
     distribution.

The user interface used with the installer is

  Copyright (C) 2002-2005 Joost Verburg

  [It is distributed along with NSIS and the same conditions as stated
  above apply]


The term "W32" is used to describe the API used by current Microsoft
Windows versions.  We don't use the Microsft terminology here; in
hacker terminology, calling something a "win" is a form of praise.
Keep in mind that Windows ist just a temporary workaround until you
can switch to a complete Free Software system.  Be the source always
with you.
