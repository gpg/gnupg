
Compiling GNU Privacy Guard with Microsoft VC++ Version 7.1
-----------------------------------------------------------

This contribution allows GNU Privacy Guard version 1.2.3 to
be compiled using Microsoft VC++ version 7.1 (together with 
the free NASM assembler). To use this version you will need
to download the NASM assembler from:

   http://sourceforge.net/projects/nasm
   
and place it in the 'bin' directory of your Microsoft Visual 
C++ installation (i.e where the VC++ compiler resides).

This version of GNUPG does not support GNU gettext but is 
otherwise complete.  It also uses my AES C code because this 
is a lot faster with VC++ (I also provide NASM assembler code
which is even faster).

To compile this code you need to obtain gnupg-1.2.3.tar.gz
and expand it into a directory tree. This zip file must then
be expanded so that the directory 'conf-win32brg' resides in
the 'scripts' subdirectory of the gnupg directory tree. From
the VC++ IDE the solution file 'conf-w32brg.sln' can then be
opened and the projects built. The resulting executable files:

gpg.exe
ks_hkp.exe   
ks_ldap.exe

are placed in the 'bin' sub-directory of the 'conf-win32brg' 
directory.

  Brian Gladman <brg@brg.me.uk>
