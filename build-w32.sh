#!/bin/sh

[ -z "$w32root" ] && w32root="$HOME/w32root"

 ./configure --enable-maintainer-mode --prefix=${w32root}  \
             --host=i586-mingw32msvc --build=`scripts/config.guess` \
             --with-gpg-error-prefix=${w32root} \
	     --with-ksba-prefix=${w32root} \
	     --with-libgcrypt-prefix=${w32root} \
	     --with-libassuan-prefix=${w32root} \
	     --with-zlib=${w32root} \
             --with-pth-prefix=${w32root}
 
	     
 
