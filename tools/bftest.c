/* bftest.c - Blowfish test program
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_DOSISH_SYSTEM
  #include <io.h>
  #include <fcntl.h>
#endif

#include <gcrypt.h>
#include "util.h"
#include "i18n.h"

static void
my_usage(void)
{
    fprintf(stderr, "usage: bftest [-e][-d] algo key\n");
    exit(1);
}


static void
i18n_init(void)
{
  #ifdef ENABLE_NLS
    #ifdef HAVE_LC_MESSAGES
       setlocale( LC_MESSAGES, "" );
    #else
       setlocale( LC_ALL, "" );
    #endif
    bindtextdomain( PACKAGE, GNUPG_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
}

int
main(int argc, char **argv)
{
    int encode=0;
    GCRY_CIPHER_HD hd;
    char buf[4096];
    int n, size=4096;
    int algo;

  #ifdef HAVE_DOSISH_SYSTEM
    setmode( fileno(stdin), O_BINARY );
    setmode( fileno(stdout), O_BINARY );
  #endif

    i18n_init();
    if( argc > 1 && !strcmp(argv[1], "-e") ) {
	encode++;
	argc--; argv++;
    }
    else if( argc > 1 && !strcmp(argv[1], "-E") ) {
	encode++;
	argc--; argv++;
	size = 10;
    }
    else if( argc > 1 && !strcmp(argv[1], "-d") ) {
	argc--; argv++;
    }
    else if( argc > 1 && !strcmp(argv[1], "-D") ) {
	argc--; argv++;
	size = 10;
    }
    if( argc != 3 )
	my_usage();
    argc--; argv++;
    algo = gcry_cipher_map_name( *argv );
    argc--; argv++;

    hd = gcry_cipher_open( algo, GCRY_CIPHER_MODE_CFB, 0 );
    gcry_cipher_setkey( hd, *argv, strlen(*argv) );
    gcry_cipher_setiv( hd, NULL, 0 );
    while( (n = fread( buf, 1, size, stdin )) > 0 ) {
	if( encode )
	    gcry_cipher_encrypt( hd, buf, n, buf, n );
	else
	    gcry_cipher_decrypt( hd, buf, n, buf, n );
	if( fwrite( buf, 1, n, stdout) != n )
	    log_fatal("write error\n");
    }
    gcry_cipher_close(hd);
    return 0;
}

