/* bftest.c - Blowfish test program
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_DOSISH_SYSTEM
#include <io.h>
#include <fcntl.h>
#endif

#include "util.h"
#include "cipher.h"
#include "i18n.h"

static void
my_usage(void)
{
    fprintf(stderr, "usage: bftest [-e][-d] algo key\n");
    exit(1);
}

const char *
strusage( int level )
{
    return default_strusage(level);
}

static void
i18n_init(void)
{
#ifdef ENABLE_NLS
  setlocale( LC_ALL, "" );
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain( PACKAGE );
#endif
}

int
main(int argc, char **argv)
{
    int encode=0;
    CIPHER_HANDLE hd;
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
    algo = string_to_cipher_algo( *argv );
    argc--; argv++;

    hd = cipher_open( algo, CIPHER_MODE_CFB, 0 );
    cipher_setkey( hd, *argv, strlen(*argv) );
    cipher_setiv( hd, NULL, 0 );
    while( (n = fread( buf, 1, size, stdin )) > 0 ) {
	if( encode )
	    cipher_encrypt( hd, buf, buf, n );
	else
	    cipher_decrypt( hd, buf, buf, n );
	if( fwrite( buf, 1, n, stdout) != n )
	    log_fatal("write error\n");
    }
    cipher_close(hd);
    return 0;
}
