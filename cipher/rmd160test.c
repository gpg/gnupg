/* rmd160test.c - ripe md 160 test program
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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

#include "util.h"
#include "rmd.h"

static void
usage(void)
{
    fprintf(stderr, "usage: rmd160test\n");
    exit(1);
}


int
main(int argc, char **argv)
{
    RMDHANDLE rmdhd;
    int i, n;
    byte buf[100], *p;

    if( argc > 1 )
	usage();

    rmdhd = rmd160_open(0);
  #if 1
    while( (n = fread( buf, 1, 100, stdin )) > 0 )
	rmd160_write(rmdhd, buf, n);
  #else
    for(i=0; i < 1000000; i++ )
	rmd160_putchar(rmdhd, 'a');
  #endif
    p = rmd160_final(rmdhd);
    for(i=0; i < 20; i++, p++ )
	printf("%02x", *p );
    putchar('\n');

    rmd160_close(rmdhd);
    return 0;
}

