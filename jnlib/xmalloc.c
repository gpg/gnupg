/* xmalloc.c -	standard malloc wrappers
 *	Copyright (C) 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libjnlib-config.h"
#include "xmalloc.h"

static void
out_of_core(void)
{
    fputs("\nfatal: out of memory\n", stderr );
    exit(2);
}


void *
xmalloc( size_t n )
{
    void *p = malloc( n );
    if( !p )
	out_of_core();
    return p;
}

void *
xrealloc( void *a, size_t n )
{
    void *p = realloc( a, n );
    if( !p )
	out_of_core();
    return p;
}

void *
xcalloc( size_t n, size_t m )
{
    void *p = calloc( n, m );
    if( !p )
	out_of_core();
    return p;
}

char *
xstrdup( const char *string )
{
    void *p = xmalloc( strlen(string)+1 );
    strcpy( p, string );
    return p;
}


char *
xstrcat2( const char *a, const char *b )
{
    size_t n1;
    char *p;

    if( !b )
	return xstrdup( a );

    n1 = strlen(a);
    p = xmalloc( n1 + strlen(b) + 1 );
    memcpy(p, a, n1 );
    strcpy(p+n1, b );
    return p;
}

