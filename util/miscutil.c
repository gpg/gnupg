/* miscutil.c -  miscellaneous utilities
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "types.h"
#include "util.h"

u32
make_timestamp()
{
    return time(NULL);
}


/****************
 * Print a string to FP, but filter all control characters out.
 */
void
print_string( FILE *fp, byte *p, size_t n )
{
    for( ; n; n--, p++ )
	if( iscntrl( *p ) ) {
	    putc('\\', fp);
	    if( *p == '\n' )
		putc('n', fp);
	    else if( !*p )
		putc('0', fp);
	    else
		fprintf(fp, "x%02x", *p );
	}
	else
	    putc(*p, fp);
}

int
answer_is_yes( const char *s )
{
    if( !stricmp(s, "yes") )
	return 1;
    if( *s == 'y' && !s[1] )
	return 1;
    if( *s == 'Y' && !s[1] )
	return 1;
    return 0;
}

