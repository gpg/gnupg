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
#include "i18n.h"

u32
make_timestamp()
{
    return time(NULL);
}

u32
add_days_to_timestamp( u32 stamp, u16 days )
{
    return stamp + days*86400L;
}


/****************
 * Return a string with a time value in the form: x Y, n D, n H
 */

const char *
strtimevalue( u32 value )
{
    static char buffer[30];
    unsigned int years, days, hours, minutes;

    value /= 60;
    minutes = value % 60;
    value /= 60;
    hours = value % 24;
    value /= 24;
    days = value % 365;
    value /= 365;
    years = value;

    sprintf(buffer,"%uy%ud%uh%um", years, days, hours, minutes );
    if( years )
	return buffer;
    if( days )
	return strchr( buffer, 'y' ) + 1;
    return strchr( buffer, 'd' ) + 1;
}


/****************
 * Note: this function returns GMT
 */
const char *
strtimestamp( u32 stamp )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = stamp;

    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d",
		    1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}

/****************
 * Note: this function returns local time
 */
const char *
asctimestamp( u32 stamp )
{
    static char buffer[50];
    struct tm *tp;
    time_t atime = stamp;

    tp = localtime( &atime );
  #ifdef HAVE_STRFTIME
    strftime( buffer, DIM(buffer)-1, "%c %Z", tp );
    buffer[DIM(buffer)-1] = 0;
  #else
    mem2str( buffer, asctime(tp), DIM(buffer) );
  #endif
    return buffer;
}

/****************
 * Print a string to FP, but filter all control characters out.
 */
void
print_string( FILE *fp, byte *p, size_t n, int delim )
{
    for( ; n; n--, p++ )
	if( iscntrl( *p ) || *p == delim ) {
	    putc('\\', fp);
	    if( *p == '\n' )
		putc('n', fp);
	    else if( *p == '\r' )
		putc('r', fp);
	    else if( *p == '\f' )
		putc('f', fp);
	    else if( *p == '\v' )
		putc('v', fp);
	    else if( *p == '\b' )
		putc('b', fp);
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
    char *long_yes = _("yes");
    char *short_yes = _("yY");

    if( !stricmp(s, long_yes ) )
	return 1;
    if( strchr( short_yes, *s ) && !s[1] )
	return 1;
    return 0;
}


