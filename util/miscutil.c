/* miscutil.c -  miscellaneous utilities
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#ifdef HAVE_LANGINFO_H
  #include <langinfo.h>
#endif
#include "types.h"
#include "util.h"
#include "i18n.h"

/****************
 * I know that the OpenPGP protocol has a Y2106 problem ;-)
 */
u32
make_timestamp()
{
    return time(NULL);
}

/****************
 * Scan a date string and return a timestamp.
 * The only supported format is "yyyy-mm-dd"
 * Returns 0 for an invalid date.
 */
u32
scan_isodatestr( const char *string )
{
    int year, month, day;
    struct tm tmbuf;
    time_t stamp;
    int i;

    if( strlen(string) != 10 || string[4] != '-' || string[7] != '-' )
	return 0;
    for( i=0; i < 4; i++ )
	if( !isdigit(string[i]) )
	    return 0;
    if( !isdigit(string[5]) || !isdigit(string[6]) )
	return 0;
    if( !isdigit(string[8]) || !isdigit(string[9]) )
	return 0;
    year = atoi(string);
    month = atoi(string+5);
    day = atoi(string+8);
    /* some basic checks */
    if( year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 )
	return 0;
    memset( &tmbuf, 0, sizeof tmbuf );
    tmbuf.tm_mday = day;
    tmbuf.tm_mon = month-1;
    tmbuf.tm_year = year - 1900;
    tmbuf.tm_isdst = -1;
    stamp = mktime( &tmbuf );
    if( stamp == (time_t)-1 )
	return 0;
    return stamp;
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
    
    if (atime < 0) {
        strcpy (buffer, "????-??-??");
    }
    else {
        tp = gmtime( &atime );
        sprintf(buffer,"%04d-%02d-%02d",
                1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
    return buffer;
}

/****************
 * Note: this function returns local time
 */
const char *
asctimestamp( u32 stamp )
{
    static char buffer[50];
    #if defined (HAVE_STRFTIME) && defined (HAVE_NL_LANGINFO)
      static char fmt[50];
    #endif
    struct tm *tp;
    time_t atime = stamp;

    if (atime < 0) {
        strcpy (buffer, "????-??-??");
        return buffer;
    }

    tp = localtime( &atime );
  #ifdef HAVE_STRFTIME
    #if defined(HAVE_NL_LANGINFO)
      mem2str( fmt, nl_langinfo(D_T_FMT), DIM(fmt)-3 );
      if( strstr( fmt, "%Z" ) == NULL )
	strcat( fmt, " %Z");
      strftime( buffer, DIM(buffer)-1, fmt, tp );
    #else
      /* fixme: we should check whether the locale appends a " %Z"
       * These locales from glibc don't put the " %Z":
       * fi_FI hr_HR ja_JP lt_LT lv_LV POSIX ru_RU ru_SU sv_FI sv_SE zh_CN
       */
      strftime( buffer, DIM(buffer)-1, "%c %Z", tp );
    #endif
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
print_string( FILE *fp, const byte *p, size_t n, int delim )
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

/****************
 * Print an UTF8 string to FP and filter all control characters out.
 */
void
print_utf8_string( FILE *fp, const byte *p, size_t n )
{
    size_t i;
    char *buf;

    /* we can handle plain ascii simpler, so check for it first */
    for(i=0; i < n; i++ ) {
	if( p[i] & 0x80 )
	    break;
    }
    if( i < n ) {
	buf = utf8_to_native( p, n );
	fputs( buf, fp );
	m_free( buf );
    }
    else
	print_string( fp, p, n, 0 );
}

/****************
 * This function returns a string which is suitable for printing
 * Caller must release it with m_free()
 */
char *
make_printable_string( const byte *p, size_t n, int delim )
{
    size_t save_n, buflen;
    const byte *save_p;
    char *buffer, *d;

    /* first count length */
    for(save_n = n, save_p = p, buflen=1 ; n; n--, p++ ) {
	if( iscntrl( *p ) || *p == delim ) {
	    if( *p=='\n' || *p=='\r' || *p=='\f'
		|| *p=='\v' || *p=='\b' || !*p )
		buflen += 2;
	    else
		buflen += 4;
	}
	else
	    buflen++;
    }
    p = save_p;
    n = save_n;
    /* and now make the string */
    d = buffer = m_alloc( buflen );
    for( ; n; n--, p++ ) {
	if( iscntrl( *p ) || *p == delim ) {
	    *d++ = '\\';
	    if( *p == '\n' )
		*d++ = 'n';
	    else if( *p == '\r' )
		*d++ = 'r';
	    else if( *p == '\f' )
		*d++ = 'f';
	    else if( *p == '\v' )
		*d++ = 'v';
	    else if( *p == '\b' )
		*d++ = 'b';
	    else if( !*p )
		*d++ = '0';
	    else {
		sprintf(d, "x%02x", *p );
		d += 2;
	    }
	}
	else
	    *d++ = *p;
    }
    *d = 0;
    return buffer;
}


int
answer_is_yes( const char *s )
{
    const char *long_yes = _("yes");
    const char *short_yes = _("yY");
    const char *long_no = _("no");
    const char *short_no = _("nN");

    if( !stricmp(s, long_yes ) )
	return 1;
    if( *s && strchr( short_yes, *s ) && !s[1] )
	return 1;
    /* test for no strings to catch ambiguities for the next test */
    if( !stricmp(s, long_no ) )
	return 0;
    if( *s && strchr( short_no, *s ) && !s[1] )
	return 0;
    /* test for the english version (for those who are used to type yes) */
    if( !stricmp(s, "yes" ) )
	return 1;
    if( *s && strchr( "yY", *s ) && !s[1] )
	return 1;
    return 0;
}


/****************
 * Return 1 for yes, -1 for quit, or 0 for no
 */
int
answer_is_yes_no_quit( const char *s )
{
    const char *long_yes = _("yes");
    const char *long_no = _("no");
    const char *long_quit = _("quit");
    const char *short_yes = _("yY");
    const char *short_no = _("nN");
    const char *short_quit = _("qQ");

    if( !stricmp(s, long_no ) )
	return 0;
    if( !stricmp(s, long_yes ) )
	return 1;
    if( !stricmp(s, long_quit ) )
	return -1;
    if( *s && strchr( short_no, *s ) && !s[1] )
	return 0;
    if( *s && strchr( short_yes, *s ) && !s[1] )
	return 1;
    if( *s && strchr( short_quit, *s ) && !s[1] )
	return -1;
    if( !stricmp(s, "yes" ) )
	return 1;
    if( !stricmp(s, "quit" ) )
	return -1;
    if( *s && strchr( "yY", *s ) && !s[1] )
	return 1;
    if( *s && strchr( "qQ", *s ) && !s[1] )
	return -1;
    return 0;
}


