/* miscutil.c -  miscellaneous utilities
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004, 2005 Free Software Foundation, Inc.
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
	if( !digitp(string+i) )
	    return 0;
    if( !digitp(string+5) || !digitp(string+6) )
	return 0;
    if( !digitp(string+8) || !digitp(string+9) )
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
        strcpy (buffer, "????" "-??" "-??");
    }
    else {
        tp = gmtime( &atime );
        sprintf(buffer,"%04d-%02d-%02d",
                1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
    return buffer;
}


/****************
 * Note: this function returns GMT
 */
const char *
isotimestamp (u32 stamp)
{
    static char buffer[25+5];
    struct tm *tp;
    time_t atime = stamp;
    
    if (atime < 0) {
        strcpy (buffer, "????" "-??" "-??" " " "??" ":" "??" ":" "??");
    }
    else {
        tp = gmtime( &atime );
        sprintf(buffer,"%04d-%02d-%02d %02d:%02d:%02d",
                1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                tp->tm_hour, tp->tm_min, tp->tm_sec);
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
        strcpy (buffer, "????" "-??" "-??");
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
      strftime( buffer, DIM(buffer)-1, 
#ifdef HAVE_W32_SYSTEM                
                "%c"
#else
                "%c %Z"
#endif
                , tp );
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
print_string2( FILE *fp, const byte *p, size_t n, int delim, int delim2 )
{
    for( ; n; n--, p++ )
	if( *p < 0x20 || (*p >= 0x7f && *p < 0xa0)
	    || *p == delim || *p == delim2
	    || ((delim || delim2) && *p=='\\'))
	  {
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

void
print_string( FILE *fp, const byte *p, size_t n, int delim )
{
  print_string2(fp,p,n,delim,0);
}

/****************
 * Print an UTF8 string to FP and filter all control characters out.
 */
void
print_utf8_string2 ( FILE *fp, const byte *p, size_t n, int delim )
{
    size_t i;
    char *buf;

    /* we can handle plain ascii simpler, so check for it first */
    for(i=0; i < n; i++ ) {
	if( p[i] & 0x80 )
	    break;
    }
    if( i < n ) {
	buf = utf8_to_native ( p, n, delim );
	/*(utf8 conversion already does the control character quoting)*/
	fputs( buf, fp );
	xfree( buf );
    }
    else
	print_string( fp, p, n, delim );
}

void
print_utf8_string( FILE *fp, const byte *p, size_t n )
{
    print_utf8_string2 (fp, p, n, 0);
}

/****************
 * This function returns a string which is suitable for printing
 * Caller must release it with xfree()
 */
char *
make_printable_string( const byte *p, size_t n, int delim )
{
    size_t save_n, buflen;
    const byte *save_p;
    char *buffer, *d;

    /* first count length */
    for(save_n = n, save_p = p, buflen=1 ; n; n--, p++ ) {
	if( *p < 0x20 || (*p >= 0x7f && *p < 0xa0) || *p == delim ||
	    (delim && *p=='\\')) {
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
    d = buffer = xmalloc( buflen );
    for( ; n; n--, p++ ) {
	if( *p < 0x20 || (*p >= 0x7f && *p < 0xa0) || *p == delim ||
	    (delim && *p=='\\')) {
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
		d += 3;
	    }
	}
	else
	    *d++ = *p;
    }
    *d = 0;
    return buffer;
}

int
answer_is_yes_no_default( const char *s, int def_answer )
{
    /* TRANSLATORS: See doc/TRANSLATE about this string. */
    const char *long_yes = _("yes");
    const char *short_yes = _("yY");
    /* TRANSLATORS: See doc/TRANSLATE about this string. */
    const char *long_no = _("no");
    const char *short_no = _("nN");

    /* Note: we have to use the local dependent strcasecmp here */
    if( match_multistr(long_yes,s) )
	return 1;
    if( *s && strchr( short_yes, *s ) && !s[1] )
	return 1;
    /* test for no strings to catch ambiguities for the next test */
    if( match_multistr(long_no,s) )
	return 0;
    if( *s && strchr( short_no, *s ) && !s[1] )
	return 0;
    /* test for the english version (for those who are used to type yes) */
    if( !ascii_strcasecmp(s, "yes" ) )
	return 1;
    if( *s && strchr( "yY", *s ) && !s[1] )
	return 1;
    return def_answer;
}

int
answer_is_yes( const char *s )
{
  return answer_is_yes_no_default(s,0);
}

/****************
 * Return 1 for yes, -1 for quit, or 0 for no
 */
int
answer_is_yes_no_quit( const char *s )
{
    /* TRANSLATORS: See doc/TRANSLATE about this string. */
    const char *long_yes = _("yes");
    /* TRANSLATORS: See doc/TRANSLATE about this string. */
    const char *long_no = _("no");
    /* TRANSLATORS: See doc/TRANSLATE about this string. */
    const char *long_quit = _("quit");
    const char *short_yes = _("yY");
    const char *short_no = _("nN");
    const char *short_quit = _("qQ");

    if( match_multistr(long_no,s) )
	return 0;
    if( match_multistr(long_yes,s) )
	return 1;
    if( match_multistr(long_quit,s) )
	return -1;
    if( *s && strchr( short_no, *s ) && !s[1] )
	return 0;
    if( *s && strchr( short_yes, *s ) && !s[1] )
	return 1;
    if( *s && strchr( short_quit, *s ) && !s[1] )
	return -1;
    /* but not here */
    if( !ascii_strcasecmp(s, "yes" ) )
	return 1;
    if( !ascii_strcasecmp(s, "quit" ) )
	return -1;
    if( *s && strchr( "yY", *s ) && !s[1] )
	return 1;
    if( *s && strchr( "qQ", *s ) && !s[1] )
	return -1;
    return 0;
}

/*
   Return 1 for okay, 0 for for cancel or DEF_ANSWER for default. 
 */
int
answer_is_okay_cancel (const char *s, int def_answer)
{
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_okay = _("okay|okay");
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_cancel = _("cancel|cancel");
  const char *short_okay = _("oO");
  const char *short_cancel = _("cC");
  
  /* Note: We have to use the locale dependent strcasecmp */
  if ( match_multistr(long_okay,s) )
    return 1;
  if ( match_multistr(long_cancel,s) )
    return 0;
  if ( *s && strchr( short_okay, *s ) && !s[1] )
    return 1;
  if ( *s && strchr( short_cancel, *s ) && !s[1] )
    return 0;
  /* Always test for the English values (not locale here) */
  if ( !ascii_strcasecmp(s, "okay" ) )
    return 1;
  if ( !ascii_strcasecmp(s, "ok" ) )
    return 1;
  if ( !ascii_strcasecmp(s, "cancel" ) )
    return 0;
  if ( *s && strchr( "oO", *s ) && !s[1] )
    return 1;
  if ( *s && strchr( "cC", *s ) && !s[1] )
    return 0;
  return def_answer;
}

/* Try match against each substring of multistr, delimited by | */
int
match_multistr(const char *multistr,const char *match)
{
  do
    {
      size_t seglen=strcspn(multistr,"|");
      if(!seglen)
	break;
      /* Using the localized strncasecmp */
      if(strncasecmp(multistr,match,seglen)==0)
	return 1;
      multistr+=seglen;
      if(*multistr=='|')
	multistr++;
    }
  while(*multistr);

  return 0;
}
