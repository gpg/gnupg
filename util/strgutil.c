/* strgutil.c -  miscellaneous utilities
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "types.h"
#include "util.h"
#include "memory.h"


static int use_koi8 = 0;
static ushort koi82unicode[128] = {
    0x2500,0x2502,0x250c,0x2510,0x2514,0x2518,0x251c,0x2524,
    0x252c,0x2534,0x253c,0x2580,0x2584,0x2588,0x258c,0x2590,
    0x2591,0x2592,0x2593,0x2320,0x25a0,0x2219,0x221a,0x2248,
    0x2264,0x2265,0x00a0,0x2321,0x00b0,0x00b2,0x00b7,0x00f7,
    0x2550,0x2551,0x2552,0x0451,0x2553,0x2554,0x2555,0x2556,
    0x2557,0x2558,0x2559,0x255a,0x255b,0x255c,0x255d,0x255e,
    0x255f,0x2560,0x2561,0x0401,0x2562,0x2563,0x2564,0x2565,
    0x2566,0x2567,0x2568,0x2569,0x256a,0x256b,0x256c,0x00a9,
    0x044e,0x0430,0x0431,0x0446,0x0434,0x0435,0x0444,0x0433,
    0x0445,0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,
    0x043f,0x044f,0x0440,0x0441,0x0442,0x0443,0x0436,0x0432,
    0x044c,0x044b,0x0437,0x0448,0x044d,0x0449,0x0447,0x044a,
    0x042e,0x0410,0x0411,0x0426,0x0414,0x0415,0x0424,0x0413,
    0x0425,0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,
    0x041f,0x042f,0x0420,0x0421,0x0422,0x0423,0x0416,0x0412,
    0x042c,0x042b,0x0417,0x0428,0x042d,0x0429,0x0427,0x042a
};



void
free_strlist( STRLIST sl )
{
    STRLIST sl2;

    for(; sl; sl = sl2 ) {
	sl2 = sl->next;
	m_free(sl);
    }
}


STRLIST
add_to_strlist( STRLIST *list, const char *string )
{
    STRLIST sl;

    sl = m_alloc( sizeof *sl + strlen(string));
    strcpy(sl->d, string);
    sl->next = *list;
    *list = sl;
    return sl;
}

STRLIST
append_to_strlist( STRLIST *list, const char *string )
{
    STRLIST r, sl;

    sl = m_alloc( sizeof *sl + strlen(string));
    strcpy(sl->d, string);
    sl->next = NULL;
    if( !*list )
	*list = sl;
    else {
	for( r = *list; r->next; r = r->next )
	    ;
	r->next = sl;
    }
    return sl;
}



STRLIST
strlist_prev( STRLIST head, STRLIST node )
{
    STRLIST n;

    for(n=NULL; head && head != node; head = head->next )
	n = head;
    return n;
}

STRLIST
strlist_last( STRLIST node )
{
    if( node )
	for( ; node->next ; node = node->next )
	    ;
    return node;
}



/****************
 * look for the substring SUB in buffer and return a pointer to that
 * substring in BUF or NULL if not found.
 * Comparison is case-insensitive.
 */
const char *
memistr( const char *buf, size_t buflen, const char *sub )
{
    const byte *t, *s ;
    size_t n;

    for( t=buf, n=buflen, s=sub ; n ; t++, n-- )
	if( toupper(*t) == toupper(*s) ) {
	    for( buf=t++, buflen = n--, s++;
		 n && toupper(*t) == toupper(*s); t++, s++, n-- )
		;
	    if( !*s )
		return buf;
	    t = buf; n = buflen; s = sub ;
	}

    return NULL ;
}

/****************
 * Wie strncpy(), aber es werden maximal n-1 zeichen kopiert und ein
 * '\0' angehängt. Ist n = 0, so geschieht nichts, ist Destination
 * gleich NULL, so wird via m_alloc Speicher besorgt, ist dann nicht
 * genügend Speicher vorhanden, so bricht die funktion ab.
 */
char *
mem2str( char *dest , const void *src , size_t n )
{
    char *d;
    const char *s;

    if( n ) {
	if( !dest )
	    dest = m_alloc( n ) ;
	d = dest;
	s = src ;
	for(n--; n && *s; n-- )
	    *d++ = *s++;
	*d = '\0' ;
    }

    return dest ;
}


/****************
 * remove leading and trailing white spaces
 */
char *
trim_spaces( char *str )
{
    char *string, *p, *mark;

    string = str;
    /* find first non space character */
    for( p=string; *p && isspace( *(byte*)p ) ; p++ )
	;
    /* move characters */
    for( (mark = NULL); (*string = *p); string++, p++ )
	if( isspace( *(byte*)p ) ) {
	    if( !mark )
		mark = string ;
	}
	else
	    mark = NULL ;
    if( mark )
	*mark = '\0' ;  /* remove trailing spaces */

    return str ;
}


int
string_count_chr( const char *string, int c )
{
    int count;
    for(count=0; *string; string++ )
	if( *string == c )
	    count++;
    return count;
}


int
set_native_charset( const char *newset )
{
    if( !stricmp( newset, "iso-8859-1" ) )
	use_koi8 = 0;
    else if( !stricmp( newset, "koi8-r" ) )
	use_koi8 = 1;
    else
	return G10ERR_GENERAL;
    return 0;
}

/****************
 * Convert string, which is in native encoding to UTF8 and return the
 * new allocated UTF8 string.
 */
char *
native_to_utf8( const char *string )
{
    const byte *s;
    char *buffer;
    byte *p;
    size_t length=0;

    if( use_koi8 ) {
	for(s=string; *s; s++ ) {
	    length++;
	    if( *s & 0x80 )
		length += 2; /* we may need 3 bytes */
	}
	buffer = m_alloc( length + 1 );
	for(p=buffer, s=string; *s; s++ ) {
	    if( *s & 0x80 ) {
		ushort val = koi82unicode[ *s & 0x7f ];
		if( val < 0x0800 ) {
		    *p++ = 0xc0 | ( (val >> 6) & 0x1f );
		    *p++ = 0x80 | (  val & 0x3f );
		}
		else {
		    *p++ = 0xe0 | ( (val >> 12) & 0x0f );
		    *p++ = 0x80 | ( (val >>  6) & 0x3f );
		    *p++ = 0x80 | (  val & 0x3f );
		}
	    }
	    else
		*p++ = *s;
	}
	*p = 0;
    }
    else {
	for(s=string; *s; s++ ) {
	    length++;
	    if( *s & 0x80 )
		length++;
	}
	buffer = m_alloc( length + 1 );
	for(p=buffer, s=string; *s; s++ ) {
	    if( *s & 0x80 ) {
		*p++ = 0xc0 | ((*s >> 6) & 3);
		*p++ = 0x80 | ( *s & 0x3f );
	    }
	    else
		*p++ = *s;
	}
	*p = 0;
    }
    return buffer;
}


/****************
 * Convert string, which is in UTF8 to native encoding.  Replace
 * illegal encodings by some "\xnn".
 * This code assumes that native is iso-8859-1.
 */
char *
utf8_to_native( const char *string )
{
    /* FIXME: Not yet done */
    return m_strdup(string);
}


/****************
 * check whether string is a valid UTF8 string.
 * Returns 0 = Okay
 *	   1 = Too short
 *	   2 = invalid encoding
 */
int
check_utf8_string( const char *string )
{
    /*fixme */
    return 0;
}


/*********************************************
 ********** missing string functions *********
 *********************************************/

#ifndef HAVE_STPCPY
char *
stpcpy(char *a,const char *b)
{
    while( *b )
	*a++ = *b++;
    *a = 0;

    return (char*)a;
}
#endif

#ifndef HAVE_STRLWR
char *
strlwr(char *s)
{
    char *p;
    for(p=s; *p; p++ )
	*p = tolower(*p);
    return s;
}
#endif

/****************
 * mingw32/cpd has a memicmp()
 */
#ifndef HAVE_MEMICMP
int
memicmp( const char *a, const char *b, size_t n )
{
    for( ; n; n--, a++, b++ )
	if( *a != *b  && toupper(*(const byte*)a) != toupper(*(const byte*)b) )
	    return *(const byte *)a - *(const byte*)b;
    return 0;
}
#endif


