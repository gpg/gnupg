/* strgutil.c -  string utilities
 * Copyright (C) 1994, 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <ctype.h>
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "types.h"
#include "util.h"
#include "memory.h"


static ushort koi8_unicode[128] = {
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

static ushort latin2_unicode[128] = {
    0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,
    0x0088,0x0089,0x008A,0x008B,0x008C,0x008D,0x008E,0x008F,
    0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,
    0x0098,0x0099,0x009A,0x009B,0x009C,0x009D,0x009E,0x009F,
    0x00A0,0x0104,0x02D8,0x0141,0x00A4,0x013D,0x015A,0x00A7,
    0x00A8,0x0160,0x015E,0x0164,0x0179,0x00AD,0x017D,0x017B,
    0x00B0,0x0105,0x02DB,0x0142,0x00B4,0x013E,0x015B,0x02C7,
    0x00B8,0x0161,0x015F,0x0165,0x017A,0x02DD,0x017E,0x017C,
    0x0154,0x00C1,0x00C2,0x0102,0x00C4,0x0139,0x0106,0x00C7,
    0x010C,0x00C9,0x0118,0x00CB,0x011A,0x00CD,0x00CE,0x010E,
    0x0110,0x0143,0x0147,0x00D3,0x00D4,0x0150,0x00D6,0x00D7,
    0x0158,0x016E,0x00DA,0x0170,0x00DC,0x00DD,0x0162,0x00DF,
    0x0155,0x00E1,0x00E2,0x0103,0x00E4,0x013A,0x0107,0x00E7,
    0x010D,0x00E9,0x0119,0x00EB,0x011B,0x00ED,0x00EE,0x010F,
    0x0111,0x0144,0x0148,0x00F3,0x00F4,0x0151,0x00F6,0x00F7,
    0x0159,0x016F,0x00FA,0x0171,0x00FC,0x00FD,0x0163,0x02D9
};


static const char *active_charset_name = "iso-8859-1";
static ushort *active_charset = NULL;
static int no_translation = 0;

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
    sl->flags = 0;
    strcpy(sl->d, string);
    sl->next = *list;
    *list = sl;
    return sl;
}

/****************
 * ame as add_to_strlist() but if is_utf8 is *not* set a conversion
 * to UTF8 is done
 */
STRLIST
add_to_strlist2( STRLIST *list, const char *string, int is_utf8 )
{
    STRLIST sl;

    if( is_utf8 )
	sl = add_to_strlist( list, string );
    else {
	char *p = native_to_utf8( string );
	sl = add_to_strlist( list, p );
	m_free( p );
    }
    return sl;
}

STRLIST
append_to_strlist( STRLIST *list, const char *string )
{
    STRLIST r, sl;

    sl = m_alloc( sizeof *sl + strlen(string));
    sl->flags = 0;
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
append_to_strlist2( STRLIST *list, const char *string, int is_utf8 )
{
    STRLIST sl;

    if( is_utf8 )
	sl = append_to_strlist( list, string );
    else {
	char *p = native_to_utf8( string );
	sl = append_to_strlist( list, p );
	m_free( p );
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

char *
pop_strlist( STRLIST *list )
{
  char *str=NULL;
  STRLIST sl=*list;

  if(sl)
    {
      str=m_alloc(strlen(sl->d)+1);
      strcpy(str,sl->d);

      *list=sl->next;
      m_free(sl);
    }

  return str;
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

const char *
ascii_memistr( const char *buf, size_t buflen, const char *sub )
{
    const byte *t, *s ;
    size_t n;

    for( t=buf, n=buflen, s=sub ; n ; t++, n-- )
	if( ascii_toupper(*t) == ascii_toupper(*s) ) {
	    for( buf=t++, buflen = n--, s++;
		 n && ascii_toupper(*t) == ascii_toupper(*s); t++, s++, n-- )
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



unsigned int
trim_trailing_chars( byte *line, unsigned len, const char *trimchars )
{
    byte *p, *mark;
    unsigned n;

    for(mark=NULL, p=line, n=0; n < len; n++, p++ ) {
	if( strchr(trimchars, *p ) ) {
	    if( !mark )
		mark = p;
	}
	else
	    mark = NULL;
    }

    if( mark ) {
	*mark = 0;
	return mark - line;
    }
    return len;
}

/****************
 * remove trailing white spaces and return the length of the buffer
 */
unsigned
trim_trailing_ws( byte *line, unsigned len )
{
    return trim_trailing_chars( line, len, " \t\r\n" );
}

unsigned int
check_trailing_chars( const byte *line, unsigned int len,
                      const char *trimchars )
{
    const byte *p, *mark;
    unsigned int n;

    for(mark=NULL, p=line, n=0; n < len; n++, p++ ) {
	if( strchr(trimchars, *p ) ) {
	    if( !mark )
		mark = p;
	}
	else
	    mark = NULL;
    }

    if( mark ) {
	return mark - line;
    }
    return len;
}

/****************
 * remove trailing white spaces and return the length of the buffer
 */
unsigned int
check_trailing_ws( const byte *line, unsigned int len )
{
    return check_trailing_chars( line, len, " \t\r\n" );
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
    if (!newset) 
#ifdef HAVE_LANGINFO_CODESET
        newset = nl_langinfo (CODESET);
#else
        newset = "8859-1";
#endif

    if (strlen (newset) > 3 && !ascii_memcasecmp (newset, "iso", 3)) {
        newset += 3;
        if (*newset == '-' || *newset == '_')
            newset++;
    }

    if( !*newset
        || !ascii_strcasecmp (newset, "8859-1" )
        || !ascii_strcasecmp (newset, "8859-15" ) ) {
        active_charset_name = "iso-8859-1";
        no_translation = 0;
	active_charset = NULL;
    }
    else if( !ascii_strcasecmp( newset, "8859-2" ) ) {
	active_charset_name = "iso-8859-2";
        no_translation = 0;
	active_charset = latin2_unicode;
    }
    else if( !ascii_strcasecmp( newset, "koi8-r" ) ) {
	active_charset_name = "koi8-r";
        no_translation = 0;
	active_charset = koi8_unicode;
    }
    else if( !ascii_strcasecmp (newset, "utf8" )
             || !ascii_strcasecmp(newset, "utf-8") ) {
	active_charset_name = "utf-8";
        no_translation = 1;
	active_charset = NULL;
    }
    else
	return G10ERR_GENERAL;
    return 0;
}

const char*
get_native_charset()
{
    return active_charset_name;
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

    if (no_translation) {
        buffer = m_strdup (string);
    }
    else if( active_charset ) {
	for(s=string; *s; s++ ) {
	    length++;
	    if( *s & 0x80 )
		length += 2; /* we may need 3 bytes */
	}
	buffer = m_alloc( length + 1 );
	for(p=buffer, s=string; *s; s++ ) {
	    if( *s & 0x80 ) {
		ushort val = active_charset[ *s & 0x7f ];
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
 * Convert string, which is in UTF8 to native encoding.  illegal
 * encodings by some "\xnn" and quote all control characters. A
 * character with value DELIM will always be quoted, it must be a
 * vanilla ASCII character.  
  */
char *
utf8_to_native( const char *string, size_t length, int delim )
{
    int nleft;
    int i;
    byte encbuf[8];
    int encidx;
    const byte *s;
    size_t n;
    byte *buffer = NULL, *p = NULL;
    unsigned long val = 0;
    size_t slen;
    int resync = 0;

    /* 1. pass (p==NULL): count the extended utf-8 characters */
    /* 2. pass (p!=NULL): create string */
    for( ;; ) {
	for( slen=length, nleft=encidx=0, n=0, s=string; slen; s++, slen-- ) {
	    if( resync ) {
		if( !(*s < 128 || (*s >= 0xc0 && *s <= 0xfd)) ) {
		    /* still invalid */
		    if( p ) {
			sprintf(p, "\\x%02x", *s );
			p += 4;
		    }
		    n += 4;
		    continue;
		}
		resync = 0;
	    }
	    if( !nleft ) {
		if( !(*s & 0x80) ) { /* plain ascii */
		    if( *s < 0x20 || *s == 0x7f || *s == delim ||
			(delim && *s=='\\')) {
			n++;
			if( p )
			    *p++ = '\\';
			switch( *s ) {
			  case '\n': n++; if( p ) *p++ = 'n'; break;
			  case '\r': n++; if( p ) *p++ = 'r'; break;
			  case '\f': n++; if( p ) *p++ = 'f'; break;
			  case '\v': n++; if( p ) *p++ = 'v'; break;
			  case '\b': n++; if( p ) *p++ = 'b'; break;
			  case	 0 : n++; if( p ) *p++ = '0'; break;
			  default:
                            n += 3;
                            if ( p ) {
                                sprintf( p, "x%02x", *s );
                                p += 3;
                            }
                            break;
			}
		    }
		    else {
			if( p ) *p++ = *s;
			n++;
		    }
		}
		else if( (*s & 0xe0) == 0xc0 ) { /* 110x xxxx */
		    val = *s & 0x1f;
		    nleft = 1;
                    encidx = 0;
		    encbuf[encidx++] = *s;
		}
		else if( (*s & 0xf0) == 0xe0 ) { /* 1110 xxxx */
		    val = *s & 0x0f;
		    nleft = 2;
                    encidx = 0;
		    encbuf[encidx++] = *s;
		}
		else if( (*s & 0xf8) == 0xf0 ) { /* 1111 0xxx */
		    val = *s & 0x07;
		    nleft = 3;
                    encidx = 0;
		    encbuf[encidx++] = *s;
		}
		else if( (*s & 0xfc) == 0xf8 ) { /* 1111 10xx */
		    val = *s & 0x03;
		    nleft = 4;
                    encidx = 0;
		    encbuf[encidx++] = *s;
		}
		else if( (*s & 0xfe) == 0xfc ) { /* 1111 110x */
		    val = *s & 0x01;
		    nleft = 5;
                    encidx = 0;
		    encbuf[encidx++] = *s;
		}
		else {	/* invalid encoding: print as \xnn */
		    if( p ) {
			sprintf(p, "\\x%02x", *s );
			p += 4;
		    }
		    n += 4;
		    resync = 1;
		}
	    }
	    else if( *s < 0x80 || *s >= 0xc0 ) { /* invalid */
		if( p ) {
                    for(i=0; i < encidx; i++ ) {
                        sprintf(p, "\\x%02x", encbuf[i] );
                        p += 4;
                    }
		    sprintf(p, "\\x%02x", *s );
		    p += 4;
		}
		n += 4 + 4*encidx;
		nleft = 0;
                encidx = 0;
		resync = 1;
	    }
	    else {
		encbuf[encidx++] = *s;
		val <<= 6;
		val |= *s & 0x3f;
		if( !--nleft ) { /* ready */
                    if (no_translation) {
                        if( p ) {
                            for(i=0; i < encidx; i++ )
                                *p++ = encbuf[i];
                        }
                        n += encidx;
                        encidx = 0;
                    }
		    else if( active_charset ) { /* table lookup */
			for(i=0; i < 128; i++ ) {
			    if( active_charset[i] == val )
				break;
			}
			if( i < 128 ) { /* we can print this one */
			    if( p ) *p++ = i+128;
			    n++;
			}
			else { /* we do not have a translation: print utf8 */
			    if( p ) {
				for(i=0; i < encidx; i++ ) {
				    sprintf(p, "\\x%02x", encbuf[i] );
				    p += 4;
				}
			    }
			    n += encidx*4;
                            encidx = 0;
			}
		    }
		    else { /* native set */
			if( val >= 0x80 && val < 256 ) {
			    n++;    /* we can simply print this character */
			    if( p ) *p++ = val;
			}
			else { /* we do not have a translation: print utf8 */
			    if( p ) {
				for(i=0; i < encidx; i++ ) {
				    sprintf(p, "\\x%02x", encbuf[i] );
				    p += 4;
				}
			    }
			    n += encidx*4;
                            encidx = 0;
			}
		    }
		}

	    }
	}
	if( !buffer ) { /* allocate the buffer after the first pass */
	    buffer = p = m_alloc( n + 1 );
	}
	else {
	    *p = 0; /* make a string */
	    return buffer;
	}
    }
}

/****************************************************
 ******** locale insensitive ctype functions ********
 ****************************************************/
/* FIXME: replace them by a table lookup and macros */
int
ascii_isupper (int c)
{
    return c >= 'A' && c <= 'Z';
}

int
ascii_islower (int c)
{
    return c >= 'a' && c <= 'z';
}

int 
ascii_toupper (int c)
{
    if (c >= 'a' && c <= 'z')
        c &= ~0x20;
    return c;
}

int 
ascii_tolower (int c)
{
    if (c >= 'A' && c <= 'Z')
        c |= 0x20;
    return c;
}


int
ascii_strcasecmp (const char *a, const char *b)
{
  const unsigned char *p1 = (const unsigned char *)a;
  const unsigned char *p2 = (const unsigned char *)b;
  unsigned char c1, c2;

  if (p1 == p2)
    return 0;

  do
    {
      c1 = ascii_tolower (*p1);
      c2 = ascii_tolower (*p2);

      if (c1 == '\0')
	break;

      ++p1;
      ++p2;
    }
  while (c1 == c2);
  
  return c1 - c2;
}

int 
ascii_strncasecmp (const char *a, const char *b, size_t n)
{
  const unsigned char *p1 = (const unsigned char *)a;
  const unsigned char *p2 = (const unsigned char *)b;
  unsigned char c1, c2;

  if (p1 == p2 || !n )
    return 0;

  do
    {
      c1 = ascii_tolower (*p1);
      c2 = ascii_tolower (*p2);

      if ( !--n || c1 == '\0')
	break;

      ++p1;
      ++p2;
    }
  while (c1 == c2);
  
  return c1 - c2;
}


int
ascii_memcasecmp( const char *a, const char *b, size_t n )
{
    if (a == b)
        return 0;
    for ( ; n; n--, a++, b++ ) {
	if( *a != *b  && ascii_toupper (*a) != ascii_toupper (*b) )
            return *a == *b? 0 : (ascii_toupper (*a) - ascii_toupper (*b));
    }
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


#ifndef HAVE_STRSEP
/* code taken from glibc-2.2.1/sysdeps/generic/strsep.c */
char *
strsep (char **stringp, const char *delim)
{
  char *begin, *end;

  begin = *stringp;
  if (begin == NULL)
    return NULL;

  /* A frequent case is when the delimiter string contains only one
     character.  Here we don't need to call the expensive `strpbrk'
     function and instead work using `strchr'.  */
  if (delim[0] == '\0' || delim[1] == '\0')
    {
      char ch = delim[0];

      if (ch == '\0')
        end = NULL;
      else
        {
          if (*begin == ch)
            end = begin;
          else if (*begin == '\0')
            end = NULL;
          else
            end = strchr (begin + 1, ch);
        }
    }
  else
    /* Find the end of the token.  */
    end = strpbrk (begin, delim);

  if (end)
    {
      /* Terminate the token and set *STRINGP past NUL character.  */
      *end++ = '\0';
      *stringp = end;
    }
  else
    /* No more delimiters; this is the last token.  */
    *stringp = NULL;

  return begin;
}
#endif /*HAVE_STRSEP*/


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

#ifndef HAVE_STRCASECMP
int
strcasecmp( const char *a, const char *b )
{
    for( ; *a && *b; a++, b++ ) {
	if( *a != *b && toupper(*a) != toupper(*b) )
	    break;
    }
    return *(const byte*)a - *(const byte*)b;
}
#endif

#ifndef HAVE_STRNCASECMP
int
strncasecmp( const char *a, const char *b, size_t n )
{
    for( ; n && *a && *b; a++, b++, n--) {
	if( *a != *b && toupper(*a) != toupper(*b) )
	    break;
    }
    if (!n)
      return 0;
    return *(const byte*)a - *(const byte*)b;
}
#endif


#ifdef __MINGW32__
/* 
 * Like vsprintf but provides a pointer to malloc'd storage, which
 * must be freed by the caller (m_free).  Taken from libiberty as
 * found in gcc-2.95.2 and a little bit modernized.
 * FIXME: Write a new CRT for W32.
 */
int
vasprintf ( char **result, const char *format, va_list args)
{
  const char *p = format;
  /* Add one to make sure that it is never zero, which might cause malloc
     to return NULL.  */
  int total_width = strlen (format) + 1;
  va_list ap;

  /* this is not really portable but works under Windows */
  memcpy ( &ap, &args, sizeof (va_list));

  while (*p != '\0')
    {
      if (*p++ == '%')
	{
	  while (strchr ("-+ #0", *p))
	    ++p;
	  if (*p == '*')
	    {
	      ++p;
	      total_width += abs (va_arg (ap, int));
	    }
	  else
            {
              char *endp;  
              total_width += strtoul (p, &endp, 10);
              p = endp;
            }
	  if (*p == '.')
	    {
	      ++p;
	      if (*p == '*')
		{
		  ++p;
		  total_width += abs (va_arg (ap, int));
		}
	      else
                {
                  char *endp;
                  total_width += strtoul (p, &endp, 10);
                  p = endp;
                }
	    }
	  while (strchr ("hlL", *p))
	    ++p;
	  /* Should be big enough for any format specifier except %s
             and floats.  */
	  total_width += 30;
	  switch (*p)
	    {
	    case 'd':
	    case 'i':
	    case 'o':
	    case 'u':
	    case 'x':
	    case 'X':
	    case 'c':
	      (void) va_arg (ap, int);
	      break;
	    case 'f':
	    case 'e':
	    case 'E':
	    case 'g':
	    case 'G':
	      (void) va_arg (ap, double);
	      /* Since an ieee double can have an exponent of 307, we'll
		 make the buffer wide enough to cover the gross case. */
	      total_width += 307;
	    
	    case 's':
	      total_width += strlen (va_arg (ap, char *));
	      break;
	    case 'p':
	    case 'n':
	      (void) va_arg (ap, char *);
	      break;
	    }
	}
    }
  *result = m_alloc (total_width);
  if (*result != NULL)
    return vsprintf (*result, format, args);
  else
    return 0;
}

#endif /*__MINGW32__*/

