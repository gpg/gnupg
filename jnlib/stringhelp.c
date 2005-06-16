/* stringhelp.c -  standard string helper functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004, 2005  Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <ctype.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include "libjnlib-config.h"
#include "utf8conv.h"
#include "stringhelp.h"


/*
 * Look for the substring SUB in buffer and return a pointer to that
 * substring in BUFFER or NULL if not found.
 * Comparison is case-insensitive.
 */
const char *
memistr (const void *buffer, size_t buflen, const char *sub)
{
  const unsigned char *buf = buffer;
  const unsigned char *t = (const unsigned char *)buffer;
  const unsigned char *s = (const unsigned char *)sub;
  size_t n = buflen;

  for ( ; n ; t++, n-- )
    {
      if ( toupper (*t) == toupper (*s) )
        {
          for ( buf=t++, buflen = n--, s++;
                n && toupper (*t) == toupper (*s); t++, s++, n-- )
            ;
          if (!*s)
            return (const char*)buf;
          t = buf;
          s = (const unsigned char *)sub ;
          n = buflen;
	}
    }
  return NULL;
}

const char *
ascii_memistr ( const void *buffer, size_t buflen, const char *sub )
{
  const unsigned char *buf = buffer;
  const unsigned char *t = (const unsigned char *)buf;
  const unsigned char *s = (const unsigned char *)sub;
  size_t n = buflen;

  for ( ; n ; t++, n-- )
    {
      if (ascii_toupper (*t) == ascii_toupper (*s) )
        {
          for ( buf=t++, buflen = n--, s++;
                n && ascii_toupper (*t) == ascii_toupper (*s); t++, s++, n-- )
            ;
          if (!*s)
            return (const char*)buf;
          t = (const unsigned char *)buf;
          s = (const unsigned char *)sub ;
          n = buflen;
	}
    }
  return NULL;
}

/* This function is similar to strncpy().  However it won't copy more
   than N - 1 characters and makes sure that a '\0' is appended. With
   N given as 0, nothing will happen.  With DEST given as NULL, memory
   will be allocated using jnlib_xmalloc (i.e. if it runs out of core
   the function terminates).  Returns DES or a pointer to the
   allocated memory.
 */
char *
mem2str( char *dest , const void *src , size_t n )
{
    char *d;
    const char *s;

    if( n ) {
	if( !dest )
	    dest = jnlib_xmalloc( n ) ;
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

/****************
 * remove trailing white spaces
 */
char *
trim_trailing_spaces( char *string )
{
    char *p, *mark;

    for( mark = NULL, p = string; *p; p++ ) {
	if( isspace( *(byte*)p ) ) {
	    if( !mark )
		mark = p;
	}
	else
	    mark = NULL;
    }
    if( mark )
	*mark = '\0' ;

    return string ;
}


unsigned
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

size_t
length_sans_trailing_chars (const unsigned char *line, size_t len,
                            const char *trimchars )
{
  const unsigned char *p, *mark;
  size_t n;
  
  for( mark=NULL, p=line, n=0; n < len; n++, p++ )
    {
      if (strchr (trimchars, *p ))
        {
          if( !mark )
            mark = p;
        }
      else
        mark = NULL;
    }
  
  if (mark) 
    return mark - line;
  return len;
}

/****************
 * remove trailing white spaces and return the length of the buffer
 */
size_t
length_sans_trailing_ws (const unsigned char *line, size_t len)
{
  return length_sans_trailing_chars (line, len, " \t\r\n");
}



/***************
 * Extract from a given path the filename component.
 *
 */
char *
make_basename(const char *filepath)
{
    char *p;

    if ( !(p=strrchr(filepath, '/')) )
      #ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
      #endif
	      {
		return jnlib_xstrdup(filepath);
	      }

    return jnlib_xstrdup(p+1);
}



/***************
 * Extract from a given filename the path prepended to it.
 * If their isn't a path prepended to the filename, a dot
 * is returned ('.').
 *
 */
char *
make_dirname(const char *filepath)
{
    char *dirname;
    int  dirname_length;
    char *p;

    if ( !(p=strrchr(filepath, '/')) )
      #ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
      #endif
	      {
		return jnlib_xstrdup(".");
	      }

    dirname_length = p-filepath;
    dirname = jnlib_xmalloc(dirname_length+1);
    strncpy(dirname, filepath, dirname_length);
    dirname[dirname_length] = 0;

    return dirname;
}



/****************
 * Construct a filename from the NULL terminated list of parts.
 * Tilde expansion is done here.
 */
char *
make_filename( const char *first_part, ... )
{
    va_list arg_ptr ;
    size_t n;
    const char *s;
    char *name, *home, *p;

    va_start( arg_ptr, first_part ) ;
    n = strlen(first_part)+1;
    while( (s=va_arg(arg_ptr, const char *)) )
	n += strlen(s) + 1;
    va_end(arg_ptr);

    home = NULL;
    if( *first_part == '~' && first_part[1] == '/'
			   && (home = getenv("HOME")) && *home )
	n += strlen(home);

    name = jnlib_xmalloc(n);
    p = home ? stpcpy(stpcpy(name,home), first_part+1)
	     : stpcpy(name, first_part);
    va_start( arg_ptr, first_part ) ;
    while( (s=va_arg(arg_ptr, const char *)) )
	p = stpcpy(stpcpy(p,"/"), s);
    va_end(arg_ptr);

    return name;
}


int
compare_filenames( const char *a, const char *b )
{
    /* ? check whether this is an absolute filename and
     * resolve symlinks?
     */
#ifdef HAVE_DRIVE_LETTERS
    return stricmp(a,b);
#else
    return strcmp(a,b);
#endif
}

/* Print a BUFFER to stream FP while replacing all control characters
   and the character DELIM with standard C escape sequences.  Returns
   the number of characters printed. */
size_t 
print_sanitized_buffer (FILE *fp, const void *buffer, size_t length,
                        int delim)
{
  const unsigned char *p = buffer;
  size_t count = 0;

  for (; length; length--, p++, count++)
    {
      if (*p < 0x20 || *p == 0x7f || *p == delim)
        {
          putc ('\\', fp);
          count++;
          if (*p == '\n')
            putc ('n', fp);
          else if (*p == '\r')
            putc ('r', fp);
          else if (*p == '\f')
            putc ('f', fp);
          else if (*p == '\v')
            putc ('v', fp);
          else if (*p == '\b')
            putc ('b', fp);
          else if (!*p)
            putc('0', fp);
          else
            {
              fprintf (fp, "x%02x", *p);
              count += 2;
            }
	}
      else
        putc (*p, fp);
    }

  return count;
}

size_t 
print_sanitized_utf8_buffer (FILE *fp, const void *buffer,
                             size_t length, int delim)
{
  const char *p = buffer;
  size_t i;

  /* We can handle plain ascii simpler, so check for it first. */
  for (i=0; i < length; i++ ) 
    {
      if ( (p[i] & 0x80) )
        break;
    }
  if (i < length)
    {
	char *buf = utf8_to_native (p, length, delim);
	/*(utf8 conversion already does the control character quoting)*/
        i = strlen (buf);
	fputs (buf, fp);
	jnlib_free (buf);
        return i;
    }
  else
    return print_sanitized_buffer (fp, p, length, delim);
}


size_t 
print_sanitized_string (FILE *fp, const char *string, int delim)
{
  return string? print_sanitized_buffer (fp, string, strlen (string), delim):0;
}

size_t 
print_sanitized_utf8_string (FILE *fp, const char *string, int delim)
{
  return string? print_sanitized_utf8_buffer (fp,
                                              string, strlen (string),
                                              delim) : 0;
}

/* Create a string from the buffer P_ARG of length N which is suitable for
   printing.  Caller must release the created string using xfree. */
char *
sanitize_buffer (const void *p_arg, size_t n, int delim)
{
  const unsigned char *p = p_arg;
  size_t save_n, buflen;
  const unsigned char *save_p;
  char *buffer, *d;

  /* first count length */
  for (save_n = n, save_p = p, buflen=1 ; n; n--, p++ ) 
    {
      if ( *p < 0x20 || *p == 0x7f || *p == delim  || (delim && *p=='\\'))
        {
          if ( *p=='\n' || *p=='\r' || *p=='\f'
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
  d = buffer = jnlib_xmalloc( buflen );
  for ( ; n; n--, p++ )
    {
      if (*p < 0x20 || *p == 0x7f || *p == delim || (delim && *p=='\\')) {
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


/****************************************************
 **********  W32 specific functions  ****************
 ****************************************************/

#ifdef HAVE_W32_SYSTEM
const char *
w32_strerror (int ec)
{
  static char strerr[256];
  
  if (ec == -1)
    ec = (int)GetLastError ();
  FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, ec,
                 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                 strerr, DIM (strerr)-1, NULL);
  return strerr;    
}
#endif /*HAVE_W32_SYSTEM*/


/****************************************************
 ******** Locale insensitive ctype functions ********
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
ascii_strcasecmp( const char *a, const char *b )
{
    if (a == b)
        return 0;

    for (; *a && *b; a++, b++) {
	if (*a != *b && ascii_toupper(*a) != ascii_toupper(*b))
	    break;
    }
    return *a == *b? 0 : (ascii_toupper (*a) - ascii_toupper (*b));
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
ascii_memcasecmp (const void *a_arg, const void *b_arg, size_t n )
{
  const char *a = a_arg;
  const char *b = b_arg;

  if (a == b)
    return 0;
  for ( ; n; n--, a++, b++ )
    {
      if( *a != *b  && ascii_toupper (*a) != ascii_toupper (*b) )
        return *a == *b? 0 : (ascii_toupper (*a) - ascii_toupper (*b));
    }
  return 0;
}

int
ascii_strcmp( const char *a, const char *b )
{
    if (a == b)
        return 0;

    for (; *a && *b; a++, b++) {
	if (*a != *b )
	    break;
    }
    return *a == *b? 0 : (*(signed char *)a - *(signed char *)b);
}


void *
ascii_memcasemem (const void *haystack, size_t nhaystack,
                  const void *needle, size_t nneedle)
{

  if (!nneedle)
    return (void*)haystack; /* finding an empty needle is really easy */
  if (nneedle <= nhaystack)
    {
      const char *a = haystack;
      const char *b = a + nhaystack - nneedle;
      
      for (; a <= b; a++)
        {
          if ( !ascii_memcasecmp (a, needle, nneedle) )
            return (void *)a;
        }
    }
  return NULL;
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


