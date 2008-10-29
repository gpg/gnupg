/* stringhelp.c -  standard string helper functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005,
 *               2006, 2007, 2008  Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
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


#define tohex_lower(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'a'))

/* Sometimes we want to avoid mixing slashes and backslashes on W32
   and prefer backslashes.  There is usual no problem with mixing
   them, however a very few W32 API calls can't grok plain slashes.
   Printing filenames with mixed slashes also looks a bit strange.
   This function has no effext on POSIX. */
static inline char *
change_slashes (char *name)
{
  char *p;

#ifdef HAVE_DRIVE_LETTERS
  if (strchr (name, '\\'))
    {
      for (p=name; *p; p++)
        if (*p == '/')
          *p = '\\';
    }
#endif /*HAVE_DRIVE_LETTERS*/
  return name;
}


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

/*
 *  Return the length of line ignoring trailing white-space.
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
make_basename(const char *filepath, const char *inputpath)
{
#ifdef __riscos__
    return riscos_make_basename(filepath, inputpath);
#else
    char *p;

    (void)inputpath; /* Only required for riscos.  */

    if ( !(p=strrchr(filepath, '/')) )
#ifdef HAVE_DRIVE_LETTERS
	if ( !(p=strrchr(filepath, '\\')) )
	    if ( !(p=strrchr(filepath, ':')) )
#endif
	      {
		return jnlib_xstrdup(filepath);
	      }

    return jnlib_xstrdup(p+1);
#endif
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



/* Implementation of make_filename and make_filename_try.  We need to
   use macros here toa void the use of the soemtimes problematic
   va_copy fucntion which is not available on all systems.  */
#define MAKE_FILENAME_PART1                        \
  va_list arg_ptr;                                 \
  size_t n;                                        \
  const char *s;                                   \
  char *name, *home, *p;                           \
                                                   \
  va_start (arg_ptr, first_part);                  \
  n = strlen (first_part) + 1;                     \
  while ( (s = va_arg (arg_ptr, const char *)) )   \
    n += strlen(s) + 1;                            \
  va_end(arg_ptr);                                 \
                                                   \
  home = NULL;                                     \
  if ( *first_part == '~' && first_part[1] == '/'  \
       && (home = getenv("HOME")) && *home )       \
    n += strlen (home);                            
  
#define MAKE_FILENAME_PART2                         \
  p = (home                                         \
       ? stpcpy (stpcpy (name,home), first_part + 1)\
       : stpcpy(name, first_part));                 \
                                                    \
  va_start (arg_ptr, first_part);                   \
  while ( (s = va_arg(arg_ptr, const char *)) )     \
    p = stpcpy (stpcpy (p,"/"), s);                 \
  va_end(arg_ptr);                                  \
  return change_slashes (name);


/* Construct a filename from the NULL terminated list of parts.  Tilde
   expansion is done here.  This function will never fail. */
char *
make_filename (const char *first_part, ... )
{
  MAKE_FILENAME_PART1
  name = jnlib_xmalloc (n);
  MAKE_FILENAME_PART2
}

/* Construct a filename from the NULL terminated list of parts.  Tilde
   expansion is done here.  This function may return NULL on error. */
char *
make_filename_try (const char *first_part, ... )
{
  MAKE_FILENAME_PART1
  name = jnlib_xmalloc (n);
  if (!name)
    return NULL;
  MAKE_FILENAME_PART2
}
#undef MAKE_FILENAME_PART1
#undef MAKE_FILENAME_PART2



/* Compare whether the filenames are identical.  This is a
   special version of strcmp() taking the semantics of filenames in
   account.  Note that this function works only on the supplied names
   without considereing any context like the current directory.  See
   also same_file_p(). */
int
compare_filenames (const char *a, const char *b)
{
#ifdef HAVE_DRIVE_LETTERS
  for ( ; *a && *b; a++, b++ ) 
    {
      if (*a != *b 
          && (toupper (*(const unsigned char*)a)
              != toupper (*(const unsigned char*)b) )
          && !((*a == '/' && *b == '\\') || (*a == '\\' && *b == '/')))
        break;
    }
  if ((*a == '/' && *b == '\\') || (*a == '\\' && *b == '/'))
    return 0;
  else
    return (toupper (*(const unsigned char*)a) 
            - toupper (*(const unsigned char*)b));
#else
    return strcmp(a,b);
#endif
}


/* Convert 2 hex characters at S to a byte value.  Return this value
   or -1 if there is an error. */
int
hextobyte (const char *s)
{
  int c;

  if ( *s >= '0' && *s <= '9' )
    c = 16 * (*s - '0');
  else if ( *s >= 'A' && *s <= 'F' )
    c = 16 * (10 + *s - 'A');
  else if ( *s >= 'a' && *s <= 'f' )
    c = 16 * (10 + *s - 'a');
  else
    return -1;
  s++;
  if ( *s >= '0' && *s <= '9' )
    c += *s - '0';
  else if ( *s >= 'A' && *s <= 'F' )
    c += 10 + *s - 'A';
  else if ( *s >= 'a' && *s <= 'f' )
    c += 10 + *s - 'a';
  else
    return -1;
  return c;
}


/* Print a BUFFER to stream FP while replacing all control characters
   and the characters DELIM and DELIM2 with standard C escape
   sequences.  Returns the number of characters printed. */
size_t 
print_sanitized_buffer2 (FILE *fp, const void *buffer, size_t length,
                         int delim, int delim2)
{
  const unsigned char *p = buffer;
  size_t count = 0;

  for (; length; length--, p++, count++)
    {
      if (*p < 0x20 
          || *p == 0x7f
          || *p == delim 
          || *p == delim2
          || ((delim || delim2) && *p=='\\'))
        {
          putc ('\\', fp);
          count++;
          if (*p == '\n')
            {
              putc ('n', fp);
              count++;
            }
          else if (*p == '\r')
            {
              putc ('r', fp);
              count++;
            }
          else if (*p == '\f')
            {
              putc ('f', fp);
              count++;
            }
          else if (*p == '\v')
            {
              putc ('v', fp);
              count++;
            }
          else if (*p == '\b')
            {
              putc ('b', fp);
              count++;
            }
          else if (!*p)
            {
              putc('0', fp);
              count++;
            }
          else
            {
              fprintf (fp, "x%02x", *p);
              count += 3;
            }
	}
      else
        {
          putc (*p, fp);
          count++;
        }
    }

  return count;
}

/* Same as print_sanitized_buffer2 but with just one delimiter. */
size_t 
print_sanitized_buffer (FILE *fp, const void *buffer, size_t length,
                        int delim)
{
  return print_sanitized_buffer2 (fp, buffer, length, delim, 0);
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
print_sanitized_string2 (FILE *fp, const char *string, int delim, int delim2)
{
  return string? print_sanitized_buffer2 (fp, string, strlen (string),
                                          delim, delim2):0;
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

  /* First count length. */
  for (save_n = n, save_p = p, buflen=1 ; n; n--, p++ ) 
    {
      if ( *p < 0x20 || *p == 0x7f || *p == delim  || (delim && *p=='\\'))
        {
          if ( *p=='\n' || *p=='\r' || *p=='\f'
               || *p=='\v' || *p=='\b' || !*p )
            buflen += 2;
          else
            buflen += 5;
	}
      else
        buflen++;
    }
  p = save_p;
  n = save_n;
  /* And now make the string */
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
          d += 3;
        }
      }
      else
        *d++ = *p;
    }
  *d = 0;
  return buffer;
}


/* Given a string containing an UTF-8 encoded text, return the number
   of characters in this string.  It differs from strlen in that it
   only counts complete UTF-8 characters.  Note, that this function
   does not take combined characters into account.  */
size_t
utf8_charcount (const char *s)
{
  size_t n;

  for (n=0; *s; s++)
    if ( (*s&0xc0) != 0x80 ) /* Exclude continuation bytes: 10xxxxxx */
      n++;

  return n;
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

#ifndef HAVE_STRSEP
/* Code taken from glibc-2.2.1/sysdeps/generic/strsep.c. */
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


#ifndef HAVE_MEMRCHR
void *
memrchr (const void *buffer, int c, size_t n)
{
  const unsigned char *p = buffer;

  for (p += n; n ; n--)
    if (*--p == c)
      return (void *)p;
  return NULL;
}
#endif /*HAVE_MEMRCHR*/


/* Percent-escape the string STR by replacing colons with '%3a'.  If
   EXTRA is not NULL all characters in EXTRA are also escaped.  */
static char *
do_percent_escape (const char *str, const char *extra, int die)
{
  int i, j;
  char *ptr;

  if (!str)
    return NULL;

  for (i=j=0; str[i]; i++)
    if (str[i] == ':' || str[i] == '%' || (extra && strchr (extra, str[i])))
      j++;
  if (die)
    ptr = jnlib_xmalloc (i + 2 * j + 1);
  else
    {
      ptr = jnlib_malloc (i + 2 * j + 1);
      if (!ptr)
        return NULL;
    }
  i = 0;
  while (*str)
    {
      if (*str == ':')
	{
	  ptr[i++] = '%';
	  ptr[i++] = '3';
	  ptr[i++] = 'a';
	}
      else if (*str == '%')
	{
	  ptr[i++] = '%';
	  ptr[i++] = '2';
	  ptr[i++] = '5';
	}
      else if (extra && strchr (extra, *str))
        {
	  ptr[i++] = '%';
          ptr[i++] = tohex_lower ((*str>>4)&15);
          ptr[i++] = tohex_lower (*str&15);
        }
      else
	ptr[i++] = *str;
      str++;
    }
  ptr[i] = '\0';

  return ptr;
}

/* Percent-escape the string STR by replacing colons with '%3a'.  If
   EXTRA is not NULL all characters in EXTRA are also escaped.  */
char *
percent_escape (const char *str, const char *extra)
{
  return do_percent_escape (str, extra, 1);
}

/* Same as percent_escape but return NULL instead of exiting on memory
   error. */
char *
try_percent_escape (const char *str, const char *extra)
{
  return do_percent_escape (str, extra, 0);
}
