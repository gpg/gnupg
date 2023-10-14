/* stringhelp.c -  standard string helper functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010  Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2015, 2021  g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif
#include <limits.h>

#include "util.h"
#include "common-defs.h"
#include "utf8conv.h"
#include "sysutils.h"
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
#ifdef HAVE_DOSISH_SYSTEM
  char *p;

  if (strchr (name, '\\'))
    {
      for (p=name; *p; p++)
        if (*p == '/')
          *p = '\\';
    }
#endif /*HAVE_DOSISH_SYSTEM*/
  return name;
}


/*
 * Check whether STRING starts with KEYWORD.  The keyword is
 * delimited by end of string, a space or a tab.  Returns NULL if not
 * found or a pointer into STRING to the next non-space character
 * after the KEYWORD (which may be end of string).
 */
char *
has_leading_keyword (const char *string, const char *keyword)
{
  size_t n = strlen (keyword);

  if (!strncmp (string, keyword, n)
      && (!string[n] || string[n] == ' ' || string[n] == '\t'))
    {
      string += n;
      while (*string == ' ' || *string == '\t')
        string++;
      return (char*)string;
    }
  return NULL;
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


/* This is a case-sensitive version of our memistr.  I wonder why no
 * standard function memstr exists but we better do not use the name
 * memstr to avoid future conflicts.
 */
const char *
gnupg_memstr (const void *buffer, size_t buflen, const char *sub)
{
  const unsigned char *buf = buffer;
  const unsigned char *t = (const unsigned char *)buf;
  const unsigned char *s = (const unsigned char *)sub;
  size_t n = buflen;

  for ( ; n ; t++, n-- )
    {
      if (*t == *s)
        {
          for (buf = t++, buflen = n--, s++; n && *t ==*s; t++, s++, n--)
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
   will be allocated using xmalloc (i.e. if it runs out of core
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
	    dest = xmalloc( n ) ;
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


/* Same as trim_spaces but only consider, space, tab, cr and lf as space.  */
char *
ascii_trim_spaces (char *str)
{
  char *string, *p, *mark;

  string = str;

  /* Find first non-ascii space character.  */
  for (p=string; *p && ascii_isspace (*p); p++)
    ;
  /* Move characters.  */
  for (mark=NULL; (*string = *p); string++, p++ )
    {
      if (ascii_isspace (*p))
        {
          if (!mark)
            mark = string;
        }
      else
        mark = NULL ;
    }
  if (mark)
    *mark = '\0' ;  /* Remove trailing spaces. */

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



/*
 * Extract from a given path the filename component.  This function
 * terminates the process on memory shortage.
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
#ifdef HAVE_DOSISH_SYSTEM
	if ( !(p=strrchr(filepath, '\\')) )
#endif
#ifdef HAVE_DRIVE_LETTERS
	    if ( !(p=strrchr(filepath, ':')) )
#endif
	      {
		return xstrdup(filepath);
	      }

    return xstrdup(p+1);
#endif
}



/*
 * Extract from a given filename the path prepended to it.  If there
 * isn't a path prepended to the filename, a dot is returned ('.').
 * This function terminates the process on memory shortage.
 */
char *
make_dirname(const char *filepath)
{
    char *dirname;
    int  dirname_length;
    char *p;

    if ( !(p=strrchr(filepath, '/')) )
#ifdef HAVE_DOSISH_SYSTEM
	if ( !(p=strrchr(filepath, '\\')) )
#endif
#ifdef HAVE_DRIVE_LETTERS
	    if ( !(p=strrchr(filepath, ':')) )
#endif
	      {
		return xstrdup(".");
	      }

    dirname_length = p-filepath;
    dirname = xmalloc(dirname_length+1);
    strncpy(dirname, filepath, dirname_length);
    dirname[dirname_length] = 0;

    return dirname;
}



static char *
get_pwdir (int xmode, const char *name)
{
  char *result = NULL;
#ifdef HAVE_PWD_H
  struct passwd *pwd = NULL;

  if (name)
    {
#ifdef HAVE_GETPWNAM
      /* Fixme: We should use getpwnam_r if available.  */
      pwd = getpwnam (name);
#endif
    }
  else
    {
#ifdef HAVE_GETPWUID
      /* Fixme: We should use getpwuid_r if available.  */
      pwd = getpwuid (getuid());
#endif
    }
  if (pwd)
    {
      if (xmode)
        result = xstrdup (pwd->pw_dir);
      else
        result = xtrystrdup (pwd->pw_dir);
    }
#else /*!HAVE_PWD_H*/
  /* No support at all.  */
  (void)xmode;
  (void)name;
#endif /*HAVE_PWD_H*/
  return result;
}


/* xmode 0 := Return NULL on error
         1 := Terminate on error
         2 := Make sure that name is absolute; return NULL on error
         3 := Make sure that name is absolute; terminate on error
 */
static char *
do_make_filename (int xmode, const char *first_part, va_list arg_ptr)
{
  const char *argv[32];
  int argc;
  size_t n;
  int skip = 1;
  char *home_buffer = NULL;
  char *name, *home, *p;
  int want_abs;

  want_abs = !!(xmode & 2);
  xmode &= 1;

  n = strlen (first_part) + 1;
  argc = 0;
  while ( (argv[argc] = va_arg (arg_ptr, const char *)) )
    {
      n += strlen (argv[argc]) + 1;
      if (argc >= DIM (argv)-1)
        {
          if (xmode)
            BUG ();
          gpg_err_set_errno (EINVAL);
          return NULL;
        }
      argc++;
    }
  n++;

  home = NULL;
  if (*first_part == '~')
    {
      if (first_part[1] == '/' || !first_part[1])
        {
          /* This is the "~/" or "~" case.  */
          home = getenv("HOME");
          if (!home)
            home = home_buffer = get_pwdir (xmode, NULL);
          if (home && *home)
            n += strlen (home);
        }
      else
        {
          /* This is the "~username/" or "~username" case.  */
          char *user;

          if (xmode)
            user = xstrdup (first_part+1);
          else
            {
              user = xtrystrdup (first_part+1);
              if (!user)
                return NULL;
            }
          p = strchr (user, '/');
          if (p)
            *p = 0;
          skip = 1 + strlen (user);

          home = home_buffer = get_pwdir (xmode, user);
          xfree (user);
          if (home)
            n += strlen (home);
          else
            skip = 1;
        }
    }

  if (xmode)
    name = xmalloc (n);
  else
    {
      name = xtrymalloc (n);
      if (!name)
        {
          xfree (home_buffer);
          return NULL;
        }
    }

  if (home)
    p = stpcpy (stpcpy (name, home), first_part + skip);
  else
    p = stpcpy (name, first_part);

  xfree (home_buffer);
  for (argc=0; argv[argc]; argc++)
    {
      /* Avoid a leading double slash if the first part was "/".  */
      if (!argc && name[0] == '/' && !name[1])
        p = stpcpy (p, argv[argc]);
      else
        p = stpcpy (stpcpy (p, "/"), argv[argc]);
    }

  if (want_abs)
    {
#ifdef HAVE_DRIVE_LETTERS
      p = strchr (name, ':');
      if (p)
        p++;
      else
        p = name;
#else
      p = name;
#endif
      if (*p != '/'
#ifdef HAVE_DRIVE_LETTERS
          && *p != '\\'
#endif
          )
        {
          home = gnupg_getcwd ();
          if (!home)
            {
              if (xmode)
                {
                  fprintf (stderr, "\nfatal: getcwd failed: %s\n",
                           strerror (errno));
                  exit(2);
                }
              xfree (name);
              return NULL;
            }
          n = strlen (home) + 1 + strlen (name) + 1;
          if (xmode)
            home_buffer = xmalloc (n);
          else
            {
              home_buffer = xtrymalloc (n);
              if (!home_buffer)
                {
                  xfree (home);
                  xfree (name);
                  return NULL;
                }
            }
          if (p == name)
            p = home_buffer;
          else /* Windows case.  */
            {
              memcpy (home_buffer, p, p - name + 1);
              p = home_buffer + (p - name + 1);
            }

          /* Avoid a leading double slash if the cwd is "/".  */
          if (home[0] == '/' && !home[1])
            strcpy (stpcpy (p, "/"), name);
          else
            strcpy (stpcpy (stpcpy (p, home), "/"), name);

          xfree (home);
          xfree (name);
          name = home_buffer;
          /* Let's do a simple compression to catch the most common
             case of using "." for gpg's --homedir option.  */
          n = strlen (name);
          if (n > 2 && name[n-2] == '/' && name[n-1] == '.')
            name[n-2] = 0;
        }
    }
  return change_slashes (name);
}

/* Construct a filename from the NULL terminated list of parts.  Tilde
   expansion is done for the first argument.  This function terminates
   the process on memory shortage. */
char *
make_filename (const char *first_part, ... )
{
  va_list arg_ptr;
  char *result;

  va_start (arg_ptr, first_part);
  result = do_make_filename (1, first_part, arg_ptr);
  va_end (arg_ptr);
  return result;
}

/* Construct a filename from the NULL terminated list of parts.  Tilde
   expansion is done for the first argument.  This function may return
   NULL on error. */
char *
make_filename_try (const char *first_part, ... )
{
  va_list arg_ptr;
  char *result;

  va_start (arg_ptr, first_part);
  result = do_make_filename (0, first_part, arg_ptr);
  va_end (arg_ptr);
  return result;
}

/* Construct an absolute filename from the NULL terminated list of
   parts.  Tilde expansion is done for the first argument.  This
   function terminates the process on memory shortage. */
char *
make_absfilename (const char *first_part, ... )
{
  va_list arg_ptr;
  char *result;

  va_start (arg_ptr, first_part);
  result = do_make_filename (3, first_part, arg_ptr);
  va_end (arg_ptr);
  return result;
}

/* Construct an absolute filename from the NULL terminated list of
   parts.  Tilde expansion is done for the first argument.  This
   function may return NULL on error. */
char *
make_absfilename_try (const char *first_part, ... )
{
  va_list arg_ptr;
  char *result;

  va_start (arg_ptr, first_part);
  result = do_make_filename (2, first_part, arg_ptr);
  va_end (arg_ptr);
  return result;
}



/* Compare whether the filenames are identical.  This is a
   special version of strcmp() taking the semantics of filenames in
   account.  Note that this function works only on the supplied names
   without considering any context like the current directory.  See
   also same_file_p(). */
int
compare_filenames (const char *a, const char *b)
{
#ifdef HAVE_DOSISH_SYSTEM
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


/* Convert a base-10 number in STRING into a 64 bit unsigned int
 * value.  Leading white spaces are skipped but no error checking is
 * done.  Thus it is similar to atoi().  See also scan_secondsstr.  */
uint64_t
string_to_u64 (const char *string)
{
  uint64_t val = 0;

  while (spacep (string))
    string++;
  for (; digitp (string); string++)
    {
      val *= 10;
      val += *string - '0';
    }
  return val;
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

/* Given a string containing an UTF-8 encoded text, return the number
   of characters in this string.  It differs from strlen in that it
   only counts complete UTF-8 characters.  SIZE is the maximum length
   of the string in bytes.  If SIZE is -1, then a NUL character is
   taken to be the end of the string.  Note, that this function does
   not take combined characters into account.  */
size_t
utf8_charcount (const char *s, int len)
{
  size_t n;

  if (len == 0)
    return 0;

  for (n=0; *s; s++)
    {
      if ( (*s&0xc0) != 0x80 ) /* Exclude continuation bytes: 10xxxxxx */
        n++;

      if (len != -1)
        {
          len --;
          if (len == 0)
            break;
        }
    }

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
#ifdef HAVE_W32CE_SYSTEM
  /* There is only a wchar_t FormatMessage.  It does not make much
     sense to play the conversion game; we print only the code.  */
  snprintf (strerr, sizeof strerr, "ec=%d", (int)GetLastError ());
#else
  FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, ec,
                 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                 strerr, DIM (strerr)-1, NULL);
  {
    /* Strip the CR,LF - we want just the string.  */
    size_t n = strlen (strerr);
    if (n > 2 && strerr[n-2] == '\r' && strerr[n-1] == '\n' )
      strerr[n-2] = 0;
  }
#endif
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

/* Lowercase all ASCII characters in S.  */
char *
ascii_strlwr (char *s)
{
  char *p = s;

  for (p=s; *p; p++ )
    if (isascii (*p) && *p >= 'A' && *p <= 'Z')
      *p |= 0x20;

  return s;
}

/* Upcase all ASCII characters in S.  */
char *
ascii_strupr (char *s)
{
  char *p = s;

  for (p=s; *p; p++ )
    if (isascii (*p) && *p >= 'a' && *p <= 'z')
      *p &= ~0x20;

  return s;
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

#ifndef HAVE_STRPBRK
/* Find the first occurrence in S of any character in ACCEPT.
   Code taken from glibc-2.6/string/strpbrk.c (LGPLv2.1+) and modified. */
char *
strpbrk (const char *s, const char *accept)
{
  while (*s != '\0')
    {
      const char *a = accept;
      while (*a != '\0')
	if (*a++ == *s)
	  return (char *) s;
      ++s;
    }

  return NULL;
}
#endif /*!HAVE_STRPBRK*/


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
     character.  Here we don't need to call the expensive 'strpbrk'
     function and instead work using 'strchr'.  */
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
    if (str[i] == ':' || str[i] == '%' || str[i] == '\n'
        || (extra && strchr (extra, str[i])))
      j++;
  if (die)
    ptr = xmalloc (i + 2 * j + 1);
  else
    {
      ptr = xtrymalloc (i + 2 * j + 1);
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
      else if (*str == '\n')
	{
	  /* The newline is problematic in a line-based format.  */
	  ptr[i++] = '%';
	  ptr[i++] = '0';
	  ptr[i++] = 'a';
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
   EXTRA is not NULL all characters in EXTRA are also escaped.  This
   function terminates the process on memory shortage.  */
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


/* Same as strconcat but takes a va_list.  Returns EINVAL if the list
 * is too long, all other errors are due to an ENOMEM condition.  */
char *
vstrconcat (const char *s1, va_list arg_ptr)
{
  const char *argv[48];
  size_t argc;
  size_t needed;
  char *buffer, *p;

  argc = 0;
  argv[argc++] = s1;
  needed = strlen (s1);
  while (((argv[argc] = va_arg (arg_ptr, const char *))))
    {
      needed += strlen (argv[argc]);
      if (argc >= DIM (argv)-1)
        {
          gpg_err_set_errno (EINVAL);
          return NULL;
        }
      argc++;
    }
  needed++;
  buffer = xtrymalloc (needed);
  if (buffer)
    {
      for (p = buffer, argc=0; argv[argc]; argc++)
        p = stpcpy (p, argv[argc]);
    }
  return buffer;
}


/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *
strconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    result = xtrystrdup ("");
  else
    {
      va_start (arg_ptr, s1);
      result = vstrconcat (s1, arg_ptr);
      va_end (arg_ptr);
    }
  return result;
}

/* Same as strconcat but terminate the process with an error message
   if something goes wrong.  */
char *
xstrconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    result = xstrdup ("");
  else
    {
      va_start (arg_ptr, s1);
      result = vstrconcat (s1, arg_ptr);
      va_end (arg_ptr);
    }
  if (!result)
    {
      if (errno == EINVAL)
        fputs ("\nfatal: too many args for xstrconcat\n", stderr);
      else
        fputs ("\nfatal: out of memory\n", stderr);
      exit (2);
    }
  return result;
}

/* Split a string into fields at DELIM.  REPLACEMENT is the character
   to replace the delimiter with (normally: '\0' so that each field is
   NUL terminated).  The caller is responsible for freeing the result.
   Note: this function modifies STRING!  If you need the original
   value, then you should pass a copy to this function.

   If malloc fails, this function returns NULL.  */
char **
strsplit (char *string, char delim, char replacement, int *count)
{
  int fields = 1;
  char *t;
  char **result;

  /* First, count the number of fields.  */
  for (t = strchr (string, delim); t; t = strchr (t + 1, delim))
    fields ++;

  result = xtrycalloc ((fields + 1), sizeof (*result));
  if (! result)
    return NULL;

  result[0] = string;
  fields = 1;
  for (t = strchr (string, delim); t; t = strchr (t + 1, delim))
    {
      result[fields ++] = t + 1;
      *t = replacement;
    }

  if (count)
    *count = fields;

  return result;
}


/* Tokenize STRING using the set of delimiters in DELIM.  Leading
 * spaces and tabs are removed from all tokens.  The caller must xfree
 * the result.
 *
 * Returns: A malloced and NULL delimited array with the tokens.  On
 *          memory error NULL is returned and ERRNO is set.
 */
static char **
do_strtokenize (const char *string, const char *delim, int trim)
{
  const char *s;
  size_t fields;
  size_t bytes, n;
  char *buffer;
  char *p, *px, *pend;
  char **result;

  /* Count the number of fields.  */
  for (fields = 1, s = strpbrk (string, delim); s; s = strpbrk (s + 1, delim))
    fields++;
  fields++; /* Add one for the terminating NULL.  */

  /* Allocate an array for all fields, a terminating NULL, and space
     for a copy of the string.  */
  bytes = fields * sizeof *result;
  if (bytes / sizeof *result != fields)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  n = strlen (string) + 1;
  bytes += n;
  if (bytes < n)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  result = xtrymalloc (bytes);
  if (!result)
    return NULL;
  buffer = (char*)(result + fields);

  /* Copy and parse the string.  */
  strcpy (buffer, string);
  for (n = 0, p = buffer; (pend = strpbrk (p, delim)); p = pend + 1)
    {
      *pend = 0;
      if (trim)
        {
          while (spacep (p))
            p++;
          for (px = pend - 1; px >= p && spacep (px); px--)
            *px = 0;
        }
      result[n++] = p;
    }
  if (trim)
    {
      while (spacep (p))
        p++;
      for (px = p + strlen (p) - 1; px >= p && spacep (px); px--)
        *px = 0;
    }
  result[n++] = p;
  result[n] = NULL;

  log_assert ((char*)(result + n + 1) == buffer);

  return result;
}

/* Tokenize STRING using the set of delimiters in DELIM.  Leading
 * spaces and tabs are removed from all tokens.  The caller must xfree
 * the result.
 *
 * Returns: A malloced and NULL delimited array with the tokens.  On
 *          memory error NULL is returned and ERRNO is set.
 */
char **
strtokenize (const char *string, const char *delim)
{
  return do_strtokenize (string, delim, 1);
}

/* Same as strtokenize but does not trim leading and trailing spaces
 * from the fields.  */
char **
strtokenize_nt (const char *string, const char *delim)
{
  return do_strtokenize (string, delim, 0);
}


/* Split a string into space delimited fields and remove leading and
 * trailing spaces from each field.  A pointer to each field is stored
 * in ARRAY.  Stop splitting at ARRAYSIZE fields.  The function
 * modifies STRING.  The number of parsed fields is returned.
 * Example:
 *
 *   char *fields[2];
 *   if (split_fields (string, fields, DIM (fields)) < 2)
 *     return  // Not enough args.
 *   foo (fields[0]);
 *   foo (fields[1]);
 */
int
split_fields (char *string, char **array, int arraysize)
{
  int n = 0;
  char *p, *pend;

  for (p = string; *p == ' '; p++)
    ;
  do
    {
      if (n == arraysize)
        break;
      array[n++] = p;
      pend = strchr (p, ' ');
      if (!pend)
        break;
      *pend++ = 0;
      for (p = pend; *p == ' '; p++)
        ;
    }
  while (*p);

  return n;
}


/* Split a string into colon delimited fields A pointer to each field
 * is stored in ARRAY.  Stop splitting at ARRAYSIZE fields.  The
 * function modifies STRING.  The number of parsed fields is returned.
 * Note that leading and trailing spaces are not removed from the fields.
 * Example:
 *
 *   char *fields[2];
 *   if (split_fields (string, fields, DIM (fields)) < 2)
 *     return  // Not enough args.
 *   foo (fields[0]);
 *   foo (fields[1]);
 */
int
split_fields_colon (char *string, char **array, int arraysize)
{
  int n = 0;
  char *p, *pend;

  p = string;
  do
    {
      if (n == arraysize)
        break;
      array[n++] = p;
      pend = strchr (p, ':');
      if (!pend)
        break;
      *pend++ = 0;
      p = pend;
    }
  while (*p);

  return n;
}



/* Version number parsing.  */

/* This function parses the first portion of the version number S and
   stores it in *NUMBER.  On success, this function returns a pointer
   into S starting with the first character, which is not part of the
   initial number portion; on failure, NULL is returned.  */
static const char*
parse_version_number (const char *s, int *number)
{
  int val = 0;

  if (*s == '0' && digitp (s+1))
    return NULL;  /* Leading zeros are not allowed.  */
  for (; digitp (s); s++)
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0 ? NULL : s;
}


/* This function breaks up the complete string-representation of the
   version number S, which is of the following struture: <major
   number>.<minor number>[.<micro number>]<patch level>.  The major,
   minor, and micro number components will be stored in *MAJOR, *MINOR
   and *MICRO.  If MICRO is not given 0 is used instead.

   On success, the last component, the patch level, will be returned;
   in failure, NULL will be returned.  */
static const char *
parse_version_string (const char *s, int *major, int *minor, int *micro)
{
  s = parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s)
    return NULL;
  if (*s == '.')
    {
      s++;
      s = parse_version_number (s, micro);
      if (!s)
        return NULL;
    }
  else
    *micro = 0;
  return s;  /* Patchlevel.  */
}


/* Compare the version string MY_VERSION to the version string
 * REQ_VERSION.  Returns -1, 0, or 1 if MY_VERSION is found,
 * respectively, to be less than, to match, or be greater than
 * REQ_VERSION.  This function works for three and two part version
 * strings; for a two part version string the micro part is assumed to
 * be 0.  Patch levels are compared as strings.  If a version number
 * is invalid INT_MIN is returned.  If REQ_VERSION is given as NULL
 * the function returns 0 if MY_VERSION is parsable version string. */
int
compare_version_strings (const char *my_version, const char *req_version)
{
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_patch, *rq_patch;
  int result;

  if (!my_version)
    return INT_MIN;

  my_patch = parse_version_string (my_version, &my_major, &my_minor, &my_micro);
  if (!my_patch)
    return INT_MIN;
  if (!req_version)
    return 0; /* MY_VERSION can be parsed.  */
  rq_patch = parse_version_string (req_version, &rq_major, &rq_minor,&rq_micro);
  if (!rq_patch)
    return INT_MIN;

  if (my_major == rq_major)
    {
      if (my_minor == rq_minor)
        {
          if (my_micro == rq_micro)
            result = strcmp (my_patch, rq_patch);
          else
            result = my_micro - rq_micro;
        }
      else
        result = my_minor - rq_minor;
    }
  else
    result = my_major - rq_major;

  return !result? 0 : result < 0 ? -1 : 1;
}



/* Format a string so that it fits within about TARGET_COLS columns.
 * TEXT_IN is copied to a new buffer, which is returned.  Normally,
 * target_cols will be 72 and max_cols is 80.  On error NULL is
 * returned and ERRNO is set. */
char *
format_text (const char *text_in, int target_cols, int max_cols)
{
  /* const int do_debug = 0; */

  /* The character under consideration.  */
  char *p;
  /* The start of the current line.  */
  char *line;
  /* The last space that we saw.  */
  char *last_space = NULL;
  int last_space_cols = 0;
  int copied_last_space = 0;
  char *text;

  text = xtrystrdup (text_in);
  if (!text)
    return NULL;

  p = line = text;
  while (1)
    {
      /* The number of columns including any trailing space.  */
      int cols;

      p = p + strcspn (p, "\n ");
      if (! p)
        /* P now points to the NUL character.  */
        p = &text[strlen (text)];

      if (*p == '\n')
        /* Pass through any newlines.  */
        {
          p ++;
          line = p;
          last_space = NULL;
          last_space_cols = 0;
          copied_last_space = 1;
          continue;
        }

      /* Have a space or a NUL.  Note: we don't count the trailing
         space.  */
      cols = utf8_charcount (line, (uintptr_t) p - (uintptr_t) line);
      if (cols < target_cols)
        {
          if (! *p)
            /* Nothing left to break.  */
            break;

          last_space = p;
          last_space_cols = cols;
          p ++;
          /* Skip any immediately following spaces.  If we break:
             "... foo bar ..." between "foo" and "bar" then we want:
             "... foo\nbar ...", which means that the left space has
             to be the first space after foo, not the last space
             before bar.  */
          while (*p == ' ')
            p ++;
        }
      else
        {
          int cols_with_left_space;
          int cols_with_right_space;
          int left_penalty;
          int right_penalty;

          cols_with_left_space = last_space_cols;
          cols_with_right_space = cols;

          /* if (do_debug) */
          /*   log_debug ("Breaking: '%.*s'\n", */
          /*              (int) ((uintptr_t) p - (uintptr_t) line), line); */

          /* The number of columns away from TARGET_COLS.  We prefer
             to underflow than to overflow.  */
          left_penalty = target_cols - cols_with_left_space;
          right_penalty = 2 * (cols_with_right_space - target_cols);

          if (cols_with_right_space > max_cols)
            /* Add a large penalty for each column that exceeds
               max_cols.  */
            right_penalty += 4 * (cols_with_right_space - max_cols);

          /* if (do_debug) */
          /*   log_debug ("Left space => %d cols (penalty: %d); " */
          /*              "right space => %d cols (penalty: %d)\n", */
          /*              cols_with_left_space, left_penalty, */
          /*              cols_with_right_space, right_penalty); */
          if (last_space_cols && left_penalty <= right_penalty)
            {
              /* Prefer the left space.  */
              /* if (do_debug) */
              /*   log_debug ("Breaking at left space.\n"); */
              p = last_space;
            }
          else
            {
              /* if (do_debug) */
              /*   log_debug ("Breaking at right space.\n"); */
            }

          if (! *p)
            break;

          *p = '\n';
          p ++;
          if (*p == ' ')
            {
              int spaces;
              for (spaces = 1; p[spaces] == ' '; spaces ++)
                ;
              memmove (p, &p[spaces], strlen (&p[spaces]) + 1);
            }
          line = p;
          last_space = NULL;
          last_space_cols = 0;
          copied_last_space = 0;
        }
    }

  /* Chop off any trailing space.  */
  trim_trailing_chars (text, strlen (text), " ");
  /* If we inserted the trailing newline, then remove it.  */
  if (! copied_last_space && *text && text[strlen (text) - 1] == '\n')
    text[strlen (text) - 1] = '\0';

  return text;
}


/* Substitute variables in STRING and return a new string.  GETVAL is
 * a function which maps NAME to its value; that value is a string
 * which may not change during the execution time of this function.
 * If GETVAL returns NULL substitute_vars returns NULL and the caller
 * may inspect ERRNO for the reason.  In all other error cases this
 * function also returns NULL.  Caller must free the returned string.  */
char *
substitute_vars (const char *string,
                 const char *(*getval)(void *cookie, const char *name),
                 void *cookie)
{
  char *line, *p, *pend;
  const char *value;
  size_t valuelen, n;
  char *result = NULL;

  result = line = xtrystrdup (string);
  if (!result)
    return NULL; /* Ooops */

  while (*line)
    {
      p = strchr (line, '$');
      if (!p)
        goto leave; /* No or no more variables.  */

      if (p[1] == '$') /* Escaped dollar sign. */
        {
          memmove (p, p+1, strlen (p+1)+1);
          line = p + 1;
          continue;
        }

      if (p[1] == '{')
        {
          int count = 0;

          for (pend=p+2; *pend; pend++)
            {
              if (*pend == '{')
                count++;
              else if (*pend == '}')
                {
                  if (--count < 0)
                    break;
                }
            }
          if (!*pend)
            goto leave; /* Unclosed - don't substitute.  */
        }
      else
        {
          for (pend = p+1; *pend && (alnump (pend) || *pend == '_'); pend++)
            ;
        }

      if (p[1] == '{' && *pend == '}')
        {
          int save = *pend;
          *pend = 0;
          value = getval (cookie, p+2);
          *pend++ = save;
        }
      else
        {
          int save = *pend;
          *pend = 0;
          value = getval (cookie, p+1);
          *pend = save;
        }

      if (!value)
        {
          xfree (result);
          return NULL;
        }
      valuelen = strlen (value);
      if (valuelen <= pend - p)
        {
          memcpy (p, value, valuelen);
          p += valuelen;
          n = pend - p;
          if (n)
            memmove (p, p+n, strlen (p+n)+1);
          line = p;
        }
      else
        {
          char *src = result;
          char *dst;

          dst = xtrymalloc (strlen (src) + valuelen + 1);
          if (!dst)
            {
              xfree (result);
              return NULL;
            }
          n = p - src;
          memcpy (dst, src, n);
          memcpy (dst + n, value, valuelen);
          n += valuelen;
          strcpy (dst + n, pend);
          line = dst + n;
          xfree (result);
          result = dst;
        }
    }

 leave:
  return result;
}


/* Helper for substitute_envvars.  */
static const char *
subst_getenv (void *cookie, const char *name)
{
  const char *s;

  (void)cookie;

  s = getenv (name);
  return s? s : "";
}


/* Substitute environment variables in STRING and return a new string.
 * On error the function returns NULL.  */
char *
substitute_envvars (const char *string)
{
  return substitute_vars (string, subst_getenv, NULL);

}
