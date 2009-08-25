/* compat.c - Simple compatibility functions
 * Copyright (C) 2006, 2007, 2009 Free Software Foundation, Inc.
 *
 * The origin of this code is GnuPG.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * History:
 * 2006-09-28 dshaw  Created.  Added function hextobyte from GnuPG.
 * 2007-04-16 dshaw  Added ascii_toupper, ascii_tolower, ascii_strcasecmp,
 *                   ascii_strncasecmp from GnuPG.
 * 2009-08-25 wk     License changed by GnuPG maintainer from GPL with 
 *                   OpenSSL exception to this all permissive license.
 * 2009-08-25 wk     Wrote new function xstrconcat.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

/* We require an external malloc function named xtrymalloc.  */
void *xtrymalloc (size_t n);


#ifndef DIM
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#endif



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


static char *
do_strconcat (const char *s1, va_list arg_ptr)
{
  const char *argv[48];
  size_t argc;
  size_t needed;
  char *buffer, *p;
  const char *r;

  argc = 0;
  argv[argc++] = s1;
  needed = strlen (s1);
  while (((argv[argc] = va_arg (arg_ptr, const char *))))
    {
      needed += strlen (argv[argc]);
      if (argc >= DIM (argv)-1)
        {
          errno = EINVAL;
          return NULL;
        }
      argc++;
    }
  needed++;
  buffer = xtrymalloc (needed);
  if (buffer)
    {
      for (p = buffer, argc=0; argv[argc]; argc++)
        {
          for (r = argv[argc]; *r; )
            *p++ = *r++;
          *p = 0;
        }
    }
  return buffer;
}


/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer.  */
char *
xstrconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    {
      result = xtrymalloc (1);
      if (result)
        *result = 0;
    }
  else
    {
      va_start (arg_ptr, s1);
      result = do_strconcat (s1, arg_ptr);
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

