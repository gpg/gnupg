/* no-libgcrypt.c - Replacement functions for libgcrypt.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 * 
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../common/util.h"
#include "i18n.h"


/* Replace libgcrypt's malloc functions which are used by
   ../jnlib/libjnlib.a .  ../common/util.h defines macros to map them
   to xmalloc etc. */
static void
out_of_memory (void)
{
  fprintf (stderr, "error allocating enough memory: %s\n", strerror (errno));
  exit (2);
}


void *
gcry_malloc (size_t n)
{
  return malloc (n);
}

void *
gcry_xmalloc (size_t n)
{
  void *p = malloc (n);
  if (!p)
    out_of_memory ();
  return p;
}

char *
gcry_strdup (const char *string)
{
  char *p = malloc (strlen (string)+1);
  if (p)
    strcpy (p, string);
  return p;
}


void *
gcry_realloc (void *a, size_t n)
{
  return realloc (a, n);
}

void *
gcry_xrealloc (void *a, size_t n)
{
  void *p = realloc (a, n);
  if (!p)
    out_of_memory ();
  return p;
}



void *
gcry_calloc (size_t n, size_t m)
{
  return calloc (n, m);
}

void *
gcry_xcalloc (size_t n, size_t m)
{
  void *p = calloc (n, m);
  if (!p)
    out_of_memory ();
  return p;
}


char *
gcry_xstrdup (const char *string)
{
  void *p = malloc (strlen (string)+1);
  if (!p)
    out_of_memory ();
  strcpy( p, string );
  return p;
}

void
gcry_free (void *a)
{
  if (a)
    free (a);
}
