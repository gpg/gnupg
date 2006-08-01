/* no-libgcrypt.c - Replacement functions for libgcrypt.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
out_of_core (void)
{
  log_fatal (_("error allocating enough memory: %s\n"), strerror (errno));
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
    out_of_core ();
  return p;
}

char *
gcry_strdup (const char *string)
{
  return malloc (strlen (string)+1);
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
    out_of_core ();
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
    out_of_core ();
  return p;
}


char *
gcry_xstrdup (const char *string)
{
  void *p = malloc (strlen (string)+1);
  if (!p)
    out_of_core ();
  strcpy( p, string );
  return p;
}

void
gcry_free (void *a)
{
  if (a)
    free (a);
}
