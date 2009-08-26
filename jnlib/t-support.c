/* t-support.c - helper functions for the regression tests.
 * Copyright (C) 2007 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "t-support.h"


/* Replacements for the malloc functions as used here. */

static void
out_of_memory (void)
{
  fprintf (stderr,"error: out of core in regression tests: %s\n",
           strerror (errno));
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
  strcpy (p, string);
  return p;
}

void
gcry_free (void *a)
{
  if (a)
    free (a);
}



/* Stubs for gpg-error functions required because some compilers do
   not eliminate the supposed-to-be-unused-inline-functions and thus
   require functions called from these inline fucntions.  Although we
   do not use gpg-error, gpg-error.h may get included via gcrypt.h if
   it happens to be used used in libjnlib-config.h.  */
int
gpg_err_code_from_errno (int err)
{
  (void)err;
  assert (!"stub function");
  return -1;
}


/* Retrieve the error code directly from the ERRNO variable.  This
   returns GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped
   (report this) and GPG_ERR_MISSING_ERRNO if ERRNO has the value 0. */
int
gpg_err_code_from_syserror (void)
{
  assert (!"stub function");
  return -1;
}



