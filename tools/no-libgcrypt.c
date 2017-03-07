/* no-libgcrypt.c - Replacement functions for libgcrypt.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../common/util.h"
#include "../common/i18n.h"


/* Replace libgcrypt's malloc functions which are used by
   ../common/libcommon.a .  ../common/util.h defines macros to map them
   to xmalloc etc. */
static void
out_of_memory (void)
{
  log_fatal (_("error allocating enough memory: %s\n"), strerror (errno));
}


void *
gcry_malloc (size_t n)
{
  return malloc (n);
}

void *
gcry_malloc_secure (size_t n)
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


/* We need this dummy because exechelp.c uses gcry_control to
   terminate the secure memeory.  */
gcry_error_t
gcry_control (enum gcry_ctl_cmds cmd, ...)
{
  (void)cmd;
  return 0;
}

void
gcry_set_outofcore_handler (gcry_handler_no_mem_t h, void *opaque)
{
  (void)h;
  (void)opaque;
}

void
gcry_set_fatalerror_handler (gcry_handler_error_t fnc, void *opaque)
{
  (void)fnc;
  (void)opaque;
}

void
gcry_set_log_handler (gcry_handler_log_t f, void *opaque)
{
  (void)f;
  (void)opaque;
}


void
gcry_create_nonce (void *buffer, size_t length)
{
  (void)buffer;
  (void)length;

  log_fatal ("unexpected call to gcry_create_nonce\n");
}


const char *
gcry_cipher_algo_name (int algo)
{
  (void)algo;
  return "?";
}
