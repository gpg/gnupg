/* assuan-util.c - Utility functions for Assuan 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <string.h>

#include "assuan-defs.h"

#ifdef HAVE_JNLIB_LOGGING
#include "../jnlib/logging.h"
#endif

ssize_t (*_assuan_read_wrapper)(int,void*,size_t) = NULL;
ssize_t (*_assuan_write_wrapper)(int,const void*,size_t) = NULL;


static void *(*alloc_func)(size_t n) = malloc;
static void *(*realloc_func)(void *p, size_t n) = realloc;
static void (*free_func)(void*) = free;



void
assuan_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                          void *(*new_realloc_func)(void *p, size_t n),
                          void (*new_free_func)(void*) )
{
  alloc_func	    = new_alloc_func;
  realloc_func      = new_realloc_func;
  free_func	    = new_free_func;
}

void *
_assuan_malloc (size_t n)
{
  return alloc_func (n);
}

void *
_assuan_realloc (void *a, size_t n)
{
  return realloc_func (a, n);
}

void *
_assuan_calloc (size_t n, size_t m)
{
  void *p = _assuan_malloc (n*m);
  if (p)
    memset (p, 0, n* m);
  return p;
}

void
_assuan_free (void *p)
{
  if (p)
    free_func (p);
}

/* For use with Pth it is required to have special read and write
   functions.  We can't assume an ELF based system so we have to
   explicitly set them if we are going to use Pth. */
void
assuan_set_io_func (ssize_t (*r)(int,void*,size_t),
                    ssize_t (*w)(int,const void*,size_t))
{
  _assuan_read_wrapper = r;
  _assuan_write_wrapper = w;
}



/* Store the error in the context so that the error sending function
  can take out a descriptive text.  Inside the assuan code, use the
  macro set_error instead of this function. */
int
assuan_set_error (ASSUAN_CONTEXT ctx, int err, const char *text)
{
  ctx->err_no = err;
  ctx->err_str = text;
  return err;
}

void
assuan_set_pointer (ASSUAN_CONTEXT ctx, void *pointer)
{
  if (ctx)
    ctx->user_pointer = pointer;
}

void *
assuan_get_pointer (ASSUAN_CONTEXT ctx)
{
  return ctx? ctx->user_pointer : NULL;
}


void
assuan_set_log_stream (ASSUAN_CONTEXT ctx, FILE *fp)
{
  if (ctx)
    {
      if (ctx->log_fp)
        fflush (ctx->log_fp);
      ctx->log_fp = fp;
    }
}


void
assuan_begin_confidential (ASSUAN_CONTEXT ctx)
{
  if (ctx)
    {
      ctx->confidential = 1;
    }
}

void
assuan_end_confidential (ASSUAN_CONTEXT ctx)
{
  if (ctx)
    {
      ctx->confidential = 0;
    }
}

void
_assuan_log_print_buffer (FILE *fp, const void *buffer, size_t length)
{
  const unsigned char *s;
  int n;

  for (n=length,s=buffer; n; n--, s++)
    {
      if (*s < ' ' || (*s >= 0x7f && *s <= 0xa0))
        break;
    }
  s = buffer;
  if (!n && *s != '[')
    fwrite (buffer, length, 1, fp);
  else
    {
      putc ('[', fp);
      for (n=0; n < length; n++, s++)
          fprintf (fp, " %02x", *s);
      putc (' ', fp);
      putc (']', fp);
    }
}


/* print a user supplied string after filtering out potential bad
   characters*/
void
_assuan_log_sanitized_string (const char *string)
{
  const unsigned char *s = string;
#ifdef HAVE_JNLIB_LOGGING
  FILE *fp = log_get_stream ();
#else
  FILE *fp = stderr;
#endif

  for (; *s; s++)
    {
      if (*s < 0x20 || (*s >= 0x7f && *s <= 0xa0))
        {
          putc ('\\', fp);
          if (*s == '\n')
            putc ('n', fp);
          else if (*s == '\r')
            putc ('r', fp);
          else if (*s == '\f')
            putc ('f', fp);
          else if (*s == '\v')
            putc ('v', fp);
          else if (*s == '\b')
            putc ('b', fp);
          else if (!*s)
            putc ('0', fp);
          else
            fprintf (fp, "x%02x", *s );
	}
      else
        putc (*s, fp);
    }
}


