/* assuan-util.c - Utility functions for Assuan 
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
 * Copyright (C) 2005 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Please note that this is a stripped down and modified version of
   the orginal Assuan code from libassuan. */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "assuan-defs.h"



/* Store the error in the context so that the error sending function
  can take out a descriptive text.  Inside the assuan code, use the
  macro set_error instead of this function. */
int
assuan_set_error (assuan_context_t ctx, int err, const char *text)
{
  ctx->err_no = err;
  ctx->err_str = text;
  return err;
}

void
assuan_set_pointer (assuan_context_t ctx, void *pointer)
{
  if (ctx)
    ctx->user_pointer = pointer;
}

void *
assuan_get_pointer (assuan_context_t ctx)
{
  return ctx? ctx->user_pointer : NULL;
}


void
assuan_set_log_stream (assuan_context_t ctx, FILE *fp)
{
  if (ctx)
    {
      if (ctx->log_fp)
        fflush (ctx->log_fp);
      ctx->log_fp = fp;
      _assuan_set_default_log_stream (fp);
    }
}


void
assuan_begin_confidential (assuan_context_t ctx)
{
  if (ctx)
    {
      ctx->confidential = 1;
    }
}

void
assuan_end_confidential (assuan_context_t ctx)
{
  if (ctx)
    {
      ctx->confidential = 0;
    }
}

/* Dump a possibly binary string (used for debugging).  Distinguish
   ascii text from binary and print it accordingly.  */
void
_assuan_log_print_buffer (FILE *fp, const void *buffer, size_t length)
{
  const unsigned char *s;
  int n;

  for (n=length,s=buffer; n; n--, s++)
    if  ((!isascii (*s) || iscntrl (*s) || !isprint (*s)) && !(*s >= 0x80))
      break;

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

/* Log a user-supplied string.  Escapes non-printable before
   printing.  */
void
_assuan_log_sanitized_string (const char *string)
{
  const unsigned char *s = string;
  FILE *fp = assuan_get_assuan_log_stream ();

  if (! *s)
    return;

  for (; *s; s++)
    {
      int c = 0;

      switch (*s)
	{
	case '\r':
	  c = 'r';
	  break;

	case '\n':
	  c = 'n';
	  break;

	case '\f':
	  c = 'f';
	  break;

	case '\v':
	  c = 'v';
	  break;

	case '\b':
	  c = 'b';
	  break;

	default:
	  if ((isascii (*s) && isprint (*s)) || (*s >= 0x80))
	    putc (*s, fp);
	  else
	    {
	      putc ('\\', fp);
	      fprintf (fp, "x%02x", *s);
	    }
	}

      if (c)
	{
	  putc ('\\', fp);
	  putc (c, fp);
	}
    }
}

