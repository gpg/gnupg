/* assuan-inquire.c - handle inquire stuff
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

#define digitp(a) ((a) >= '0' && (a) <= '9')
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


struct membuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
  int too_large;
  size_t maxlen;
};



/* A simple implemnation of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  */

static void
init_membuf (struct membuf *mb, int initiallen, size_t maxlen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->too_large = 0;
  mb->maxlen = maxlen;
  /* we need to allocate one byte more for get_membuf */
  mb->buf = xtrymalloc (initiallen+1);
  if (!mb->buf)
      mb->out_of_core = 1;
}

static void
put_membuf (struct membuf *mb, const void *buf, size_t len)
{
  if (mb->out_of_core || mb->too_large)
    return;

  if (mb->maxlen && mb->len + len > mb->maxlen)
    {
      mb->too_large = 1;
      return;
    }

  if (mb->len + len >= mb->size)
    {
      char *p;
      
      mb->size += len + 1024;
      /* we need to allocate one byte more for get_membuf */
      p = xtryrealloc (mb->buf, mb->size+1);
      if (!p)
        {
          mb->out_of_core = 1;
          return;
        }
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}

static void *
get_membuf (struct membuf *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core || mb->too_large)
    {
      xfree (mb->buf);
      mb->buf = NULL;
      return NULL;
    }

  mb->buf[mb->len] = 0; /* there is enough space for the hidden eos */
  p = mb->buf;
  *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = 1; /* don't allow a reuse */
  return p;
}

static void
free_membuf (struct membuf *mb)
{
  xfree (mb->buf);
  mb->buf = NULL;
}


/**
 * assuan_inquire:
 * @ctx: An assuan context
 * @keyword: The keyword used for the inquire
 * @r_buffer: Returns an allocated buffer
 * @r_length: Returns the length of this buffer
 * @maxlen: If not 0, the size limit of the inquired data.
 * 
 * A Server may use this to Send an inquire.  r_buffer, r_length and
 * maxlen may all be NULL/0 to indicate that no real data is expected.
 * 
 * Return value: 0 on success or an ASSUAN error code
 **/
AssuanError
assuan_inquire (ASSUAN_CONTEXT ctx, const char *keyword,
                char **r_buffer, size_t *r_length, size_t maxlen)
{
  AssuanError rc;
  struct membuf mb;
  char cmdbuf[100];
  unsigned char *line, *p;
  int linelen;
  int nodataexpected;

  if (!ctx || !keyword || (10 + strlen (keyword) >= sizeof (cmdbuf)))
    return ASSUAN_Invalid_Value;
  nodataexpected = !r_buffer && !r_length && !maxlen;
  if (!nodataexpected && (!r_buffer || !r_length))
    return ASSUAN_Invalid_Value;
  if (!ctx->is_server)
    return ASSUAN_Not_A_Server;
  if (ctx->in_inquire)
    return ASSUAN_Nested_Commands;
  
  ctx->in_inquire = 1;
  if (nodataexpected)
    memset (&mb, 0, sizeof mb); /* avoid compiler warnings */
  else
    init_membuf (&mb, maxlen? maxlen:1024, maxlen);

  strcpy (stpcpy (cmdbuf, "INQUIRE "), keyword);
  rc = assuan_write_line (ctx, cmdbuf);
  if (rc)
    goto leave;

  for (;;)
    {
      do 
        {
          rc = _assuan_read_line (ctx);
          if (rc)
            goto leave;
          line = ctx->inbound.line;
          linelen = ctx->inbound.linelen;
        }    
      while (*line == '#' || !linelen);
      if (line[0] == 'E' && line[1] == 'N' && line[2] == 'D'
          && (!line[3] || line[3] == ' '))
        break; /* END command received*/
      if (line[0] == 'C' && line[1] == 'A' && line[2] == 'N')
        {
          rc = ASSUAN_Canceled;
          goto leave;
        }
      if (line[0] != 'D' || line[1] != ' ' || nodataexpected)
        {
          rc = ASSUAN_Unexpected_Command;
          goto leave;
        }
      if (linelen < 3)
        continue;
      line += 2;
      linelen -= 2;

      p = line;
      while (linelen)
        {
          for (;linelen && *p != '%'; linelen--, p++)
            ;
          put_membuf (&mb, line, p-line);
          if (linelen > 2)
            { /* handle escaping */
              unsigned char tmp[1];
              p++;
              *tmp = xtoi_2 (p);
              p += 2;
              linelen -= 3;
              put_membuf (&mb, tmp, 1);
            }
          line = p;
        }
      if (mb.too_large)
        {
          rc = ASSUAN_Too_Much_Data;
          goto leave;
        }
    }

  if (!nodataexpected)
    {
      *r_buffer = get_membuf (&mb, r_length);
      if (!*r_buffer)
        rc = ASSUAN_Out_Of_Core;
    }

 leave:
  if (!nodataexpected)
    free_membuf (&mb);
  ctx->in_inquire = 0;
  return rc;
}






