/* assuan-buffer.c - read and send data
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
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include "assuan-defs.h"


static int
writen ( int fd, const char *buffer, size_t length )
{
  while (length)
    {
      int nwritten = write (fd, buffer, length);
      
      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          return -1; /* write error */
        }
      length -= nwritten;
      buffer += nwritten;
    }
  return 0;  /* okay */
}

/* read an entire line */
static int
readline (int fd, char *buf, size_t buflen, int *r_nread, int *eof)
{
  size_t nleft = buflen;
  char *p;

  *eof = 0;
  *r_nread = 0;
  while (nleft > 0)
    {
      int n = read (fd, buf, nleft);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1; /* read error */
        }
      else if (!n)
        {
          *eof = 1;
          break; /* allow incomplete lines */
        }
      p = buf;
      nleft -= n;
      buf += n;
      *r_nread += n;
      
      for (; n && *p != '\n'; n--, p++)
        ;
      if (n)
        break; /* at least one full line available - that's enough for now */
    }

  return 0;
}


int
_assuan_read_line (ASSUAN_CONTEXT ctx)
{
  char *line = ctx->inbound.line;
  int n, nread;
  int rc;
  
  if (ctx->inbound.eof)
    return -1;

  if (ctx->inbound.attic.linelen)
    {
      memcpy (line, ctx->inbound.attic.line, ctx->inbound.attic.linelen);
      nread = ctx->inbound.attic.linelen;
      ctx->inbound.attic.linelen = 0;
      for (n=0; n < nread && line[n] != '\n'; n++)
        ;
      if (n < nread)
        rc = 0; /* found another line in the attic */
      else
        { /* read the rest */
          n = nread;
          assert (n < LINELENGTH);
          rc = readline (ctx->inbound.fd, line + n, LINELENGTH - n,
                         &nread, &ctx->inbound.eof);
        }
    }
  else
    rc = readline (ctx->inbound.fd, line, LINELENGTH,
                   &nread, &ctx->inbound.eof);
  if (rc)
    return ASSUAN_Read_Error;
  if (!nread)
    {
      assert (ctx->inbound.eof);
      return -1; 
    }

  for (n=0; n < nread; n++)
    {
      if (line[n] == '\n')
        {
          if (n+1 < nread)
            {
              n++;
              /* we have to copy the rest because the handlers are
                 allowed to modify the passed buffer */
              memcpy (ctx->inbound.attic.line, line+n, nread-n);
              ctx->inbound.attic.linelen = nread-n;
              n--;
            }
          if (n && line[n-1] == '\r')
            n--;
          line[n] = 0;
          ctx->inbound.linelen = n;
          return 0;
        }
    }

  *line = 0;
  ctx->inbound.linelen = 0;
  return ctx->inbound.eof? ASSUAN_Line_Not_Terminated : ASSUAN_Line_Too_Long;
}




int 
_assuan_write_line (ASSUAN_CONTEXT ctx, const char *line )
{
  int rc;

  /* fixme: we should do some kind of line buffering */
  rc = writen (ctx->outbound.fd, line, strlen(line));
  if (rc)
    rc = ASSUAN_Write_Error;
  if (!rc)
    {
      rc = writen (ctx->outbound.fd, "\n", 1);
      if (rc)
        rc = ASSUAN_Write_Error;
    }

  return rc;
}



/* Write out the data in buffer as datalines with line wrapping and
   percent escaping.  This fucntion is used for GNU's custom streams */
int
_assuan_cookie_write_data (void *cookie, const char *buffer, size_t size)
{
  ASSUAN_CONTEXT ctx = cookie;
  char *line;
  size_t linelen;

  if (ctx->outbound.data.error)
    return 0;

  line = ctx->outbound.data.line;
  linelen = ctx->outbound.data.linelen;
  line += linelen;
  while (size)
    {
      /* insert data line header */
      if (!linelen)
        {
          *line++ = 'D';
          *line++ = ' ';
          linelen += 2;
        }
      
      /* copy data, keep some space for the CRLF and to escape one character */
      while (size && linelen < LINELENGTH-2-2)
        {
          if (*buffer == '%' || *buffer == '\r' || *buffer == '\n')
            {
              sprintf (line, "%%%02X", *(unsigned char*)buffer);
              line += 3;
              linelen += 3;
              buffer++;
            }
          else
            {
              *line++ = *buffer++;
              linelen++;
            }
          size--;
        }
      
      if (linelen >= LINELENGTH-2-2)
        {
          *line++ = '\n';
          linelen++;
          if (writen (ctx->outbound.fd, ctx->outbound.data.line, linelen))
            {
              ctx->outbound.data.error = ASSUAN_Write_Error;
              return 0;
            }
          line = ctx->outbound.data.line;
          linelen = 0;
        }
    }

  ctx->outbound.data.linelen = linelen;
  return 0;
}


/* Write out any buffered data 
   This fucntion is used for GNU's custom streams */
int
_assuan_cookie_write_flush (void *cookie)
{
  ASSUAN_CONTEXT ctx = cookie;
  char *line;
  size_t linelen;

  if (ctx->outbound.data.error)
    return 0;

  line = ctx->outbound.data.line;
  linelen = ctx->outbound.data.linelen;
  line += linelen;
  if (linelen)
    {
      *line++ = '\n';
      linelen++;
      if (writen (ctx->outbound.fd, ctx->outbound.data.line, linelen))
        {
          ctx->outbound.data.error = ASSUAN_Write_Error;
          return 0;
        }
      ctx->outbound.data.linelen = 0;
    }
  return 0;
}




