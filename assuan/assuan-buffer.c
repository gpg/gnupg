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
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include "assuan-defs.h"

#ifdef HAVE_JNLIB_LOGGING
#include "../jnlib/logging.h"
#endif


static const char *
my_log_prefix (void)
{
#ifdef HAVE_JNLIB_LOGGING
  return log_get_prefix (NULL);
#else
  return "";
#endif
}


static int
writen ( int fd, const char *buffer, size_t length )
{
  while (length)
    {
      int nwritten = _assuan_write_wrapper?
        _assuan_write_wrapper (fd, buffer, length):
        write (fd, buffer, length);
      
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
      int n = _assuan_read_wrapper?
        _assuan_read_wrapper (fd, buf, nleft):
        read (fd, buf, nleft);

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
  int n, nread, atticlen;
  int rc;

  if (ctx->inbound.eof)
    return -1;

  atticlen = ctx->inbound.attic.linelen;
  if (atticlen)
    {
      memcpy (line, ctx->inbound.attic.line, atticlen);
      ctx->inbound.attic.linelen = 0;
      for (n=0; n < atticlen && line[n] != '\n'; n++)
        ;
      if (n < atticlen)
	{
	  rc = 0; /* found another line in the attic */
	  nread = atticlen;
	  atticlen = 0;
	}
      else
        { /* read the rest */
          assert (atticlen < LINELENGTH);
          rc = readline (ctx->inbound.fd, line + atticlen,
			 LINELENGTH - atticlen, &nread, &ctx->inbound.eof);
        }
    }
  else
    rc = readline (ctx->inbound.fd, line, LINELENGTH,
                   &nread, &ctx->inbound.eof);
  if (rc)
    {
      if (ctx->log_fp)
        fprintf (ctx->log_fp, "%s[%p] <- [Error: %s]\n",
                 my_log_prefix (), ctx, strerror (errno)); 
      return ASSUAN_Read_Error;
    }
  if (!nread)
    {
      assert (ctx->inbound.eof);
      if (ctx->log_fp)
        fprintf (ctx->log_fp, "%s[%p] <- [EOF]\n", my_log_prefix (),ctx); 
      return -1; 
    }

  ctx->inbound.attic.pending = 0;
  nread += atticlen;
  for (n=0; n < nread; n++)
    {
      if (line[n] == '\n')
        {
          if (n+1 < nread)
            {
              char *s, *d;
              int i;

              n++;
              /* we have to copy the rest because the handlers are
                 allowed to modify the passed buffer */
              for (d=ctx->inbound.attic.line, s=line+n, i=nread-n; i; i--)
                {
                  if (*s=='\n')
                    ctx->inbound.attic.pending = 1;
                  *d++ = *s++;
                }
              ctx->inbound.attic.linelen = nread-n;
              n--;
            }
          if (n && line[n-1] == '\r')
            n--;
          line[n] = 0;
          ctx->inbound.linelen = n;
          if (ctx->log_fp)
            {
              fprintf (ctx->log_fp, "%s[%p] <- ", my_log_prefix (), ctx); 
              if (ctx->confidential)
                fputs ("[Confidential data not shown]", ctx->log_fp);
              else
                _assuan_log_print_buffer (ctx->log_fp, 
                                          ctx->inbound.line,
                                          ctx->inbound.linelen);
              putc ('\n', ctx->log_fp);
            }
          return 0;
        }
    }

  if (ctx->log_fp)
    fprintf (ctx->log_fp, "%s[%p] <- [Invalid line]\n", my_log_prefix (), ctx);
  *line = 0;
  ctx->inbound.linelen = 0;
  return ctx->inbound.eof? ASSUAN_Line_Not_Terminated : ASSUAN_Line_Too_Long;
}


/* Read the next line from the client or server and return a pointer
   to a buffer with holding that line.  linelen returns the length of
   the line.  This buffer is valid until another read operation is
   done on this buffer.  The caller is allowed to modify this buffer.
   He should only use the buffer if the function returns without an
   error.

   Returns: 0 on success or an assuan error code
   See also: assuan_pending_line().
*/
AssuanError
assuan_read_line (ASSUAN_CONTEXT ctx, char **line, size_t *linelen)
{
  AssuanError err;

  if (!ctx)
    return ASSUAN_Invalid_Value;

  err = _assuan_read_line (ctx);
  *line = ctx->inbound.line;
  *linelen = ctx->inbound.linelen;
  return err;
}


/* Return true when a full line is pending for a read, without the need
   for actual IO */
int
assuan_pending_line (ASSUAN_CONTEXT ctx)
{
  return ctx && ctx->inbound.attic.pending;
}


AssuanError 
assuan_write_line (ASSUAN_CONTEXT ctx, const char *line )
{
  int rc;
  
  if (!ctx)
    return ASSUAN_Invalid_Value;

  /* fixme: we should do some kind of line buffering */
  if (ctx->log_fp)
    {
      fprintf (ctx->log_fp, "%s[%p] -> ", my_log_prefix (), ctx); 
      if (ctx->confidential)
        fputs ("[Confidential data not shown]", ctx->log_fp);
      else
        _assuan_log_print_buffer (ctx->log_fp, 
                                  line, strlen (line));
      putc ('\n', ctx->log_fp);
    }

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
          if (ctx->log_fp)
            {
              fprintf (ctx->log_fp, "%s[%p] -> ", my_log_prefix (), ctx); 
              if (ctx->confidential)
                fputs ("[Confidential data not shown]", ctx->log_fp);
              else 
                _assuan_log_print_buffer (ctx->log_fp, 
                                          ctx->outbound.data.line,
                                          linelen);
              putc ('\n', ctx->log_fp);
            }
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
      if (ctx->log_fp)
        {
          fprintf (ctx->log_fp, "%s[%p] -> ", my_log_prefix (), ctx); 
          if (ctx->confidential)
            fputs ("[Confidential data not shown]", ctx->log_fp);
          else
            _assuan_log_print_buffer (ctx->log_fp, 
                                      ctx->outbound.data.line,
                                      linelen);
          putc ('\n', ctx->log_fp);
            }
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


/**
 * assuan_send_data:
 * @ctx: An assuan context
 * @buffer: Data to send or NULL to flush
 * @length: length of the data to send/
 * 
 * This function may be used by the server or the client to send data
 * lines.  The data will be escaped as required by the Assuan protocol
 * and may get buffered until a line is full.  To force sending the
 * data out @buffer may be passed as NULL (in which case @length must
 * also be 0); however when used by a client this flush operation does
 * also send the terminating "END" command to terminate the reponse on
 * a INQUIRE response.  However, when assuan_transact() is used, this
 * function takes care of sending END itself.
 * 
 * Return value: 0 on success or an error code
 **/

AssuanError
assuan_send_data (ASSUAN_CONTEXT ctx, const void *buffer, size_t length)
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  if (!buffer && length)
    return ASSUAN_Invalid_Value;

  if (!buffer)
    { /* flush what we have */
      _assuan_cookie_write_flush (ctx);
      if (ctx->outbound.data.error)
        return ctx->outbound.data.error;
      if (!ctx->is_server)
        return assuan_write_line (ctx, "END");
    }
  else
    {
      _assuan_cookie_write_data (ctx, buffer, length);
      if (ctx->outbound.data.error)
        return ctx->outbound.data.error;
    }

  return 0;
}




