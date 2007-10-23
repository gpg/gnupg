/* assuan-client.c - client functions
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
 *	Copyright (C) 2005 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "assuan-defs.h"

#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


assuan_error_t
_assuan_read_from_server (assuan_context_t ctx, int *okay, int *off)
{
  char *line;
  int linelen;
  assuan_error_t rc;

  *okay = 0;
  *off = 0;
  do 
    {
      rc = _assuan_read_line (ctx);
      if (rc)
        return rc;
      line = ctx->inbound.line;
      linelen = ctx->inbound.linelen;
    }    
  while (*line == '#' || !linelen);

  if (linelen >= 1
      && line[0] == 'D' && line[1] == ' ')
    {
      *okay = 2; /* data line */
      *off = 2;
    }
  else if (linelen >= 1
           && line[0] == 'S' 
           && (line[1] == '\0' || line[1] == ' '))
    {
      *okay = 4;
      *off = 1;
      while (line[*off] == ' ')
        ++*off;
    }  
  else if (linelen >= 2
           && line[0] == 'O' && line[1] == 'K'
           && (line[2] == '\0' || line[2] == ' '))
    {
      *okay = 1;
      *off = 2;
      while (line[*off] == ' ')
        ++*off;
    }
  else if (linelen >= 3
           && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
           && (line[3] == '\0' || line[3] == ' '))
    {
      *okay = 0;
      *off = 3;
      while (line[*off] == ' ')
        ++*off;
    }  
  else if (linelen >= 7
           && line[0] == 'I' && line[1] == 'N' && line[2] == 'Q'
           && line[3] == 'U' && line[4] == 'I' && line[5] == 'R'
           && line[6] == 'E' 
           && (line[7] == '\0' || line[7] == ' '))
    {
      *okay = 3;
      *off = 7;
      while (line[*off] == ' ')
        ++*off;
    }
  else if (linelen >= 3
           && line[0] == 'E' && line[1] == 'N' && line[2] == 'D'
           && (line[3] == '\0' || line[3] == ' '))
    {
      *okay = 5; /* end line */
      *off = 3;
    }
  else
    rc = ASSUAN_Invalid_Response;
  return rc;
}



assuan_error_t
assuan_transact (assuan_context_t ctx,
                 const char *command,
                 assuan_error_t (*data_cb)(void *, const void *, size_t),
                 void *data_cb_arg,
                 assuan_error_t (*inquire_cb)(void*, const char *),
                 void *inquire_cb_arg,
                 assuan_error_t (*status_cb)(void*, const char *),
                 void *status_cb_arg)
{
  return assuan_transact2 (ctx, command,
                           data_cb, data_cb_arg,
                           inquire_cb, inquire_cb_arg,
                           status_cb, status_cb_arg,
                           NULL, NULL);
}


/**
 * assuan_transact2:
 * @ctx: The Assuan context
 * @command: Coimmand line to be send to server
 * @data_cb: Callback function for data lines
 * @data_cb_arg: first argument passed to @data_cb
 * @inquire_cb: Callback function for a inquire response
 * @inquire_cb_arg: first argument passed to @inquire_cb
 * @status_cb: Callback function for a status response
 * @status_cb_arg: first argument passed to @status_cb
 * @okay_cb: Callback function for the final  OK response
 * @okay_cb_arg: first argument passed to @okay_cb
 * 
 * FIXME: Write documentation
 * 
 * Return value: 0 on success or error code.  The error code may be
 * the one one returned by the server in error lines or from the
 * callback functions.
 **/
assuan_error_t
assuan_transact2 (assuan_context_t ctx,
                  const char *command,
                  assuan_error_t (*data_cb)(void *, const void *, size_t),
                  void *data_cb_arg,
                  assuan_error_t (*inquire_cb)(void*, const char *),
                  void *inquire_cb_arg,
                  assuan_error_t (*status_cb)(void*, const char *),
                  void *status_cb_arg,
                  assuan_error_t (*okay_cb)(void*, const char *),
                  void *okay_cb_arg)
{
  int rc, okay, off;
  unsigned char *line;
  int linelen;

  rc = assuan_write_line (ctx, command);
  if (rc)
    return rc;

  if (*command == '#' || !*command)
    return 0; /* Don't expect a response for a comment line.  */

 again:
  rc = _assuan_read_from_server (ctx, &okay, &off);
  if (rc)
    return rc; /* error reading from server */

  line = ctx->inbound.line + off;
  linelen = ctx->inbound.linelen - off;

  if (!okay)
    {
      rc = atoi (line);
      if (rc < 100)
        rc = ASSUAN_Server_Fault;
    }
  else if (okay == 1) /* Received OK. */
    {
      if (okay_cb)
        {
          rc = okay_cb (okay_cb_arg, line);
          /* We better wipe out the buffer after processing it.  This
             is no real guarantee that it won't get swapped out but at
             least for the standard cases we can make sure that a
             passphrase returned with the OK line is rendered
             unreadable.  In fact the current Assuan interface suffers
             from the problem that it is not possible to do assuan I/O
             through secure memory.  There is no easy solution given
             the current implementation but we need to address it
             sooner or later.  The problem was introduced with
             gpg-agent's GET_PASPHRASE command but it might also make
             sense to have a way to convey sessions keys through
             secured memory.  Note that the old implementation in gpg
             for accessing the passphrase in fact used secure memory
             but had the drawback of using a limited and not fully
             conforming Assuan implementation - given that pinentry
             and gpg-agent neither use secured memory for Assuan I/O,
             it is negligible to drop the old implementation in gpg's
             passphrase.c and use the wipememory workaround here.  */
          memset (line, 0, strlen (line));
        }
    }
  else if (okay == 2)
    {
      if (!data_cb)
        rc = ASSUAN_No_Data_Callback;
      else 
        {
          unsigned char *s, *d;

          for (s=d=line; linelen; linelen--)
            {
              if (*s == '%' && linelen > 2)
                { /* handle escaping */
                  s++;
                  *d++ = xtoi_2 (s);
                  s += 2;
                  linelen -= 2;
                }
              else
                *d++ = *s++;
            }
          *d = 0; /* add a hidden string terminator */
          rc = data_cb (data_cb_arg, line, d - line);
          if (!rc)
            goto again;
        }
    }
  else if (okay == 3)
    {
      if (!inquire_cb)
        {
          assuan_write_line (ctx, "END"); /* get out of inquire mode */
          _assuan_read_from_server (ctx, &okay, &off); /* dummy read */
          rc = ASSUAN_No_Inquire_Callback;
        }
      else
        {
          rc = inquire_cb (inquire_cb_arg, line);
          if (!rc)
            rc = assuan_send_data (ctx, NULL, 0); /* flush and send END */
          if (!rc)
            goto again;
        }
    }
  else if (okay == 4)
    {
      if (status_cb)
        rc = status_cb (status_cb_arg, line);
      if (!rc)
        goto again;
    }
  else if (okay == 5)
    {
      if (!data_cb)
        rc = ASSUAN_No_Data_Callback;
      else 
        {
          rc = data_cb (data_cb_arg, NULL, 0);
          if (!rc)
            goto again;
        }
    }

  return rc;
}

