/* b64enc.c - Simple Base64 encoder.
 *	Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "i18n.h"
#include "util.h"

#define B64ENC_DID_HEADER   1
#define B64ENC_DID_TRAILER  2
#define B64ENC_NO_LINEFEEDS 16


/* The base-64 character list */
static unsigned char bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
                                    "abcdefghijklmnopqrstuvwxyz" 
                                    "0123456789+/"; 

/* Prepare for base-64 writing to the stream FP.  If TITLE is not NULL
   and not an empty string, this string will be used as the title for
   the armor lines, with TITLE being an empty string, we don't write
   the header lines and furthermore even don't write any linefeeds.
   With TITLE beeing NULL, we merely don't write header but make sure
   that lines are not too long. Note, that we don't write any output
   unless at least one byte get written using b64enc_write. */
gpg_error_t
b64enc_start (struct b64state *state, FILE *fp, const char *title)
{
  memset (state, 0, sizeof *state);
  state->fp = fp;
  if (title && !*title)
    state->flags |= B64ENC_NO_LINEFEEDS;
  else if (title)
    {
      state->title = strdup (title);
      if (!state->title)
        return  gpg_error_from_errno (errno);
    }
  return 0;
}


/* Write NBYTES from BUFFER to the Base 64 stream identified by
   STATE. With BUFFER and NBYTES being 0, merely do a fflush on the
   stream. */
gpg_error_t
b64enc_write (struct b64state *state, const void *buffer, size_t nbytes)
{
  unsigned char radbuf[4];
  int idx, quad_count;
  const unsigned char *p;
  FILE *fp = state->fp;


  if (!nbytes)
    {
      if (buffer && fflush (fp))
        goto write_error;
      return 0;
    }

  if (!(state->flags & B64ENC_DID_HEADER))
    {
      if (state->title)
        {
          if ( fputs ("-----BEGIN ", fp) == EOF
               || fputs (state->title, fp) == EOF
               || fputs ("-----\n", fp) == EOF)
            goto write_error;
        }
      state->flags |= B64ENC_DID_HEADER;
    }

  idx = state->idx;
  quad_count = state->quad_count;
  assert (idx < 4);
  memcpy (radbuf, state->radbuf, idx);
  
  for (p=buffer; nbytes; p++, nbytes--)
    {
      radbuf[idx++] = *p;
      if (idx > 2)
        {
          char tmp[4];

          tmp[0] = bintoasc[(*radbuf >> 2) & 077];
          tmp[1] = bintoasc[(((*radbuf<<4)&060)|((radbuf[1] >> 4)&017))&077];
          tmp[2] = bintoasc[(((radbuf[1]<<2)&074)|((radbuf[2]>>6)&03))&077];
          tmp[3] = bintoasc[radbuf[2]&077];
          for (idx=0; idx < 4; idx++)
            putc (tmp[idx], fp);
          idx = 0;
          if (ferror (fp))
            goto write_error;
          if (++quad_count >= (64/4)) 
            {
              quad_count = 0;
              if (!(state->flags & B64ENC_NO_LINEFEEDS)
                  && fputs ("\n", fp) == EOF)
                goto write_error;
            }
        }
    }
  memcpy (state->radbuf, radbuf, idx);
  state->idx = idx;
  state->quad_count = quad_count;
  return 0;

 write_error:
  return gpg_error_from_errno (errno);
}

gpg_error_t
b64enc_finish (struct b64state *state)
{
  gpg_error_t err = 0;
  unsigned char radbuf[4];
  int idx, quad_count;
  FILE *fp;

  if (!(state->flags & B64ENC_DID_HEADER))
    goto cleanup;

  /* Flush the base64 encoding */
  fp = state->fp;
  idx = state->idx;
  quad_count = state->quad_count;
  assert (idx < 4);
  memcpy (radbuf, state->radbuf, idx);

  if (idx)
    {
      char tmp[4];
      
      tmp[0] = bintoasc[(*radbuf>>2)&077];
      if (idx == 1)
        {
          tmp[1] = bintoasc[((*radbuf << 4) & 060) & 077];
          tmp[2] = '=';
          tmp[3] = '=';
        }
      else 
        { 
          tmp[1] = bintoasc[(((*radbuf<<4)&060)|((radbuf[1]>>4)&017))&077];
          tmp[2] = bintoasc[((radbuf[1] << 2) & 074) & 077];
          tmp[3] = '=';
        }
      for (idx=0; idx < 4; idx++)
        putc (tmp[idx], fp);
      idx = 0;
      if (ferror (fp))
        goto write_error;
      
      if (++quad_count >= (64/4)) 
        {
          quad_count = 0;
          if (!(state->flags & B64ENC_NO_LINEFEEDS)
              && fputs ("\n", fp) == EOF)
            goto write_error;
        }
    }

  /* Finish the last line and write the trailer. */
  if (quad_count
      && !(state->flags & B64ENC_NO_LINEFEEDS)
      && fputs ("\n", fp) == EOF)
    goto write_error;

  if (state->title)
    {
      if ( fputs ("-----END ", fp) == EOF
           || fputs (state->title, fp) == EOF
           || fputs ("-----\n", fp) == EOF)
        goto write_error;
    }

  goto cleanup;

 write_error:
  err = gpg_error_from_errno (errno);

 cleanup:
  if (state->title)
    {
      free (state->title);
      state->title = NULL;
    }
  state->fp = NULL;
  return err;
}

