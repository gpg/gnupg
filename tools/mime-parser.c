/* mime-parser.c - Parse MIME structures (high level rfc822 parser).
 * Copyright (C) 2016 g10 Code GmbH
 * Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/util.h"
#include "rfc822parse.h"
#include "mime-parser.h"


enum pgpmime_states
  {
    PGPMIME_NONE = 0,
    PGPMIME_WAIT_ENCVERSION,
    PGPMIME_IN_ENCVERSION,
    PGPMIME_WAIT_ENCDATA,
    PGPMIME_IN_ENCDATA,
    PGPMIME_GOT_ENCDATA,
    PGPMIME_WAIT_SIGNEDDATA,
    PGPMIME_IN_SIGNEDDATA,
    PGPMIME_WAIT_SIGNATURE,
    PGPMIME_IN_SIGNATURE,
    PGPMIME_GOT_SIGNATURE,
    PGPMIME_INVALID
  };


/* Definition of the mime parser object.  */
struct mime_parser_context_s
{
  void *cookie;                /* Cookie passed to all callbacks.  */

  /* The callback to announce the transation from header to body.  */
  gpg_error_t (*t2body) (void *cookie, int level);

  /* The callback to announce a new part.  */
  gpg_error_t (*new_part) (void *cookie,
                           const char *mediatype,
                           const char *mediasubtype);
  /* The callback to return data of a part.  */
  gpg_error_t (*part_data) (void *cookie,
                            const void *data,
                            size_t datalen);
  /* The callback to collect encrypted data.  */
  gpg_error_t (*collect_encrypted) (void *cookie, const char *data);
  /* The callback to collect signed data.  */
  gpg_error_t (*collect_signeddata) (void *cookie, const char *data);
  /* The callback to collect a signature.  */
  gpg_error_t (*collect_signature) (void *cookie, const char *data);

  /* The RFC822 parser context is stored here during callbacks.  */
  rfc822parse_t msg;

  /* Helper to convey error codes from user callbacks.  */
  gpg_error_t err;

  int nesting_level;           /* The current nesting level.  */
  int hashing_at_level;        /* The nesting level at which we are hashing. */
  enum pgpmime_states pgpmime; /* Current PGP/MIME state.  */
  unsigned int delay_hashing:1;/* Helper for PGPMIME_IN_SIGNEDDATA. */
  unsigned int want_part:1;    /* Return the current part.  */
  unsigned int decode_part:2;  /* Decode the part.  1 = QP, 2 = Base64. */

  unsigned int verbose:1;      /* Enable verbose mode.  */
  unsigned int debug:1;        /* Enable debug mode.  */

  /* Flags to help with debug output.  */
  struct {
    unsigned int n_skip;         /* Skip showing these number of lines.  */
    unsigned int header:1;       /* Show the header lines.  */
    unsigned int data:1;         /* Show the data lines.  */
    unsigned int as_note:1;      /* Show the next data line as a note.  */
    unsigned int boundary : 1;
  } show;

  struct b64state *b64state;     /* NULL or malloced Base64 decoder state.  */

  /* A buffer for reading a mail line,  */
  char line[5000];
};


/* Print the event received by the parser for debugging.  */
static void
show_message_parser_event (rfc822parse_event_t event)
{
  const char *s;

  switch (event)
    {
    case RFC822PARSE_OPEN: s= "Open"; break;
    case RFC822PARSE_CLOSE: s= "Close"; break;
    case RFC822PARSE_CANCEL: s= "Cancel"; break;
    case RFC822PARSE_T2BODY: s= "T2Body"; break;
    case RFC822PARSE_FINISH: s= "Finish"; break;
    case RFC822PARSE_RCVD_SEEN: s= "Rcvd_Seen"; break;
    case RFC822PARSE_LEVEL_DOWN: s= "Level_Down"; break;
    case RFC822PARSE_LEVEL_UP: s= "Level_Up"; break;
    case RFC822PARSE_BOUNDARY: s= "Boundary"; break;
    case RFC822PARSE_LAST_BOUNDARY: s= "Last_Boundary"; break;
    case RFC822PARSE_BEGIN_HEADER: s= "Begin_Header"; break;
    case RFC822PARSE_PREAMBLE: s= "Preamble"; break;
    case RFC822PARSE_EPILOGUE: s= "Epilogue"; break;
    default: s= "[unknown event]"; break;
    }
  log_debug ("*** RFC822 event %s\n", s);
}


/* Do in-place decoding of quoted-printable data of LENGTH in BUFFER.
   Returns the new length of the buffer and stores true at R_SLBRK if
   the line ended with a soft line break; false is stored if not.
   This function asssumes that a complete line is passed in
   buffer.  */
static size_t
qp_decode (char *buffer, size_t length, int *r_slbrk)
{
  char *d, *s;

  if (r_slbrk)
    *r_slbrk = 0;

  /* Fixme:  We should remove trailing white space first.  */
  for (s=d=buffer; length; length--)
    {
      if (*s == '=')
        {
          if (length > 2 && hexdigitp (s+1) && hexdigitp (s+2))
            {
              s++;
              *(unsigned char*)d++ = xtoi_2 (s);
              s += 2;
              length -= 2;
            }
          else if (length > 2 && s[1] == '\r' && s[2] == '\n')
            {
              /* Soft line break.  */
              s += 3;
              length -= 2;
              if (r_slbrk && length == 1)
                *r_slbrk = 1;
            }
          else if (length > 1 && s[1] == '\n')
            {
              /* Soft line break with only a Unix line terminator. */
              s += 2;
              length -= 1;
              if (r_slbrk && length == 1)
                *r_slbrk = 1;
            }
          else if (length == 1)
            {
              /* Soft line break at the end of the line. */
              s += 1;
              if (r_slbrk)
                *r_slbrk = 1;
            }
          else
            *d++ = *s++;
        }
      else
        *d++ = *s++;
    }

  return d - buffer;
}


/* This function is called by parse_mail to communicate events.  This
 * callback communicates with the caller using a structure passed in
 * OPAQUE.  Should return 0 on success or set ERRNO and return -1. */
static int
parse_message_cb (void *opaque, rfc822parse_event_t event, rfc822parse_t msg)
{
  mime_parser_t ctx = opaque;
  const char *s;
  int rc = 0;

  /* Make the RFC822 parser context availabale for callbacks.  */
  ctx->msg = msg;

  if (ctx->debug)
    show_message_parser_event (event);

  if (event == RFC822PARSE_BEGIN_HEADER || event == RFC822PARSE_T2BODY)
    {
      /* We need to check here whether to start collecting signed data
       * because attachments might come without header lines and thus
       * we won't see the BEGIN_HEADER event.  */
      if (ctx->pgpmime == PGPMIME_WAIT_SIGNEDDATA)
        {
          if (ctx->debug)
            log_debug ("begin_hash\n");
          ctx->hashing_at_level = ctx->nesting_level;
          ctx->pgpmime = PGPMIME_IN_SIGNEDDATA;
          ctx->delay_hashing = 0;
        }
    }

  if (event == RFC822PARSE_OPEN)
    {
      /* Initialize for a new message. */
      ctx->show.header = 1;
    }
  else if (event == RFC822PARSE_T2BODY)
    {
      rfc822parse_field_t field;

      ctx->want_part = 0;
      ctx->decode_part = 0;

      if (ctx->t2body)
        {
          rc = ctx->t2body (ctx->cookie, ctx->nesting_level);
          if (rc)
            goto t2body_leave;
        }

      field = rfc822parse_parse_field (msg, "Content-Type", -1);
      if (field)
        {
          const char *s1, *s2;

          s1 = rfc822parse_query_media_type (field, &s2);
          if (s1)
            {
              if (ctx->verbose)
                log_debug ("h media: %*s%s %s\n",
                           ctx->nesting_level*2, "", s1, s2);
              if (ctx->pgpmime == PGPMIME_WAIT_ENCVERSION)
                {
                  if (!strcmp (s1, "application")
                      && !strcmp (s2, "pgp-encrypted"))
                    {
                      if (ctx->debug)
                        log_debug ("c begin_encversion\n");
                      ctx->pgpmime = PGPMIME_IN_ENCVERSION;
                    }
                  else
                    {
                      log_error ("invalid PGP/MIME structure;"
                                 " expected '%s', got '%s/%s'\n",
                                 "application/pgp-encrypted", s1, s2);
                      ctx->pgpmime = PGPMIME_INVALID;
                    }
                }
              else if (ctx->pgpmime == PGPMIME_WAIT_ENCDATA)
                {
                  if (!strcmp (s1, "application")
                      && !strcmp (s2, "octet-stream"))
                    {
                      if (ctx->debug)
                        log_debug ("c begin_encdata\n");
                      ctx->pgpmime = PGPMIME_IN_ENCDATA;
                    }
                  else
                    {
                      log_error ("invalid PGP/MIME structure;"
                                 " expected '%s', got '%s/%s'\n",
                                 "application/octet-stream", s1, s2);
                      ctx->pgpmime = PGPMIME_INVALID;
                    }
                }
              else if (ctx->pgpmime == PGPMIME_WAIT_SIGNATURE)
                {
                  if (!strcmp (s1, "application")
                      && !strcmp (s2, "pgp-signature"))
                    {
                      if (ctx->debug)
                        log_debug ("c begin_signature\n");
                      ctx->pgpmime = PGPMIME_IN_SIGNATURE;
                    }
                  else
                    {
                      log_error ("invalid PGP/MIME structure;"
                                 " expected '%s', got '%s/%s'\n",
                                 "application/pgp-signature", s1, s2);
                      ctx->pgpmime = PGPMIME_INVALID;
                    }
                }
              else if (!strcmp (s1, "multipart")
                       && !strcmp (s2, "encrypted"))
                {
                  s = rfc822parse_query_parameter (field, "protocol", 0);
                  if (s)
                    {
                      if (ctx->debug)
                        log_debug ("h encrypted.protocol: %s\n", s);
                      if (!strcmp (s, "application/pgp-encrypted"))
                        {
                          if (ctx->pgpmime)
                            log_error ("note: "
                                       "ignoring nested PGP/MIME signature\n");
                          else
                            ctx->pgpmime = PGPMIME_WAIT_ENCVERSION;
                        }
                      else if (ctx->verbose)
                        log_debug ("# this protocol is not supported\n");
                    }
                }
              else if (!strcmp (s1, "multipart")
                       && !strcmp (s2, "signed"))
                {
                  s = rfc822parse_query_parameter (field, "protocol", 1);
                  if (s)
                    {
                      if (ctx->debug)
                        log_debug ("h signed.protocol: %s\n", s);
                      if (!strcmp (s, "application/pgp-signature"))
                        {
                          if (ctx->pgpmime)
                            log_error ("note: "
                                       "ignoring nested PGP/MIME signature\n");
                          else
                            ctx->pgpmime = PGPMIME_WAIT_SIGNEDDATA;
                        }
                      else if (ctx->verbose)
                        log_debug ("# this protocol is not supported\n");
                    }
                }
              else if (ctx->new_part)
                {
                  ctx->err = ctx->new_part (ctx->cookie, s1, s2);
                  if (!ctx->err)
                    ctx->want_part = 1;
                  else if (gpg_err_code (ctx->err) == GPG_ERR_FALSE)
                    ctx->err = 0;
                  else if (gpg_err_code (ctx->err) == GPG_ERR_TRUE)
                    {
                      ctx->want_part = ctx->decode_part = 1;
                      ctx->err = 0;
                    }
                }
            }
          else
            {
              if (ctx->debug)
                log_debug ("h media: %*s none\n", ctx->nesting_level*2, "");
              if (ctx->new_part)
                {
                  ctx->err = ctx->new_part (ctx->cookie, "", "");
                  if (!ctx->err)
                    ctx->want_part = 1;
                  else if (gpg_err_code (ctx->err) == GPG_ERR_FALSE)
                    ctx->err = 0;
                  else if (gpg_err_code (ctx->err) == GPG_ERR_TRUE)
                    {
                      ctx->want_part = ctx->decode_part = 1;
                      ctx->err = 0;
                    }
                }
            }

          rfc822parse_release_field (field);
        }
      else
        {
          if (ctx->verbose)
            log_debug ("h media: %*stext plain [assumed]\n",
                       ctx->nesting_level*2, "");
          if (ctx->new_part)
            {
              ctx->err = ctx->new_part (ctx->cookie, "text", "plain");
              if (!ctx->err)
                ctx->want_part = 1;
              else if (gpg_err_code (ctx->err) == GPG_ERR_FALSE)
                ctx->err = 0;
              else if (gpg_err_code (ctx->err) == GPG_ERR_TRUE)
                {
                  ctx->want_part = ctx->decode_part = 1;
                  ctx->err = 0;
                }
            }
        }

      /* Figure out the encoding if needed.  */
      if (ctx->decode_part)
        {
          char *value;
          size_t valueoff;

          ctx->decode_part = 0; /* Fallback for unknown encoding.  */
          value = rfc822parse_get_field (msg, "Content-Transfer-Encoding", -1,
                                         &valueoff);
          if (value)
            {
              if (!stricmp (value+valueoff, "quoted-printable"))
                ctx->decode_part = 1;
              else if (!stricmp (value+valueoff, "base64"))
                {
                  ctx->decode_part = 2;
                  if (ctx->b64state)
                    b64dec_finish (ctx->b64state); /* Reuse state.  */
                  else
                    {
                      ctx->b64state = xtrymalloc (sizeof *ctx->b64state);
                      if (!ctx->b64state)
                        rc = gpg_error_from_syserror ();
                    }
                  if (!rc)
                    rc = b64dec_start (ctx->b64state, NULL);
                }
              free (value); /* Right, we need a plain free.  */
            }
        }

    t2body_leave:
      ctx->show.header = 0;
      ctx->show.data = 1;
      ctx->show.n_skip = 1;
    }
  else if (event == RFC822PARSE_PREAMBLE)
    ctx->show.as_note = 1;
  else if (event == RFC822PARSE_LEVEL_DOWN)
    {
      if (ctx->debug)
        log_debug ("b down\n");
      ctx->nesting_level++;
    }
  else if (event == RFC822PARSE_LEVEL_UP)
    {
      if (ctx->debug)
        log_debug ("b up\n");
      if (ctx->nesting_level)
        ctx->nesting_level--;
      else
        log_error ("invalid structure (bad nesting level)\n");
    }
  else if (event == RFC822PARSE_BOUNDARY || event == RFC822PARSE_LAST_BOUNDARY)
    {
      ctx->show.data = 0;
      ctx->show.boundary = 1;
      if (event == RFC822PARSE_BOUNDARY)
        {
          ctx->show.header = 1;
          ctx->show.n_skip = 1;
          if (ctx->debug)
            log_debug ("b part\n");
        }
      else if (ctx->debug)
        log_debug ("b last\n");

      if (ctx->pgpmime == PGPMIME_IN_ENCDATA)
        {
          if (ctx->debug)
            log_debug ("c end_encdata\n");
          ctx->pgpmime = PGPMIME_GOT_ENCDATA;
          /* FIXME: We should assert (event == LAST_BOUNDARY).  */
        }
      else if (ctx->pgpmime == PGPMIME_IN_SIGNEDDATA
               && ctx->nesting_level == ctx->hashing_at_level)
        {
          if (ctx->debug)
            log_debug ("c end_hash\n");
          ctx->pgpmime = PGPMIME_WAIT_SIGNATURE;
          if (ctx->collect_signeddata)
            ctx->err = ctx->collect_signeddata (ctx->cookie, NULL);
        }
      else if (ctx->pgpmime == PGPMIME_IN_SIGNATURE)
        {
          if (ctx->debug)
            log_debug ("c end_signature\n");
          ctx->pgpmime = PGPMIME_GOT_SIGNATURE;
          /* FIXME: We should assert (event == LAST_BOUNDARY).  */
        }
      else if (ctx->want_part)
        {
          if (ctx->part_data)
            {
              /* FIXME: We may need to flush things.  */
              ctx->err = ctx->part_data (ctx->cookie, NULL, 0);
            }
          ctx->want_part = 0;
        }
    }

  ctx->msg = NULL;

  return rc;
}


/* Create a new mime parser object.  COOKIE is a values which will be
 * used as first argument for all callbacks registered with this
 * parser object.  */
gpg_error_t
mime_parser_new (mime_parser_t *r_parser, void *cookie)
{
  mime_parser_t ctx;

  *r_parser = NULL;

  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    return gpg_error_from_syserror ();
  ctx->cookie = cookie;

  *r_parser = ctx;
  return 0;
}


/* Release a mime parser object.  */
void
mime_parser_release (mime_parser_t ctx)
{
  if (!ctx)
    return;

  if (ctx->b64state)
    {
      b64dec_finish (ctx->b64state);
      xfree (ctx->b64state);
    }
  xfree (ctx);
}


/* Set verbose and debug mode.  */
void
mime_parser_set_verbose (mime_parser_t ctx, int level)
{
  if (!level)
    {
      ctx->verbose = 0;
      ctx->debug = 0;
    }
  else
    {
      ctx->verbose = 1;
      if (level > 10)
        ctx->debug = 1;
    }
}


/* Set a callback for the transition from header to body.  LEVEL is
 * the current nesting level, starting with 0.  This callback can be
 * used to evaluate headers before any other action is done.  Note
 * that if a new NEW_PART callback needs to be called it is done after
 * this T2BODY callback.  */
void
mime_parser_set_t2body (mime_parser_t ctx,
                        gpg_error_t (*fnc) (void *cookie, int level))
{
  ctx->t2body = fnc;
}


/* Set the callback used to announce a new part.  It will be called
 * with the media type and media subtype of the part.  If no
 * Content-type header was given both values are the empty string.
 * The callback should return 0 on success or an error code.  The
 * error code GPG_ERR_FALSE indicates that the caller is not
 * interested in the part and data shall not be returned via a
 * registered part_data callback.  The error code GPG_ERR_TRUE
 * indicates that the parts shall be redurned in decoded format
 * (i.e. base64 or QP encoding is removed).  */
void
mime_parser_set_new_part (mime_parser_t ctx,
                          gpg_error_t (*fnc) (void *cookie,
                                              const char *mediatype,
                                              const char *mediasubtype))
{
  ctx->new_part = fnc;
}


/* Set the callback used to return the data of a part to the caller.
 * The end of the part is indicated by passing NUL for DATA.  */
void
mime_parser_set_part_data (mime_parser_t ctx,
                           gpg_error_t (*fnc) (void *cookie,
                                               const void *data,
                                               size_t datalen))
{
  ctx->part_data = fnc;
}


/* Set the callback to collect encrypted data.  A NULL passed to the
 * callback indicates the end of the encrypted data; the callback may
 * then decrypt the collected data.  */
void
mime_parser_set_collect_encrypted (mime_parser_t ctx,
                                   gpg_error_t (*fnc) (void *cookie,
                                                       const char *data))
{
  ctx->collect_encrypted = fnc;
}


/* Set the callback to collect signed data.  A NULL passed to the
 * callback indicates the end of the signed data.  */
void
mime_parser_set_collect_signeddata (mime_parser_t ctx,
                                    gpg_error_t (*fnc) (void *cookie,
                                                        const char *data))
{
  ctx->collect_signeddata = fnc;
}


/* Set the callback to collect the signature.  A NULL passed to the
 * callback indicates the end of the signature; the callback may the
 * verify the signature.  */
void
mime_parser_set_collect_signature (mime_parser_t ctx,
                                   gpg_error_t (*fnc) (void *cookie,
                                                       const char *data))
{
  ctx->collect_signature = fnc;
}


/* Return the RFC888 parser context.  This is only available inside a
 * callback.  */
rfc822parse_t
mime_parser_rfc822parser (mime_parser_t ctx)
{
  return ctx->msg;
}


/* Helper for mime_parser_parse.  */
static gpg_error_t
process_part_data (mime_parser_t ctx, char *line, size_t *length)
{
  gpg_error_t err;
  size_t nbytes;

  if (!ctx->want_part)
    return 0;
  if (!ctx->part_data)
    return 0;

  if (ctx->decode_part == 1)
    {
      *length = qp_decode (line, *length, NULL);
    }
  else if (ctx->decode_part == 2)
    {
      log_assert (ctx->b64state);
      err = b64dec_proc (ctx->b64state, line, *length, &nbytes);
      if (err)
        return err;
      *length = nbytes;
    }

  return ctx->part_data (ctx->cookie, line, *length);
}


/* Read and parse a message from FP and call the appropriate
 * callbacks.  */
gpg_error_t
mime_parser_parse (mime_parser_t ctx, estream_t fp)
{
  gpg_error_t err;
  rfc822parse_t msg = NULL;
  unsigned int lineno = 0;
  size_t length;
  char *line;

  line = ctx->line;

  msg = rfc822parse_open (parse_message_cb, ctx);
  if (!msg)
    {
      err = gpg_error_from_syserror ();
      log_error ("can't open mail parser: %s", gpg_strerror (err));
      goto leave;
    }

  /* Fixme: We should not use fgets because it can't cope with
     embedded nul characters. */
  while (es_fgets (ctx->line, sizeof (ctx->line), fp))
    {
      lineno++;
      if (lineno == 1 && !strncmp (line, "From ", 5))
        continue;  /* We better ignore a leading From line. */

      length = strlen (line);
      if (length && line[length - 1] == '\n')
	line[--length] = 0;
      else
        log_error ("mail parser detected too long or"
                   " non terminated last line (lnr=%u)\n", lineno);
      if (length && line[length - 1] == '\r')
	line[--length] = 0;

      ctx->err = 0;
      if (rfc822parse_insert (msg, line, length))
        {
          err = gpg_error_from_syserror ();
          log_error ("mail parser failed: %s", gpg_strerror (err));
          goto leave;
        }
      if (ctx->err)
        {
          /* Error from a callback detected.  */
          err = ctx->err;
          goto leave;
        }


      /* Debug output.  Note that the boundary is shown before n_skip
       * is evaluated.  */
      if (ctx->show.boundary)
        {
          if (ctx->debug)
            log_debug ("# Boundary: %s\n", line);
          ctx->show.boundary = 0;
        }
      if (ctx->show.n_skip)
        ctx->show.n_skip--;
      else if (ctx->show.data)
        {
          if (ctx->show.as_note)
            {
              if (ctx->verbose)
                log_debug ("# Note: %s\n", line);
              ctx->show.as_note = 0;
            }
          else if (ctx->debug)
            log_debug ("# Data: %s\n", line);
        }
      else if (ctx->show.header && ctx->verbose)
        log_debug ("# Header: %s\n", line);

      if (ctx->pgpmime == PGPMIME_IN_ENCVERSION)
        {
          trim_trailing_spaces (line);
          if (!*line)
            ;  /* Skip empty lines.  */
          else if (!strcmp (line, "Version: 1"))
            ctx->pgpmime = PGPMIME_WAIT_ENCDATA;
          else
            {
              log_error ("invalid PGP/MIME structure;"
                         " garbage in pgp-encrypted part ('%s')\n", line);
              ctx->pgpmime = PGPMIME_INVALID;
            }
        }
      else if (ctx->pgpmime == PGPMIME_IN_ENCDATA)
        {
          if (ctx->collect_encrypted)
            {
              err = ctx->collect_encrypted (ctx->cookie, line);
              if (!err)
                err = ctx->collect_encrypted (ctx->cookie, "\r\n");
              if (err)
                goto leave;
            }
        }
      else if (ctx->pgpmime == PGPMIME_GOT_ENCDATA)
        {
          ctx->pgpmime = PGPMIME_NONE;
          if (ctx->collect_encrypted)
            ctx->collect_encrypted (ctx->cookie, NULL);
        }
      else if (ctx->pgpmime == PGPMIME_IN_SIGNEDDATA)
        {
          /* If we are processing signed data, store the signed data.
           * We need to delay the hashing of the CR/LF because the
           * last line ending belongs to the next boundary.  This is
           * the reason why we can't use the PGPMIME state as a
           * condition.  */
          if (ctx->debug)
            log_debug ("# hashing %s'%s'\n",
                       ctx->delay_hashing? "CR,LF+":"", line);
          if (ctx->collect_signeddata)
            {
              if (ctx->delay_hashing)
                ctx->collect_signeddata (ctx->cookie, "\r\n");
              ctx->collect_signeddata (ctx->cookie, line);
            }
          ctx->delay_hashing = 1;

          err = process_part_data (ctx, line, &length);
          if (err)
            goto leave;
        }
      else if (ctx->pgpmime == PGPMIME_IN_SIGNATURE)
        {
          if (ctx->collect_signeddata)
            {
              ctx->collect_signature (ctx->cookie, line);
              ctx->collect_signature (ctx->cookie, "\r\n");
            }
        }
      else if (ctx->pgpmime == PGPMIME_GOT_SIGNATURE)
        {
          ctx->pgpmime = PGPMIME_NONE;
          if (ctx->collect_signeddata)
            ctx->collect_signature (ctx->cookie, NULL);
        }
      else
        {
          err = process_part_data (ctx, line, &length);
          if (err)
            goto leave;
        }
    }

  rfc822parse_close (msg);
  msg = NULL;
  err = 0;

 leave:
  rfc822parse_cancel (msg);
  return err;
}
