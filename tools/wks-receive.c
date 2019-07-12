/* wks-receive.c - Receive a WKS mail
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
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "gpg-wks.h"
#include "rfc822parse.h"
#include "mime-parser.h"


/* Limit of acceptable signed data.  */
#define MAX_SIGNEDDATA 10000

/* Limit of acceptable signature.  */
#define MAX_SIGNATURE 10000

/* Limit of acceptable encrypted data.  */
#define MAX_ENCRYPTED 100000

/* Data for a received object.  */
struct receive_ctx_s
{
  mime_parser_t parser;
  estream_t encrypted;
  estream_t plaintext;
  estream_t signeddata;
  estream_t signature;
  estream_t key_data;
  estream_t wkd_data;
  unsigned int collect_key_data:1;
  unsigned int collect_wkd_data:1;
  unsigned int draft_version_2:1;  /* This is a draft version 2 request.  */
  unsigned int multipart_mixed_seen:1;
};
typedef struct receive_ctx_s *receive_ctx_t;



static void
decrypt_data_status_cb (void *opaque, const char *keyword, char *args)
{
  receive_ctx_t ctx = opaque;
  (void)ctx;
  if (DBG_CRYPTO)
    log_debug ("gpg status: %s %s\n", keyword, args);
}


/* Decrypt the collected data.  */
static void
decrypt_data (receive_ctx_t ctx)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;
  int c;

  es_rewind (ctx->encrypted);

  if (!ctx->plaintext)
    ctx->plaintext = es_fopenmem (0, "w+b");
  if (!ctx->plaintext)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating space for plaintext: %s\n",
                 gpg_strerror (err));
      return;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  /* We limit the output to 64 KiB to avoid DoS using compression
   * tricks.  A regular client will anyway only send a minimal key;
   * that is one w/o key signatures and attribute packets.  */
  ccparray_put (&ccp, "--max-output=0x10000");
  ccparray_put (&ccp, "--batch");
  if (opt.verbose)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--decrypt");
  ccparray_put (&ccp, "--");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, ctx->encrypted,
                                NULL, ctx->plaintext,
                                decrypt_data_status_cb, ctx);
  if (err)
    {
      log_error ("decryption failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      es_rewind (ctx->plaintext);
      log_debug ("plaintext: '");
      while ((c = es_getc (ctx->plaintext)) != EOF)
        log_printf ("%c", c);
      log_printf ("'\n");
    }
  es_rewind (ctx->plaintext);

 leave:
  xfree (argv);
}


static void
verify_signature_status_cb (void *opaque, const char *keyword, char *args)
{
  receive_ctx_t ctx = opaque;
  (void)ctx;
  if (DBG_CRYPTO)
    log_debug ("gpg status: %s %s\n", keyword, args);
}

/* Verify the signed data.  */
static void
verify_signature (receive_ctx_t ctx)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;

  log_assert (ctx->signeddata);
  log_assert (ctx->signature);
  es_rewind (ctx->signeddata);
  es_rewind (ctx->signature);

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  ccparray_put (&ccp, "--batch");
  if (opt.verbose)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--enable-special-filenames");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust"); /* To avoid trustdb checks.  */
  ccparray_put (&ccp, "--verify");
  ccparray_put (&ccp, "--");
  ccparray_put (&ccp, "-&@INEXTRA@");
  ccparray_put (&ccp, "-");

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, ctx->signeddata,
                                ctx->signature, NULL,
                                verify_signature_status_cb, ctx);
  if (err)
    {
      log_error ("verification failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  log_debug ("Fixme: Verification result is not used\n");

 leave:
  xfree (argv);
}


static gpg_error_t
collect_encrypted (void *cookie, const char *data)
{
  receive_ctx_t ctx = cookie;

  if (!ctx->encrypted)
    if (!(ctx->encrypted = es_fopenmem (MAX_ENCRYPTED, "w+b,samethread")))
      return gpg_error_from_syserror ();
  if (data)
    es_fputs (data, ctx->encrypted);

  if (es_ferror (ctx->encrypted))
    return gpg_error_from_syserror ();

  if (!data)
    {
      decrypt_data (ctx);
    }

  return 0;
}


static gpg_error_t
collect_signeddata (void *cookie, const char *data)
{
  receive_ctx_t ctx = cookie;

  if (!ctx->signeddata)
    if (!(ctx->signeddata = es_fopenmem (MAX_SIGNEDDATA, "w+b,samethread")))
      return gpg_error_from_syserror ();
  if (data)
    es_fputs (data, ctx->signeddata);

  if (es_ferror (ctx->signeddata))
    return gpg_error_from_syserror ();
  return 0;
}

static gpg_error_t
collect_signature (void *cookie, const char *data)
{
  receive_ctx_t ctx = cookie;

  if (!ctx->signature)
    if (!(ctx->signature = es_fopenmem (MAX_SIGNATURE, "w+b,samethread")))
      return gpg_error_from_syserror ();
  if (data)
    es_fputs (data, ctx->signature);

  if (es_ferror (ctx->signature))
    return gpg_error_from_syserror ();

  if (!data)
    {
      verify_signature (ctx);
    }

  return 0;
}


/* The callback for the transition from header to body.  We use it to
 * look at some header values.  */
static gpg_error_t
t2body (void *cookie, int level)
{
  receive_ctx_t ctx = cookie;
  rfc822parse_t msg;
  char *value;
  size_t valueoff;

  log_info ("t2body for level %d\n", level);
  if (!level)
    {
      /* This is the outermost header.  */
      msg = mime_parser_rfc822parser (ctx->parser);
      if (msg)
        {
          value = rfc822parse_get_field (msg, "Wks-Draft-Version",
                                         -1, &valueoff);
          if (value)
            {
              if (atoi(value+valueoff) >= 2 )
                ctx->draft_version_2 = 1;
              free (value);
            }
        }
    }

  return 0;
}


static gpg_error_t
new_part (void *cookie, const char *mediatype, const char *mediasubtype)
{
  receive_ctx_t ctx = cookie;
  gpg_error_t err = 0;

  ctx->collect_key_data = 0;
  ctx->collect_wkd_data = 0;

  if (!strcmp (mediatype, "application")
      && !strcmp (mediasubtype, "pgp-keys"))
    {
      log_info ("new '%s/%s' message part\n", mediatype, mediasubtype);
      if (ctx->key_data)
        {
          log_error ("we already got a key - ignoring this part\n");
          err = gpg_error (GPG_ERR_FALSE);
        }
      else
        {
          ctx->key_data = es_fopenmem (0, "w+b");
          if (!ctx->key_data)
            {
              err = gpg_error_from_syserror ();
              log_error ("error allocating space for key: %s\n",
                         gpg_strerror (err));
            }
          else
            {
              ctx->collect_key_data = 1;
              err = gpg_error (GPG_ERR_TRUE); /* We want the part decoded.  */
            }
        }
    }
  else if (!strcmp (mediatype, "application")
           && !strcmp (mediasubtype, "vnd.gnupg.wks"))
    {
      log_info ("new '%s/%s' message part\n", mediatype, mediasubtype);
      if (ctx->wkd_data)
        {
          log_error ("we already got a wkd part - ignoring this part\n");
          err = gpg_error (GPG_ERR_FALSE);
        }
      else
        {
          ctx->wkd_data = es_fopenmem (0, "w+b");
          if (!ctx->wkd_data)
            {
              err = gpg_error_from_syserror ();
              log_error ("error allocating space for key: %s\n",
                         gpg_strerror (err));
            }
          else
            {
              ctx->collect_wkd_data = 1;
              err = gpg_error (GPG_ERR_TRUE); /* We want the part decoded.  */
            }
        }
    }
  else if (!strcmp (mediatype, "multipart")
           && !strcmp (mediasubtype, "mixed"))
    {
      ctx->multipart_mixed_seen = 1;
    }
  else if (!strcmp (mediatype, "text"))
    {
      /* Check that we receive a text part only after a
       * application/mixed.  This is actually a too simple test and we
       * should eventually employ a strict MIME structure check.  */
      if (!ctx->multipart_mixed_seen)
        err = gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }
  else
    {
      log_error ("unexpected '%s/%s' message part\n", mediatype, mediasubtype);
      err = gpg_error (GPG_ERR_FALSE); /* We do not want the part.  */
    }

  return err;
}


static gpg_error_t
part_data (void *cookie, const void *data, size_t datalen)
{
  receive_ctx_t ctx = cookie;

  if (data)
    {
      if (DBG_MIME)
        log_debug ("part_data: '%.*s'\n", (int)datalen, (const char*)data);
      if (ctx->collect_key_data)
        {
          if (es_write (ctx->key_data, data, datalen, NULL)
              || es_fputs ("\n", ctx->key_data))
            return gpg_error_from_syserror ();
        }
      if (ctx->collect_wkd_data)
        {
          if (es_write (ctx->wkd_data, data, datalen, NULL)
              || es_fputs ("\n", ctx->wkd_data))
            return gpg_error_from_syserror ();
        }
    }
  else
    {
      if (DBG_MIME)
        log_debug ("part_data: finished\n");
      ctx->collect_key_data = 0;
      ctx->collect_wkd_data = 0;
    }
  return 0;
}


/* Receive a WKS mail from FP and process it accordingly.  On success
 * the RESULT_CB is called with the mediatype and a stream with the
 * decrypted data. */
gpg_error_t
wks_receive (estream_t fp,
             gpg_error_t (*result_cb)(void *opaque,
                                      const char *mediatype,
                                      estream_t data,
                                      unsigned int flags),
             void *cb_data)
{
  gpg_error_t err;
  receive_ctx_t ctx;
  mime_parser_t parser;
  estream_t plaintext = NULL;
  int c;
  unsigned int flags = 0;

  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    return gpg_error_from_syserror ();

  err = mime_parser_new (&parser, ctx);
  if (err)
    goto leave;
  if (DBG_PARSER)
    mime_parser_set_verbose (parser, 1);
  mime_parser_set_t2body (parser, t2body);
  mime_parser_set_new_part (parser, new_part);
  mime_parser_set_part_data (parser, part_data);
  mime_parser_set_collect_encrypted (parser, collect_encrypted);
  mime_parser_set_collect_signeddata (parser, collect_signeddata);
  mime_parser_set_collect_signature (parser, collect_signature);

  ctx->parser = parser;

  err = mime_parser_parse (parser, fp);
  if (err)
    goto leave;

  if (ctx->key_data)
    log_info ("key data found\n");
  if (ctx->wkd_data)
    log_info ("wkd data found\n");
  if (ctx->draft_version_2)
    {
      log_info ("draft version 2 requested\n");
      flags |= WKS_RECEIVE_DRAFT2;
    }

  if (ctx->plaintext)
    {
      if (opt.verbose)
        log_info ("parsing decrypted message\n");
      plaintext = ctx->plaintext;
      ctx->plaintext = NULL;
      if (ctx->encrypted)
        es_rewind (ctx->encrypted);
      if (ctx->signeddata)
        es_rewind (ctx->signeddata);
      if (ctx->signature)
        es_rewind (ctx->signature);
      err = mime_parser_parse (parser, plaintext);
      if (err)
        return err;
    }

  if (!ctx->key_data && !ctx->wkd_data)
    {
      log_error ("no suitable data found in the message\n");
      err = gpg_error (GPG_ERR_NO_DATA);
      goto leave;
    }

  if (ctx->key_data)
    {
      if (DBG_MIME)
        {
          es_rewind (ctx->key_data);
          log_debug ("Key: '");
          log_printf ("\n");
          while ((c = es_getc (ctx->key_data)) != EOF)
            log_printf ("%c", c);
          log_printf ("'\n");
        }
      if (result_cb)
        {
          es_rewind (ctx->key_data);
          err = result_cb (cb_data, "application/pgp-keys",
                           ctx->key_data, flags);
          if (err)
            goto leave;
        }
    }
  if (ctx->wkd_data)
    {
      if (DBG_MIME)
        {
          es_rewind (ctx->wkd_data);
          log_debug ("WKD: '");
          log_printf ("\n");
          while ((c = es_getc (ctx->wkd_data)) != EOF)
            log_printf ("%c", c);
          log_printf ("'\n");
        }
      if (result_cb)
        {
          es_rewind (ctx->wkd_data);
          err = result_cb (cb_data, "application/vnd.gnupg.wks",
                           ctx->wkd_data, flags);
          if (err)
            goto leave;
        }
    }


 leave:
  es_fclose (plaintext);
  mime_parser_release (parser);
  ctx->parser = NULL;
  es_fclose (ctx->encrypted);
  es_fclose (ctx->plaintext);
  es_fclose (ctx->signeddata);
  es_fclose (ctx->signature);
  es_fclose (ctx->key_data);
  es_fclose (ctx->wkd_data);
  xfree (ctx);
  return err;
}
