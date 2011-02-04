/* ks-engine-hkp.c - HKP keyserver engine
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "dirmngr.h"
#include "misc.h"
#include "userids.h"
#include "ks-engine.h"

/* To match the behaviour of our old gpgkeys helper code we escape
   more characters than actually needed. */
#define EXTRA_ESCAPE_CHARS "@!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

/* How many redirections do we allow.  */
#define MAX_REDIRECTS 2


/* Send an HTTP request.  On success returns an estream object at
   R_FP.  HOSTPORTSTR is only used for diagnostics.  If POST_CB is not
   NULL a post request is used and that callback is called to allow
   writing the post data.  */
static gpg_error_t
send_request (ctrl_t ctrl, const char *request, const char *hostportstr,
              gpg_error_t (*post_cb)(void *, http_t), void *post_cb_value,
              estream_t *r_fp)
{
  gpg_error_t err;
  http_t http = NULL;
  int redirects_left = MAX_REDIRECTS;
  estream_t fp = NULL;
  char *request_buffer = NULL;

  *r_fp = NULL;
 once_more:
  err = http_open (&http,
                   post_cb? HTTP_REQ_POST : HTTP_REQ_GET,
                   request,
                   /* fixme: AUTH */ NULL,
                   0,
                   /* fixme: proxy*/ NULL,
                   NULL, NULL,
                   /*FIXME curl->srvtag*/NULL);
  if (!err)
    {
      fp = http_get_write_ptr (http);
      /* Avoid caches to get the most recent copy of the key.  We set
         both the Pragma and Cache-Control versions of the header, so
         we're good with both HTTP 1.0 and 1.1.  */
      es_fputs ("Pragma: no-cache\r\n"
                "Cache-Control: no-cache\r\n", fp);
      if (post_cb)
        err = post_cb (post_cb_value, http);
      if (!err)
        {
          http_start_data (http);
          if (es_ferror (fp))
            err = gpg_error_from_syserror ();
        }
    }
  if (err)
    {
      /* Fixme: After a redirection we show the old host name.  */
      log_error (_("error connecting to `%s': %s\n"),
                 hostportstr, gpg_strerror (err));
      goto leave;
    }

  /* Wait for the response.  */
  dirmngr_tick (ctrl);
  err = http_wait_response (http);
  if (err)
    {
      log_error (_("error reading HTTP response for `%s': %s\n"),
                 hostportstr, gpg_strerror (err));
      goto leave;
    }

  switch (http_get_status_code (http))
    {
    case 200:
      err = 0;
      break; /* Success.  */

    case 301:
    case 302:
      {
        const char *s = http_get_header (http, "Location");

        log_info (_("URL `%s' redirected to `%s' (%u)\n"),
                  request, s?s:"[none]", http_get_status_code (http));
        if (s && *s && redirects_left-- )
          {
            xfree (request_buffer);
            request_buffer = xtrystrdup (s);
            if (request_buffer)
              {
                request = request_buffer;
                http_close (http, 0);
                http = NULL;
                goto once_more;
              }
            err = gpg_error_from_syserror ();
          }
        else
          err = gpg_error (GPG_ERR_NO_DATA);
        log_error (_("too many redirections\n"));
      }
      goto leave;

    default:
      log_error (_("error accessing `%s': http status %u\n"),
                 request, http_get_status_code (http));
      err = gpg_error (GPG_ERR_NO_DATA);
      goto leave;
    }

  fp = http_get_read_ptr (http);
  if (!fp)
    {
      err = gpg_error (GPG_ERR_BUG);
      goto leave;
    }

  /* Return the read stream and close the HTTP context.  */
  *r_fp = fp;
  http_close (http, 1);
  http = NULL;

 leave:
  http_close (http, 0);
  xfree (request_buffer);
  return err;
}


static gpg_error_t
armor_data (char **r_string, const void *data, size_t datalen)
{
  gpg_error_t err;
  struct b64state b64state;
  estream_t fp;
  long length;
  char *buffer;
  size_t nread;

  *r_string = NULL;

  fp = es_fopenmem (0, "rw");
  if (!fp)
    return gpg_error_from_syserror ();

  if ((err=b64enc_start_es (&b64state, fp, "PGP PUBLIC KEY BLOCK"))
      || (err=b64enc_write (&b64state, data, datalen))
      || (err = b64enc_finish (&b64state)))
    {
      es_fclose (fp);
      return err;
    }

  /* FIXME: To avoid the extra buffer allocation estream should
     provide a function to snatch the internal allocated memory from
     such a memory stream.  */
  length = es_ftell (fp);
  if (length < 0)
    {
      err = gpg_error_from_syserror ();
      es_fclose (fp);
      return err;
    }

  buffer = xtrymalloc (length+1);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      es_fclose (fp);
      return err;
    }

  es_rewind (fp);
  if (es_read (fp, buffer, length, &nread))
    {
      err = gpg_error_from_syserror ();
      es_fclose (fp);
      return err;
    }
  buffer[nread] = 0;
  es_fclose (fp);

  *r_string = buffer;
  return 0;
}




/* Search the keyserver identified by URI for keys matching PATTERN.
   On success R_FP has an open stream to read the data.  */
gpg_error_t
ks_hkp_search (ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
               estream_t *r_fp)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char fprbuf[2+40+1];
  const char *scheme;
  char portstr[10];
  char *hostport = NULL;
  char *request = NULL;
  estream_t fp = NULL;

  *r_fp = NULL;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id (pattern, &desc);
  if (err)
    return err;
  switch (desc.mode)
    {
    case KEYDB_SEARCH_MODE_EXACT:
    case KEYDB_SEARCH_MODE_SUBSTR:
    case KEYDB_SEARCH_MODE_MAIL:
    case KEYDB_SEARCH_MODE_MAILSUB:
      pattern = desc.u.name;
      break;
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf (fprbuf, sizeof fprbuf, "0x%08lX", (ulong)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf (fprbuf, sizeof fprbuf, "0x%08lX%08lX",
                (ulong)desc.u.kid[0], (ulong)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR16:
      bin2hex (desc.u.fpr, 16, fprbuf);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      bin2hex (desc.u.fpr, 20, fprbuf);
      pattern = fprbuf;
      break;
    default:
      return gpg_error (GPG_ERR_INV_USER_ID);
    }

  /* Map scheme and port.  */
  if (!strcmp (uri->scheme,"hkps") || !strcmp (uri->scheme,"https"))
    {
      scheme = "https";
      strcpy (portstr, "443");
    }
  else /* HKP or HTTP.  */
    {
      scheme = "http";
      strcpy (portstr, "11371");
    }
  if (uri->port)
    snprintf (portstr, sizeof portstr, "%hu", uri->port);
  else
    {} /*fixme_do_srv_lookup ()*/

  /* Build the request string.  */
  {
    char *searchkey;

    hostport = strconcat (scheme, "://",
                          *uri->host? uri->host: "localhost",
                          ":", portstr, NULL);
    if (!hostport)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }

    searchkey = http_escape_string (pattern, EXTRA_ESCAPE_CHARS);
    if (!searchkey)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }

    request = strconcat (hostport,
                         "/pks/lookup?op=index&options=mr&search=",
                         searchkey,
                         NULL);
    xfree (searchkey);
    if (!request)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
  }

  /* Send the request.  */
  err = send_request (ctrl, request, hostport, NULL, NULL, &fp);
  if (err)
    goto leave;

  /* Start reading the response.  */
  {
    int c = es_getc (fp);
    if (c == -1)
      {
        err = es_ferror (fp)?gpg_error_from_syserror ():gpg_error (GPG_ERR_EOF);
        log_error ("error reading response: %s\n", gpg_strerror (err));
        goto leave;
      }
    if (c == '<')
      {
        /* The document begins with a '<', assume it's a HTML
           response, which we don't support.  */
        err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
        goto leave;
      }
    es_ungetc (c, fp);
  }

  /* Return the read stream.  */
  *r_fp = fp;
  fp = NULL;

 leave:
  es_fclose (fp);
  xfree (request);
  xfree (hostport);
  return err;
}


/* Get the key described key the KEYSPEC string from the keyserver
   identified by URI.  On success R_FP has an open stream to read the
   data.  */
gpg_error_t
ks_hkp_get (ctrl_t ctrl, parsed_uri_t uri, const char *keyspec, estream_t *r_fp)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char kidbuf[8+1];
  const char *scheme;
  char portstr[10];
  char *hostport = NULL;
  char *request = NULL;
  estream_t fp = NULL;

  *r_fp = NULL;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id (keyspec, &desc);
  if (err)
    return err;
  switch (desc.mode)
    {
    case KEYDB_SEARCH_MODE_SHORT_KID:
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf (kidbuf, sizeof kidbuf, "%08lX", (ulong)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      /* This is a v4 fingerprint.  Take the last 8 hex digits from
         the fingerprint which is the expected short keyid.  */
      bin2hex (desc.u.fpr+16, 4, kidbuf);
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      log_error ("HKP keyserver do not support v3 fingerprints\n");
    default:
      return gpg_error (GPG_ERR_INV_USER_ID);
    }

  /* Map scheme and port.  */
  if (!strcmp (uri->scheme,"hkps") || !strcmp (uri->scheme,"https"))
    {
      scheme = "https";
      strcpy (portstr, "443");
    }
  else /* HKP or HTTP.  */
    {
      scheme = "http";
      strcpy (portstr, "11371");
    }
  if (uri->port)
    snprintf (portstr, sizeof portstr, "%hu", uri->port);
  else
    {} /*fixme_do_srv_lookup ()*/

  /* Build the request string.  */
  {
    hostport = strconcat (scheme, "://",
                          *uri->host? uri->host: "localhost",
                          ":", portstr, NULL);
    if (!hostport)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }

    request = strconcat (hostport,
                         "/pks/lookup?op=get&options=mr&search=0x",
                         kidbuf,
                         NULL);
    if (!request)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
  }

  /* Send the request.  */
  err = send_request (ctrl, request, hostport, NULL, NULL, &fp);
  if (err)
    goto leave;

  /* Return the read stream and close the HTTP context.  */
  *r_fp = fp;
  fp = NULL;

 leave:
  es_fclose (fp);
  xfree (request);
  xfree (hostport);
  return err;
}




/* Callback parameters for put_post_cb.  */
struct put_post_parm_s
{
  char *datastring;
};


/* Helper for ks_hkp_put.  */
static gpg_error_t
put_post_cb (void *opaque, http_t http)
{
  struct put_post_parm_s *parm = opaque;
  gpg_error_t err = 0;
  estream_t fp;
  size_t len;

  fp = http_get_write_ptr (http);
  len = strlen (parm->datastring);

  es_fprintf (fp,
              "Content-Type: application/x-www-form-urlencoded\r\n"
              "Content-Length: %zu\r\n", len+8 /* 8 is for "keytext" */);
  http_start_data (http);
  if (es_fputs ("keytext=", fp) || es_write (fp, parm->datastring, len, NULL))
    err = gpg_error_from_syserror ();
  return err;
}


/* Send the key in {DATA,DATALEN} to the keyserver identified by  URI.  */
gpg_error_t
ks_hkp_put (ctrl_t ctrl, parsed_uri_t uri, const void *data, size_t datalen)
{
  gpg_error_t err;
  const char *scheme;
  char portstr[10];
  char *hostport = NULL;
  char *request = NULL;
  estream_t fp = NULL;
  struct put_post_parm_s parm;
  char *armored = NULL;

  parm.datastring = NULL;

  /* Map scheme and port.  */
  if (!strcmp (uri->scheme,"hkps") || !strcmp (uri->scheme,"https"))
    {
      scheme = "https";
      strcpy (portstr, "443");
    }
  else /* HKP or HTTP.  */
    {
      scheme = "http";
      strcpy (portstr, "11371");
    }
  if (uri->port)
    snprintf (portstr, sizeof portstr, "%hu", uri->port);
  else
    {} /*fixme_do_srv_lookup ()*/

  err = armor_data (&armored, data, datalen);
  if (err)
    goto leave;

  parm.datastring = http_escape_string (armored, EXTRA_ESCAPE_CHARS);
  if (!parm.datastring)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  xfree (armored);
  armored = NULL;

  /* Build the request string.  */
  hostport = strconcat (scheme, "://",
                        *uri->host? uri->host: "localhost",
                        ":", portstr, NULL);
  if (!hostport)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  request = strconcat (hostport, "/pks/add", NULL);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Send the request.  */
  err = send_request (ctrl, request, hostport, put_post_cb, &parm, &fp);
  if (err)
    goto leave;

 leave:
  es_fclose (fp);
  xfree (parm.datastring);
  xfree (armored);
  xfree (request);
  xfree (hostport);
  return err;
}
