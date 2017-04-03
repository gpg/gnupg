/* ks-engine-http.c - HTTP OpenPGP key access
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "dirmngr.h"
#include "misc.h"
#include "ks-engine.h"

/* How many redirections do we allow.  */
#define MAX_REDIRECTS 2

/* Print a help output for the schemata supported by this module. */
gpg_error_t
ks_http_help (ctrl_t ctrl, parsed_uri_t uri)
{
  const char data[] =
    "Handler for HTTP URLs:\n"
    "  http://\n"
#if  HTTP_USE_GNUTLS || HTTP_USE_NTBTLS
    "  https://\n"
#endif
    "Supported methods: fetch\n";
  gpg_error_t err;

#if  HTTP_USE_GNUTLS || HTTP_USE_NTBTLS
  const char data2[] = "  http\n  https";
#else
  const char data2[] = "  http";
#endif

  if (!uri)
    err = ks_print_help (ctrl, data2);
  else if (uri->is_http && strcmp (uri->scheme, "hkp"))
    err = ks_print_help (ctrl, data);
  else
    err = 0;

  return err;
}


/* Get the key from URL which is expected to specify a http style
   scheme.  On success R_FP has an open stream to read the data.  */
gpg_error_t
ks_http_fetch (ctrl_t ctrl, const char *url, estream_t *r_fp)
{
  gpg_error_t err;
  http_session_t session = NULL;
  http_t http = NULL;
  int redirects_left = MAX_REDIRECTS;
  estream_t fp = NULL;
  char *request_buffer = NULL;

 once_more:
  /* Note that we only use the system provided certificates with the
   * fetch command.  */
  err = http_session_new (&session, NULL,
                          ((ctrl->http_no_crl? HTTP_FLAG_NO_CRL : 0)
                           | HTTP_FLAG_TRUST_SYS),
                          gnupg_http_tls_verify_cb, ctrl);
  if (err)
    goto leave;
  http_session_set_log_cb (session, cert_log_cb);

  *r_fp = NULL;
  err = http_open (&http,
                   HTTP_REQ_GET,
                   url,
                   /* httphost */ NULL,
                   /* fixme: AUTH */ NULL,
                   ((opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY:0)
                    | (dirmngr_use_tor ()? HTTP_FLAG_FORCE_TOR:0)
                    | (opt.disable_ipv4? HTTP_FLAG_IGNORE_IPv4 : 0)
                    | (opt.disable_ipv6? HTTP_FLAG_IGNORE_IPv6 : 0)),
                   ctrl->http_proxy,
                   session,
                   NULL,
                   /*FIXME curl->srvtag*/NULL);
  if (!err)
    {
      fp = http_get_write_ptr (http);
      /* Avoid caches to get the most recent copy of the key.  We set
         both the Pragma and Cache-Control versions of the header, so
         we're good with both HTTP 1.0 and 1.1.  */
      es_fputs ("Pragma: no-cache\r\n"
                "Cache-Control: no-cache\r\n", fp);
      http_start_data (http);
      if (es_ferror (fp))
        err = gpg_error_from_syserror ();
    }
  if (err)
    {
      /* Fixme: After a redirection we show the old host name.  */
      log_error (_("error connecting to '%s': %s\n"),
                 url, gpg_strerror (err));
      goto leave;
    }

  /* Wait for the response.  */
  dirmngr_tick (ctrl);
  err = http_wait_response (http);
  if (err)
    {
      log_error (_("error reading HTTP response for '%s': %s\n"),
                 url, gpg_strerror (err));
      goto leave;
    }

  switch (http_get_status_code (http))
    {
    case 200:
      err = 0;
      break; /* Success.  */

    case 301:
    case 302:
    case 307:
      {
        const char *s = http_get_header (http, "Location");

        log_info (_("URL '%s' redirected to '%s' (%u)\n"),
                  url, s?s:"[none]", http_get_status_code (http));
        if (s && *s && redirects_left-- )
          {
            xfree (request_buffer);
            request_buffer = xtrystrdup (s);
            if (request_buffer)
              {
                url = request_buffer;
                http_close (http, 0);
                http = NULL;
                http_session_release (session);
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
      log_error (_("error accessing '%s': http status %u\n"),
                 url, http_get_status_code (http));
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
  http_session_release (session);
  xfree (request_buffer);
  return err;
}
