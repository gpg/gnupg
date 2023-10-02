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
 * scheme.  On success R_FP has an open stream to read the data.
 * Despite its name this function is also used to retrieve arbitrary
 * data via https or http.
 */
gpg_error_t
ks_http_fetch (ctrl_t ctrl, const char *url, unsigned int flags,
               estream_t *r_fp)
{
  gpg_error_t err;
  http_session_t session = NULL;
  unsigned int session_flags;
  http_t http = NULL;
  http_redir_info_t redirinfo = { MAX_REDIRECTS };
  estream_t fp = NULL;
  char *request_buffer = NULL;
  parsed_uri_t uri = NULL;
  parsed_uri_t helpuri = NULL;

  err = http_parse_uri (&uri, url, 0);
  if (err)
    goto leave;
  redirinfo.ctrl       = ctrl;
  redirinfo.orig_url   = url;
  redirinfo.orig_onion = uri->onion;
  redirinfo.orig_https = uri->use_tls;
  redirinfo.allow_downgrade = !!(flags & KS_HTTP_FETCH_ALLOW_DOWNGRADE);
  redirinfo.restrict_redir = !!(opt.compat_flags & COMPAT_RESTRICT_HTTP_REDIR);

  /* By default we only use the system provided certificates with this
   * fetch command.  */
  session_flags = HTTP_FLAG_TRUST_SYS;
  if ((flags & KS_HTTP_FETCH_NO_CRL) || ctrl->http_no_crl)
    session_flags |= HTTP_FLAG_NO_CRL;
  if ((flags & KS_HTTP_FETCH_TRUST_CFG))
    session_flags |= HTTP_FLAG_TRUST_CFG;

 once_more:
  err = http_session_new (&session, NULL, session_flags,
                          gnupg_http_tls_verify_cb, ctrl);
  if (err)
    goto leave;
  http_session_set_log_cb (session, cert_log_cb);
  http_session_set_timeout (session, ctrl->timeout);

  *r_fp = NULL;
  err = http_open (ctrl, &http,
                   HTTP_REQ_GET,
                   url,
                   /* httphost */ NULL,
                   /* fixme: AUTH */ NULL,
                   ((opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY:0)
                    | (DBG_LOOKUP? HTTP_FLAG_LOG_RESP:0)
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
       * both the Pragma and Cache-Control versions of the header, so
       * we're good with both HTTP 1.0 and 1.1.  */
      if ((flags & KS_HTTP_FETCH_NOCACHE))
        es_fputs ("Pragma: no-cache\r\n"
                  "Cache-Control: no-cache\r\n", fp);
      http_start_data (http);
      if (es_ferror (fp))
        err = gpg_error_from_syserror ();
    }
  if (err)
    {
      log_error (_("error connecting to '%s': %s\n"),
                 url, gpg_strerror (err));
      if (gpg_err_code (err) == GPG_ERR_WRONG_NAME
          && gpg_err_source (err) == GPG_ERR_SOURCE_TLS)
        {
          const char *errhostname;

          http_release_parsed_uri (helpuri);
          if (http_parse_uri (&helpuri, url, 0))
            errhostname = url; /* On parse error we use the full URL. */
          else
            errhostname = helpuri->host? helpuri->host : "?";

          dirmngr_status_printf (ctrl, "NOTE",
                                 "tls_cert_error %u"
                                 " bad cert for '%s': %s",
                                 err, errhostname,
                                 "Hostname does not match the certificate");
        }
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
        xfree (request_buffer);
        err = http_prepare_redirect (&redirinfo, http_get_status_code (http),
                                     http_get_header (http, "Location", 0),
                                     &request_buffer);
        if (err)
          goto leave;

        url = request_buffer;
        http_close (http, 0);
        http = NULL;
        http_session_release (session);
        session = NULL;
      }
      goto once_more;

    default:
      log_error (_("error accessing '%s': http status %u\n"),
                 url, http_get_status_code (http));
      switch (http_get_status_code (http))
        {
        case 401: err = gpg_error (GPG_ERR_NO_AUTH); break;
        case 407: err = gpg_error (GPG_ERR_BAD_AUTH); break;
        case 413: err = gpg_error (GPG_ERR_TOO_LARGE); break;
        default:  err = gpg_error (GPG_ERR_NO_DATA); break;
        }
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
  http_release_parsed_uri (uri);
  http_release_parsed_uri (helpuri);
  return err;
}
