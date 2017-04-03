/* crlfetch.c - LDAP access
 *      Copyright (C) 2002 Klarälvdalens Datakonsult AB
 *      Copyright (C) 2003, 2004, 2005, 2006, 2007 g10 Code GmbH
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <errno.h>
#include <npth.h>

#include "crlfetch.h"
#include "dirmngr.h"
#include "misc.h"
#include "http.h"

#if USE_LDAP
# include "ldap-wrapper.h"
#endif

/* For detecting armored CRLs received via HTTP (yes, such CRLS really
   exits, e.g. http://grid.fzk.de/ca/gridka-crl.pem at least in June
   2008) we need a context in the reader callback.  */
struct reader_cb_context_s
{
  estream_t fp;             /* The stream used with the ksba reader.  */
  int checked:1;            /* PEM/binary detection ahs been done.    */
  int is_pem:1;             /* The file stream is PEM encoded.        */
  struct b64state b64state; /* The state used for Base64 decoding.    */
};


/* We need to associate a reader object with the reader callback
   context.  This table is used for it. */
struct file_reader_map_s
{
  ksba_reader_t reader;
  struct reader_cb_context_s *cb_ctx;
};
#define MAX_FILE_READER 50
static struct file_reader_map_s file_reader_map[MAX_FILE_READER];

/* Associate FP with READER.  If the table is full wait until another
   thread has removed an entry.  */
static void
register_file_reader (ksba_reader_t reader, struct reader_cb_context_s *cb_ctx)
{
  int i;

  for (;;)
    {
      for (i=0; i < MAX_FILE_READER; i++)
        if (!file_reader_map[i].reader)
          {
            file_reader_map[i].reader = reader;
            file_reader_map[i].cb_ctx = cb_ctx;
            return;
          }
      log_info (_("reader to file mapping table full - waiting\n"));
      npth_sleep (2);
    }
}

/* Scan the table for an entry matching READER, remove that entry and
   return the associated file pointer. */
static struct reader_cb_context_s *
get_file_reader (ksba_reader_t reader)
{
  struct reader_cb_context_s *cb_ctx = NULL;
  int i;

  for (i=0; i < MAX_FILE_READER; i++)
    if (file_reader_map[i].reader == reader)
      {
        cb_ctx = file_reader_map[i].cb_ctx;
        file_reader_map[i].reader = NULL;
        file_reader_map[i].cb_ctx = NULL;
        break;
      }
  return cb_ctx;
}



static int
my_es_read (void *opaque, char *buffer, size_t nbytes, size_t *nread)
{
  struct reader_cb_context_s *cb_ctx = opaque;
  int result;

  result = es_read (cb_ctx->fp, buffer, nbytes, nread);
  if (result)
    return result;
  /* Fixme we should check whether the semantics of es_read are okay
     and well defined.  I have some doubts.  */
  if (nbytes && !*nread && es_feof (cb_ctx->fp))
    return gpg_error (GPG_ERR_EOF);
  if (!nread && es_ferror (cb_ctx->fp))
    return gpg_error (GPG_ERR_EIO);

  if (!cb_ctx->checked && *nread)
    {
      int c = *(unsigned char *)buffer;

      cb_ctx->checked = 1;
      if ( ((c & 0xc0) >> 6) == 0 /* class: universal */
           && (c & 0x1f) == 16    /* sequence */
           && (c & 0x20)          /* is constructed */ )
        ; /* Binary data.  */
      else
        {
          cb_ctx->is_pem = 1;
          b64dec_start (&cb_ctx->b64state, "");
        }
    }
  if (cb_ctx->is_pem && *nread)
    {
      size_t nread2;

      if (b64dec_proc (&cb_ctx->b64state, buffer, *nread, &nread2))
        {
          /* EOF from decoder. */
          *nread = 0;
          result = gpg_error (GPG_ERR_EOF);
        }
      else
        *nread = nread2;
    }

  return result;
}


/* Fetch CRL from URL and return the entire CRL using new ksba reader
   object in READER.  Note that this reader object should be closed
   only using ldap_close_reader. */
gpg_error_t
crl_fetch (ctrl_t ctrl, const char *url, ksba_reader_t *reader)
{
  gpg_error_t err;
  parsed_uri_t uri;
  char *free_this = NULL;
  int redirects_left = 2; /* We allow for 2 redirect levels.  */

  *reader = NULL;

  if (!url)
    return gpg_error (GPG_ERR_INV_ARG);

 once_more:
  err = http_parse_uri (&uri, url, 0);
  http_release_parsed_uri (uri);
  if (err && !strncmp (url, "https:", 6))
    {
      /* FIXME: We now support https.
       * Our HTTP code does not support TLS, thus we can't use this
       * scheme and it is frankly not useful for CRL retrieval anyway.
       * We resort to using http, assuming that the server also
       * provides plain http access.  */
      free_this = xtrymalloc (strlen (url) + 1);
      if (free_this)
        {
          strcpy (stpcpy (free_this,"http:"), url+6);
          err = http_parse_uri (&uri, free_this, 0);
          http_release_parsed_uri (uri);
          if (!err)
            {
              log_info (_("using \"http\" instead of \"https\"\n"));
              url = free_this;
            }
        }
    }
  if (!err) /* Yes, our HTTP code groks that. */
    {
      http_t hd;

      if (opt.disable_http)
        {
          log_error (_("CRL access not possible due to disabled %s\n"),
                     "HTTP");
          err = gpg_error (GPG_ERR_NOT_SUPPORTED);
        }
      else
        err = http_open_document (&hd, url, NULL,
                                  ((opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY:0)
                                   |(DBG_LOOKUP? HTTP_FLAG_LOG_RESP:0)
                                   |(dirmngr_use_tor()? HTTP_FLAG_FORCE_TOR:0)
                                   |(opt.disable_ipv4? HTTP_FLAG_IGNORE_IPv4:0)
                                   |(opt.disable_ipv6? HTTP_FLAG_IGNORE_IPv6:0)
                                   ),
                                  ctrl->http_proxy, NULL, NULL, NULL);

      switch ( err? 99999 : http_get_status_code (hd) )
        {
        case 200:
          {
            estream_t fp = http_get_read_ptr (hd);
            struct reader_cb_context_s *cb_ctx;

            cb_ctx = xtrycalloc (1, sizeof *cb_ctx);
            if (!cb_ctx)
              err = gpg_error_from_syserror ();
            if (!err)
              err = ksba_reader_new (reader);
            if (!err)
              {
                cb_ctx->fp = fp;
                err = ksba_reader_set_cb (*reader, &my_es_read, cb_ctx);
              }
            if (err)
              {
                log_error (_("error initializing reader object: %s\n"),
                           gpg_strerror (err));
                ksba_reader_release (*reader);
                *reader = NULL;
                http_close (hd, 0);
              }
            else
              {
                /* The ksba reader misses a user pointer thus we need
                   to come up with our own way of associating a file
                   pointer (or well the callback context) with the
                   reader.  It is only required when closing the
                   reader thus there is no performance issue doing it
                   this way.  FIXME: We now have a close notification
                   which might be used here. */
                register_file_reader (*reader, cb_ctx);
                http_close (hd, 1);
              }
          }
          break;

        case 301: /* Redirection (perm.). */
        case 302: /* Redirection (temp.). */
          {
            const char *s = http_get_header (hd, "Location");

            log_info (_("URL '%s' redirected to '%s' (%u)\n"),
                      url, s?s:"[none]", http_get_status_code (hd));
            if (s && *s && redirects_left-- )
              {
                xfree (free_this); url = NULL;
                free_this = xtrystrdup (s);
                if (!free_this)
                  err = gpg_error_from_errno (errno);
                else
                  {
                    url = free_this;
                    http_close (hd, 0);
                    /* Note, that our implementation of redirection
                       actually handles a redirect to LDAP.  */
                    goto once_more;
                  }
              }
            else
              err = gpg_error (GPG_ERR_NO_DATA);
            log_error (_("too many redirections\n")); /* Or no "Location". */
            http_close (hd, 0);
          }
          break;

        case 99999: /* Made up status code for error reporting.  */
          log_error (_("error retrieving '%s': %s\n"),
                     url, gpg_strerror (err));
          break;

        default:
          log_error (_("error retrieving '%s': http status %u\n"),
                     url, http_get_status_code (hd));
          err = gpg_error (GPG_ERR_NO_DATA);
          http_close (hd, 0);
        }
    }
  else /* Let the LDAP code try other schemes. */
    {
      if (opt.disable_ldap)
        {
          log_error (_("CRL access not possible due to disabled %s\n"),
                     "LDAP");
          err = gpg_error (GPG_ERR_NOT_SUPPORTED);
        }
      else if (dirmngr_use_tor ())
        {
          /* For now we do not support LDAP over Tor.  */
          log_error (_("CRL access not possible due to Tor mode\n"));
          err = gpg_error (GPG_ERR_NOT_SUPPORTED);
        }
      else
        {
#       if USE_LDAP
          err = url_fetch_ldap (ctrl, url, NULL, 0, reader);
#       else /*!USE_LDAP*/
          err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#       endif /*!USE_LDAP*/
        }
    }

  xfree (free_this);
  return err;
}


/* Fetch CRL for ISSUER using a default server. Return the entire CRL
   as a newly opened stream returned in R_FP. */
gpg_error_t
crl_fetch_default (ctrl_t ctrl, const char *issuer, ksba_reader_t *reader)
{
  if (dirmngr_use_tor ())
    {
      /* For now we do not support LDAP over Tor.  */
      log_error (_("CRL access not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
  if (opt.disable_ldap)
    {
      log_error (_("CRL access not possible due to disabled %s\n"),
                 "LDAP");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

#if USE_LDAP
  return attr_fetch_ldap (ctrl, issuer, "certificateRevocationList",
                          reader);
#else
  (void)ctrl;
  (void)issuer;
  (void)reader;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}


/* Fetch a CA certificate for DN using the default server.  This
 * function only initiates the fetch; fetch_next_cert must be used to
 * actually read the certificate; end_cert_fetch to end the
 * operation.  */
gpg_error_t
ca_cert_fetch (ctrl_t ctrl, cert_fetch_context_t *context, const char *dn)
{
  if (dirmngr_use_tor ())
    {
      /* For now we do not support LDAP over Tor.  */
      log_error (_("CRL access not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
  if (opt.disable_ldap)
    {
      log_error (_("CRL access not possible due to disabled %s\n"),
                 "LDAP");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
#if USE_LDAP
  return start_default_fetch_ldap (ctrl, context, dn, "cACertificate");
#else
  (void)ctrl;
  (void)context;
  (void)dn;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}


gpg_error_t
start_cert_fetch (ctrl_t ctrl, cert_fetch_context_t *context,
                  strlist_t patterns, const ldap_server_t server)
{
  if (dirmngr_use_tor ())
    {
      /* For now we do not support LDAP over Tor.  */
      log_error (_("CRL access not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
  if (opt.disable_ldap)
    {
      log_error (_("certificate search not possible due to disabled %s\n"),
                 "LDAP");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }
#if USE_LDAP
  return start_cert_fetch_ldap (ctrl, context, patterns, server);
#else
  (void)ctrl;
  (void)context;
  (void)patterns;
  (void)server;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}


gpg_error_t
fetch_next_cert (cert_fetch_context_t context,
                 unsigned char **value, size_t * valuelen)
{
#if USE_LDAP
  return fetch_next_cert_ldap (context, value, valuelen);
#else
  (void)context;
  (void)value;
  (void)valuelen;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}


/* Fetch the next data from CONTEXT, assuming it is a certificate and return
 * it as a cert object in R_CERT.  */
gpg_error_t
fetch_next_ksba_cert (cert_fetch_context_t context, ksba_cert_t *r_cert)
{
  gpg_error_t err;
  unsigned char *value;
  size_t valuelen;
  ksba_cert_t cert;

  *r_cert = NULL;

#if USE_LDAP
  err = fetch_next_cert_ldap (context, &value, &valuelen);
  if (!err && !value)
    err = gpg_error (GPG_ERR_BUG);
#else
  (void)context;
  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
  if (err)
    return err;

  err = ksba_cert_new (&cert);
  if (err)
    {
      xfree (value);
      return err;
    }

  err = ksba_cert_init_from_mem (cert, value, valuelen);
  xfree (value);
  if (err)
    {
      ksba_cert_release (cert);
      return err;
    }
  *r_cert = cert;
  return 0;
}


void
end_cert_fetch (cert_fetch_context_t context)
{
#if USE_LDAP
  end_cert_fetch_ldap (context);
#else
  (void)context;
#endif
}


/* Lookup a cert by it's URL.  */
gpg_error_t
fetch_cert_by_url (ctrl_t ctrl, const char *url,
		   unsigned char **value, size_t *valuelen)
{
  const unsigned char *cert_image;
  size_t cert_image_n;
  ksba_reader_t reader;
  ksba_cert_t cert;
  gpg_error_t err;

  *value = NULL;
  *valuelen = 0;
  cert_image = NULL;
  reader = NULL;
  cert = NULL;

#if USE_LDAP
  err = url_fetch_ldap (ctrl, url, NULL, 0, &reader);
#else
  (void)ctrl;
  (void)url;
  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif /*USE_LDAP*/
  if (err)
    goto leave;

  err = ksba_cert_new (&cert);
  if (err)
    goto leave;

  err = ksba_cert_read_der (cert, reader);
  if (err)
    goto leave;

  cert_image = ksba_cert_get_image (cert, &cert_image_n);
  if (!cert_image || !cert_image_n)
    {
      err = gpg_error (GPG_ERR_INV_CERT_OBJ);
      goto leave;
    }

  *value = xtrymalloc (cert_image_n);
  if (!*value)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  memcpy (*value, cert_image, cert_image_n);
  *valuelen = cert_image_n;

 leave:

  ksba_cert_release (cert);
#if USE_LDAP
  ldap_wrapper_release_context (reader);
#endif /*USE_LDAP*/

  return err;
}

/* This function is to be used to close the reader object.  In
   addition to running ksba_reader_release it also releases the LDAP
   or HTTP contexts associated with that reader.  */
void
crl_close_reader (ksba_reader_t reader)
{
  struct reader_cb_context_s *cb_ctx;

  if (!reader)
    return;

  /* Check whether this is a HTTP one. */
  cb_ctx = get_file_reader (reader);
  if (cb_ctx)
    {
      /* This is an HTTP context. */
      if (cb_ctx->fp)
        es_fclose (cb_ctx->fp);
      /* Release the base64 decoder state.  */
      if (cb_ctx->is_pem)
        b64dec_finish (&cb_ctx->b64state);
      /* Release the callback context.  */
      xfree (cb_ctx);
    }
  else /* This is an ldap wrapper context (Currently not used). */
    {
#if USE_LDAP
      ldap_wrapper_release_context (reader);
#endif /*USE_LDAP*/
    }

  /* Now get rid of the reader object. */
  ksba_reader_release (reader);
}
