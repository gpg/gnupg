/* rfc3161.c - X.509 Time-Stamp protocol using HTTPS transport.
 * Copyright (C) 2022-2023 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>


#include "dirmngr.h"
#include "misc.h"
#include "http.h"
#include "validate.h"
#include "certcache.h"
#include "rfc3161.h"
#include "../common/tlv.h"
#include "../common/exechelp.h"

#include <ksba.h>

/* The maximum size we allow as a response from TSA. */
#define MAX_RESPONSE_SIZE 65536

/* Read from FP and return a newly allocated buffer in R_BUFFER with the
   entire data read from FP. */
static gpg_error_t
read_response (estream_t fp, unsigned char **r_buffer, size_t *r_buflen)
{
  gpg_error_t err;
  unsigned char *buffer;
  size_t bufsize, nbytes;

  *r_buffer = NULL;
  *r_buflen = 0;

  bufsize = 4096;
  buffer = xtrymalloc (bufsize);
  if (!buffer)
    return gpg_error_from_errno (errno);

  nbytes = 0;
  for (;;)
    {
      unsigned char *tmp;
      size_t nread = 0;

      assert (nbytes < bufsize);
      nread = es_fread (buffer+nbytes, 1, bufsize-nbytes, fp);
      if (nread < bufsize-nbytes && es_ferror (fp))
        {
          err = gpg_error_from_errno (errno);
          log_error (_("error reading from responder: %s\n"),
                     strerror (errno));
          xfree (buffer);
          return err;
        }
      if ( !(nread == bufsize-nbytes && !es_feof (fp)))
        { /* Response successfully received. */
          nbytes += nread;
          *r_buffer = buffer;
          *r_buflen = nbytes;
          return 0;
        }

      nbytes += nread;

      /* Need to enlarge the buffer. */
      if (bufsize >= MAX_RESPONSE_SIZE)
        {
          log_error (_("response from server too large; limit is %d bytes\n"),
                     MAX_RESPONSE_SIZE);
          xfree (buffer);
          return gpg_error (GPG_ERR_TOO_LARGE);
        }

      bufsize += 4096;
      tmp = xtryrealloc (buffer, bufsize);
      if (!tmp)
        {
          err = gpg_error_from_errno (errno);
          xfree (buffer);
          return err;
        }
      buffer = tmp;
    }
}

static gpg_error_t
tsa_parse_response (const unsigned char *buffer, size_t length,
                    ksba_cms_t *r_cms, unsigned char **r_signed_data,
                    size_t *r_signed_data_length)
{
  gpg_error_t err = 0;
  const char *where = "";
  tlv_parser_t tlv;
  gcry_md_hd_t hd;
  unsigned char *tmperror;
  unsigned char *error;
  size_t error_length;
  const unsigned char *failinfo;
  size_t failinfo_length;
  const unsigned char *tmp_signed;
  struct tag_info info;
  size_t len;
  int status;
  ksba_reader_t reader;
  ksba_stop_reason_t stopreason;
  const char *algoid;
  int algo;
  int i;

  tlv = tlv_parser_new (buffer, length, 0);
  if (!tlv)
    {
      err = gpg_error_from_syserror();
      goto bailout;
    }
  where = "start";
  if (tlv_next(tlv))
    goto bailout;
  if (tlv_expect_sequence(tlv))
    goto bailout;

  where = "status";
  if (tlv_next(tlv))
    goto bailout;
  if (tlv_expect_sequence(tlv))
    goto bailout;

  where = "pkistatus";
  if (tlv_next(tlv))
    goto bailout;

  if (tlv_expect_integer(tlv, &status))
    goto bailout;

  if (status != 0) {
    if (tlv_next(tlv))
      goto bailout;
    where = "statusString";
    if (tlv_expect_sequence(tlv))
      goto bailout;

    where = "failInfo";
    if (tlv_next(tlv))
      goto bailout;

  errors:
    if (tlv_expect_object(tlv, CLASS_UNIVERSAL, TAG_UTF8_STRING, &tmperror, &error_length)) {
      goto bailout;
    }
    error = xtrymalloc(error_length + 1);
    memcpy(error, tmperror, error_length);
    error[error_length] = 0;
    log_error("Error: %s\n", error);
    xfree(error);

    if (tlv_next(tlv))
      goto bailout;
    if (tlv_parser_level(tlv) == 3)
      goto errors;

    if (tlv_expect_object(tlv, CLASS_UNIVERSAL, TAG_BIT_STRING, &failinfo, &failinfo_length))
      goto bailout;
    return GPG_ERR_SERVER_FAILED;
  }

  *r_signed_data = buffer + tlv_parser_offset(tlv);
  tmp_signed = *r_signed_data;
  len = length - tlv_parser_offset(tlv);
  err = tlv_parse_tag(r_signed_data, &len, &info);
  if (err)
    goto bailout;
  *r_signed_data_length = info.length + info.nhdr;
  *r_signed_data = xmalloc(*r_signed_data_length);
  memcpy(*r_signed_data, tmp_signed, *r_signed_data_length);
  tlv_parser_release(tlv);

  ksba_reader_new(&reader);
  ksba_reader_set_mem(reader, *r_signed_data, *r_signed_data_length);

  ksba_cms_set_reader_writer(*r_cms, reader, NULL);

  where = "parse_cert";
  err = gcry_md_open(&hd, 0, 0);
  if (err) {
    return err;
  }
  do
  {
    err = ksba_cms_parse(*r_cms, &stopreason);
    if (stopreason == KSBA_SR_NEED_HASH
        || stopreason == KSBA_SR_BEGIN_DATA)
      {
        /* We are now able to enable the hash algorithms */
        for (i=0; (algoid=ksba_cms_get_digest_algo_list (*r_cms, i)); i++)
          {
            algo = gcry_md_map_name (algoid);
            if (!algo)
              {
                log_error ("unknown hash algorithm '%s'\n",
                            algoid? algoid:"?");
              }
            else
              {
                gcry_md_enable (hd, algo);
              }
          }
          ksba_cms_set_hash_function (*r_cms, HASH_FNC, hd);
      }
    if (err)
      {
        log_error("ksba_cms_parse failed: %s\n", gpg_strerror(err));
        goto bailout;
      }
  }
  while (stopreason != KSBA_SR_READY);
  gcry_md_close(hd);
  if (err)
    goto bailout;

  ksba_cms_set_reader_writer(*r_cms, NULL, NULL);
  ksba_reader_release(reader);

  return 0;

 bailout:
  if (!err)
    err = gpg_error (GPG_ERR_GENERAL);
  log_error ("%s(%s): @%04zu lvl=%u %s: %s - %s\n",
             __func__, where,
             tlv_parser_offset (tlv),
             tlv_parser_level (tlv),
             tlv_parser_lastfunc (tlv),
             tlv_parser_lasterrstr (tlv),
             gpg_strerror (err));
  tlv_parser_release (tlv);
  return err;
}


/* Construct an TSP request, send it to the TSA at URL and parse
 * the response. */
static gpg_error_t
do_tsp_request (ctrl_t ctrl, const char *url, char *hashalgooid,
                const void *tbshash, unsigned int tbshashlen,
                ksba_cms_t *r_cms, unsigned char **r_signed_data,
                size_t *r_signed_data_length)
{
  gpg_error_t err;
  ksba_der_t dbld = NULL;

  unsigned char *response;
  size_t responselen;
  http_t http;
  int redirects_left = 2;
  char *free_this = NULL;
  unsigned char *tmpder;
  size_t tmpderlen;

  dbld = ksba_der_builder_new (0);
  if (!dbld)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ksba_der_add_tag (dbld, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_int (dbld, "\x01", 1, 0);
  ksba_der_add_tag (dbld, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_tag (  dbld, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_oid (    dbld, hashalgooid);
  ksba_der_add_end (  dbld);
  ksba_der_add_val (  dbld, 0, KSBA_TYPE_OCTET_STRING, tbshash, tbshashlen);
  ksba_der_add_end (dbld);
  /* reqPolicy would go here.  */
  {
    unsigned char nonce[32];
    gcry_create_nonce (nonce, sizeof(nonce));
    ksba_der_add_int (dbld, nonce, sizeof(nonce), 1);
  };
  /* Whether we're requesting the certificate */
  //int true_val = 1;
  //ksba_der_add_val(dbld, 0, KSBA_TYPE_BOOLEAN, &true_val, 1);
  /* certReq would go here.  */
  /* extensions would go here.  */
  ksba_der_add_end (dbld);

  err = ksba_der_builder_get (dbld, &tmpder, &tmpderlen);
  ksba_der_builder_reset(dbld); // TODO is this needed?
  if (err) {
    goto leave;
  }

 once_more:
  err = http_open (ctrl, &http, HTTP_REQ_POST, url, NULL, NULL,
                   ((opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY:0)
                    | (dirmngr_use_tor ()? HTTP_FLAG_FORCE_TOR:0)
                    | (opt.disable_ipv4? HTTP_FLAG_IGNORE_IPv4 : 0)
                    | (opt.disable_ipv6? HTTP_FLAG_IGNORE_IPv6 : 0)),
                   ctrl->http_proxy, NULL, NULL, NULL);
  if (err)
    {
      log_error (_("error connecting to '%s': %s\n"), url, gpg_strerror (err));
      xfree (free_this);
      return err;
    }

  es_fprintf (http_get_write_ptr (http),
	      "Content-Type: application/timestamp-query\r\n"
	      "Content-Length: %lu\r\n",
	      (unsigned long)tmpderlen );
  http_start_data (http);
  if (es_fwrite (tmpder, tmpderlen, 1, http_get_write_ptr (http)) != 1)
    {
      err = gpg_error_from_errno (errno);
      log_error ("error sending request to '%s': %s\n", url, strerror (errno));
      http_close (http, 0);
      xfree (tmpder);
      xfree (free_this);
      return err;
    }
  xfree (tmpder);
  tmpder = NULL;

  err = http_wait_response (http);
  if (err || http_get_status_code (http) != 200)
    {
      if (err)
        log_error (_("error reading HTTP response for '%s': %s\n"),
                   url, gpg_strerror (err));
      else
        {
          switch (http_get_status_code (http))
            {
            case 301:
            case 302:
              {
                const char *s = http_get_header (http, "Location", 0);

                log_info (_("URL '%s' redirected to '%s' (%u)\n"),
                          url, s?s:"[none]", http_get_status_code (http));
                if (s && *s && redirects_left-- )
                  {
                    xfree (free_this); url = NULL;
                    free_this = xtrystrdup (s);
                    if (!free_this)
                      err = gpg_error_from_errno (errno);
                    else
                      {
                        url = free_this;
                        http_close (http, 0);
                        goto once_more;
                      }
                  }
                else
                  err = gpg_error (GPG_ERR_NO_DATA);
                log_error (_("too many redirections\n"));
              }
              break;

            case 413:  /* Payload too large */
              err = gpg_error (GPG_ERR_TOO_LARGE);
              break;

            default:
              log_error (_("error accessing '%s': http status %u\n"),
                         url, http_get_status_code (http));
              err = gpg_error (GPG_ERR_NO_DATA);
              break;
            }
        }
      http_close (http, 0);
      xfree (free_this);
      return err;
    }

  err = read_response (http_get_read_ptr (http), &response, &responselen);
  http_close (http, 0);
  if (err)
    {
      log_error (_("error reading HTTP response for '%s': %s\n"),
                 url, gpg_strerror (err));
      goto leave;
    }

  err = tsa_parse_response (response, responselen, r_cms, r_signed_data,
                            r_signed_data_length);

  if (err)
    {
      log_error (_("error parsing TSA response for '%s': %s\n"),
                 url, gpg_strerror (err));
      goto leave;
    }

 leave:
  xfree (response);
  xfree (free_this);
  return err;
}

/* Send a timestamp request to the current TSA (from CTRL) and return
 * the answer.  HASHALGO shall be provided by the caller; we do no
 * consistency checking here. */
gpg_error_t
dirmngr_get_timestamp (ctrl_t ctrl, char *hashalgoid,
                        const void *tbshash, unsigned int tbshashlen, ksba_cms_t *r_cms)
{
  gpg_error_t err;
  const char *url;
  unsigned char *signed_data = NULL;
  size_t signed_data_length;
  gnupg_isotime_t signing_time;
  gnupg_isotime_t current_time;
  gnupg_isotime_t tmp_time;

  int exitcode;
  estream_t in;
  pid_t pid;

  const char *argv[] = {
    "--verify",
    NULL
  };

  ksba_cms_new(r_cms);

  if (opt.disable_http)
    {
      log_error (_("Timestamp request not possible due to disabled HTTP\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  else if (opt.tsa_responder && *opt.tsa_responder)
    url = opt.tsa_responder;
  else
    {
      log_info (_("no default URL for a TSA available\n"));
      err = gpg_error (GPG_ERR_CONFIGURATION);
      goto leave;
    }

  /* Ask the TSA. */
  err = do_tsp_request (ctrl, url, hashalgoid, tbshash, tbshashlen, r_cms,
                        &signed_data, &signed_data_length);
  if (err)
    goto leave;
  /* Allow for some clock skew. */
  gnupg_get_isotime (current_time);
  add_seconds_to_isotime (current_time, opt.ocsp_max_clock_skew);

  ksba_cms_get_signing_time (*r_cms, 0, signing_time);
  if (strcmp (signing_time, current_time) > 0 )
    {
      log_error (_("TSA responder returned a status in the future\n"));
      log_info ("used now: %s  signing_time: %s\n", current_time, signing_time);
      if (!err)
        err = gpg_error (GPG_ERR_TIME_CONFLICT);
      goto leave;
    }

  /* Check that THIS_UPDATE is not too far back in the past. */
  gnupg_copy_time (tmp_time, signing_time);
  add_seconds_to_isotime (tmp_time,
                          60 + opt.ocsp_max_clock_skew); //TODO configurable

  if (!*tmp_time || strcmp (tmp_time, current_time) < 0 )
    {
      log_error (_("TSA responder returned a non-current status\n"));
      log_info ("used now: %s  signing_time: %s\n",
                current_time, signing_time);
      if (!err)
        err = gpg_error (GPG_ERR_TIME_CONFLICT);
      goto leave;
    }

  err = gnupg_spawn_process (gnupg_module_name(GNUPG_MODULE_NAME_GPGSM), argv, NULL, 0, &in, NULL, NULL, &pid);
  if (err)
    goto leave;

  es_fwrite(signed_data, 1, signed_data_length, in);
  es_fclose(in);

  gnupg_wait_process(gnupg_module_name(GNUPG_MODULE_NAME_GPGSM), pid, 1, &exitcode);
  gnupg_release_process(pid);
  if (!exitcode) {
    log_error("Signature verification successful\n");
  } else {
    log_error("Signature verification not successful\n");
    err = GPG_ERR_BAD_SIGNATURE;
    goto leave;
  }

 leave:
  if (err)
    {
      ksba_cms_release(*r_cms);
      *r_cms = NULL;
      goto leave;
    }
  xfree(signed_data);
  return err;
}
