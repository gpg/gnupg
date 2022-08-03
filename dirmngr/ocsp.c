/* ocsp.c - OCSP management
 *      Copyright (C) 2004, 2007 g10 Code GmbH
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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
#include "ocsp.h"

/* The maximum size we allow as a response from an OCSP reponder. */
#define MAX_RESPONSE_SIZE 65536


static const char oidstr_ocsp[] = "1.3.6.1.5.5.7.48.1";


/* Telesec attribute used to implement a positive confirmation.

   CertHash ::= SEQUENCE {
      HashAlgorithm    AlgorithmIdentifier,
      certificateHash OCTET STRING }
 */
/* static const char oidstr_certHash[] = "1.3.36.8.3.13"; */




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


/* Construct an OCSP request, send it to the configured OCSP responder
   and parse the response. On success the OCSP context may be used to
   further process the response.  The signature value and the
   production date are returned at R_SIGVAL and R_PRODUCED_AT; they
   may be NULL or an empty string if not available.  A new hash
   context is returned at R_MD.  */
static gpg_error_t
do_ocsp_request (ctrl_t ctrl, ksba_ocsp_t ocsp,
                 const char *url, ksba_cert_t cert, ksba_cert_t issuer_cert,
                 ksba_sexp_t *r_sigval, ksba_isotime_t r_produced_at,
                 gcry_md_hd_t *r_md)
{
  gpg_error_t err;
  unsigned char *request, *response;
  size_t requestlen, responselen;
  http_t http;
  ksba_ocsp_response_status_t response_status;
  const char *t;
  int redirects_left = 2;
  char *free_this = NULL;

  (void)ctrl;

  *r_sigval = NULL;
  *r_produced_at = 0;
  *r_md = NULL;

  if (dirmngr_use_tor ())
    {
      /* For now we do not allow OCSP via Tor due to possible privacy
         concerns.  Needs further research.  */
      log_error (_("OCSP request not possible due to Tor mode\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  if (opt.disable_http)
    {
      log_error (_("OCSP request not possible due to disabled HTTP\n"));
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  err = ksba_ocsp_add_target (ocsp, cert, issuer_cert);
  if (err)
    {
      log_error (_("error setting OCSP target: %s\n"), gpg_strerror (err));
      return err;
    }

  {
    size_t n;
    unsigned char nonce[32];

    n = ksba_ocsp_set_nonce (ocsp, NULL, 0);
    if (n > sizeof nonce)
      n = sizeof nonce;
    gcry_create_nonce (nonce, n);
    ksba_ocsp_set_nonce (ocsp, nonce, n);
  }

  err = ksba_ocsp_build_request (ocsp, &request, &requestlen);
  if (err)
    {
      log_error (_("error building OCSP request: %s\n"), gpg_strerror (err));
      return err;
    }

 once_more:
  err = http_open (&http, HTTP_REQ_POST, url, NULL, NULL,
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
	      "Content-Type: application/ocsp-request\r\n"
	      "Content-Length: %lu\r\n",
	      (unsigned long)requestlen );
  http_start_data (http);
  if (es_fwrite (request, requestlen, 1, http_get_write_ptr (http)) != 1)
    {
      err = gpg_error_from_errno (errno);
      log_error ("error sending request to '%s': %s\n", url, strerror (errno));
      http_close (http, 0);
      xfree (request);
      xfree (free_this);
      return err;
    }
  xfree (request);
  request = NULL;

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
                const char *s = http_get_header (http, "Location");

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
      xfree (free_this);
      return err;
    }
  /* log_printhex (response, responselen, "ocsp response"); */

  err = ksba_ocsp_parse_response (ocsp, response, responselen,
                                  &response_status);
  if (err)
    {
      log_error (_("error parsing OCSP response for '%s': %s\n"),
                 url, gpg_strerror (err));
      xfree (response);
      xfree (free_this);
      return err;
    }

  switch (response_status)
    {
    case KSBA_OCSP_RSPSTATUS_SUCCESS:      t = "success"; break;
    case KSBA_OCSP_RSPSTATUS_MALFORMED:    t = "malformed"; break;
    case KSBA_OCSP_RSPSTATUS_INTERNAL:     t = "internal error"; break;
    case KSBA_OCSP_RSPSTATUS_TRYLATER:     t = "try later"; break;
    case KSBA_OCSP_RSPSTATUS_SIGREQUIRED:  t = "must sign request"; break;
    case KSBA_OCSP_RSPSTATUS_UNAUTHORIZED: t = "unauthorized"; break;
    case KSBA_OCSP_RSPSTATUS_REPLAYED:     t = "replay detected"; break;
    case KSBA_OCSP_RSPSTATUS_OTHER:        t = "other (unknown)"; break;
    case KSBA_OCSP_RSPSTATUS_NONE:         t = "no status"; break;
    default:                               t = "[unknown status]"; break;
    }
  if (response_status == KSBA_OCSP_RSPSTATUS_SUCCESS)
    {
      int hash_algo;

      if (opt.verbose)
        log_info (_("OCSP responder at '%s' status: %s\n"), url, t);

      /* Get the signature value now because we can call this function
       * only once.  */
      *r_sigval = ksba_ocsp_get_sig_val (ocsp, r_produced_at);

      hash_algo = hash_algo_from_sigval (*r_sigval);
      if (!hash_algo)
        {
          if (opt.verbose)
            log_info ("ocsp: using SHA-256 as fallback hash algo.\n");
          hash_algo = GCRY_MD_SHA256;
        }
      err = gcry_md_open (r_md, hash_algo, 0);
      if (err)
        {
          log_error (_("failed to establish a hashing context for OCSP: %s\n"),
                     gpg_strerror (err));
          goto leave;
        }
      if (DBG_HASHING)
        gcry_md_debug (*r_md, "ocsp");

      err = ksba_ocsp_hash_response (ocsp, response, responselen,
                                     HASH_FNC, *r_md);
      if (err)
        log_error (_("hashing the OCSP response for '%s' failed: %s\n"),
                   url, gpg_strerror (err));
    }
  else
    {
      log_error (_("OCSP responder at '%s' status: %s\n"), url, t);
      err = gpg_error (GPG_ERR_GENERAL);
    }

 leave:
  xfree (response);
  xfree (free_this);
  if (err)
    {
      xfree (*r_sigval);
      *r_sigval = NULL;
      *r_produced_at = 0;
      gcry_md_close (*r_md);
      *r_md = NULL;
    }
  return err;
}


/* Validate that CERT is indeed valid to sign an OCSP response. If
   SIGNER_FPR_LIST is not NULL we simply check that CERT matches one
   of the fingerprints in this list. */
static gpg_error_t
validate_responder_cert (ctrl_t ctrl, ksba_cert_t cert,
                         fingerprint_list_t signer_fpr_list)
{
  gpg_error_t err;
  char *fpr;

  if (signer_fpr_list)
    {
      fpr = get_fingerprint_hexstring (cert);
      for (; signer_fpr_list && strcmp (signer_fpr_list->hexfpr, fpr);
           signer_fpr_list = signer_fpr_list->next)
        ;
      if (signer_fpr_list)
        err = 0;
      else
        {
          log_error (_("not signed by a default OCSP signer's certificate"));
          err = gpg_error (GPG_ERR_BAD_CA_CERT);
        }
      xfree (fpr);
    }
  else
    {
      /* We avoid duplicating the entire certificate validation code
         from gpgsm here.  Because we have no way calling back to the
         client and letting it compute the validity, we use the ugly
         hack of telling the client that the response will only be
         valid if the certificate given in this status message is
         valid.

         Note, that in theory we could simply ask the client via an
         inquire to validate a certificate but this might involve
         calling DirMngr again recursivly - we can't do that as of now
         (neither DirMngr nor gpgsm have the ability for concurrent
         access to DirMngr.   */

      /* FIXME: We should cache this certificate locally, so that the next
         call to dirmngr won't need to look it up - if this works at
         all. */
      fpr = get_fingerprint_hexstring (cert);
      dirmngr_status (ctrl, "ONLY_VALID_IF_CERT_VALID", fpr, NULL);
      xfree (fpr);
      err = 0;
    }

  return err;
}


/* Helper for check_signature. */
static int
check_signature_core (ctrl_t ctrl, ksba_cert_t cert, gcry_sexp_t s_sig,
                      gcry_sexp_t s_hash, fingerprint_list_t signer_fpr_list)
{
  gpg_error_t err;
  ksba_sexp_t pubkey;
  gcry_sexp_t s_pkey = NULL;

  pubkey = ksba_cert_get_public_key (cert);
  if (!pubkey)
    err = gpg_error (GPG_ERR_INV_OBJ);
  else
    err = canon_sexp_to_gcry (pubkey, &s_pkey);
  xfree (pubkey);
  if (!err)
    err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (!err)
    err = validate_responder_cert (ctrl, cert, signer_fpr_list);
  if (!err)
    {
      gcry_sexp_release (s_pkey);
      return 0; /* Successfully verified the signature. */
    }

  /* We simply ignore all errors. */
  gcry_sexp_release (s_pkey);
  return err;
}


/* Check the signature of an OCSP repsonse.  OCSP is the context,
   S_SIG the signature value and MD the handle of the hash we used for
   the response.  This function automagically finds the correct public
   key.  If SIGNER_FPR_LIST is not NULL, the default OCSP reponder has been
   used and thus the certificate is one of those identified by
   the fingerprints. */
static gpg_error_t
check_signature (ctrl_t ctrl,
                 ksba_ocsp_t ocsp, gcry_sexp_t s_sig, gcry_md_hd_t md,
                 fingerprint_list_t signer_fpr_list)
{
  gpg_error_t err;
  int algo, cert_idx;
  gcry_sexp_t s_hash;
  ksba_cert_t cert;
  const char *s;

  /* Create a suitable S-expression with the hash value of our response. */
  gcry_md_final (md);
  algo = gcry_md_get_algo (md);
  s = gcry_md_algo_name (algo);
  if (algo && s && strlen (s) < 16)
    {
      char hashalgostr[16+1];
      int i;

      for (i=0; s[i]; i++)
        hashalgostr[i] = ascii_tolower (s[i]);
      hashalgostr[i] = 0;
      err = gcry_sexp_build (&s_hash, NULL, "(data(flags pkcs1)(hash %s %b))",
                             hashalgostr,
                             (int)gcry_md_get_algo_dlen (algo),
                             gcry_md_read (md, algo));
    }
  else
    err = gpg_error (GPG_ERR_DIGEST_ALGO);
  if (err)
    {
      log_error (_("creating S-expression failed: %s\n"), gcry_strerror (err));
      return err;
    }

  /* Get rid of old OCSP specific certificate references. */
  release_ctrl_ocsp_certs (ctrl);

  if (signer_fpr_list && !signer_fpr_list->next)
    {
      /* There is exactly one signer fingerprint given. Thus we use
         the default OCSP responder's certificate and instantly know
         the certificate to use.  */
      cert = get_cert_byhexfpr (signer_fpr_list->hexfpr);
      if (!cert)
        cert = get_cert_local (ctrl, signer_fpr_list->hexfpr);
      if (cert)
        {
          err = check_signature_core (ctrl, cert, s_sig, s_hash,
                                      signer_fpr_list);
          ksba_cert_release (cert);
          cert = NULL;
          if (!err)
            {
              gcry_sexp_release (s_hash);
              return 0; /* Successfully verified the signature. */
            }
        }
    }
  else
    {
      char *name;
      ksba_sexp_t keyid;

      /* Put all certificates included in the response into the cache
         and setup a list of those certificate which will later be
         preferred used when locating certificates.  */
      for (cert_idx=0; (cert = ksba_ocsp_get_cert (ocsp, cert_idx));
           cert_idx++)
        {
          cert_ref_t cref;

          /* dump_cert ("from ocsp response", cert); */
          cref = xtrymalloc (sizeof *cref);
          if (!cref)
            {
              err = gpg_error_from_syserror ();
              log_error (_("allocating list item failed: %s\n"),
                         gpg_strerror (err));
            }
          else if (!cache_cert_silent (cert, &cref->fpr))
            {
              cref->next = ctrl->ocsp_certs;
              ctrl->ocsp_certs = cref;
            }
          else
            xfree (cref);
        }

      /* Get the certificate by means of the responder ID. */
      err = ksba_ocsp_get_responder_id (ocsp, &name, &keyid);
      if (err)
        {
          log_error (_("error getting responder ID: %s\n"),
                     gcry_strerror (err));
          return err;
        }
      cert = find_cert_bysubject (ctrl, name, keyid);
      if (!cert)
        {
          log_error ("responder certificate ");
          if (name)
            log_printf ("'/%s' ", name);
          if (keyid)
            {
              log_printf ("{");
              dump_serial (keyid);
              log_printf ("} ");
            }
          log_printf ("not found\n");
        }

      if (cert)
        {
          err = check_signature_core (ctrl, cert, s_sig, s_hash,
                                      signer_fpr_list);
          ksba_cert_release (cert);
          if (!err)
            {
              ksba_free (name);
              ksba_free (keyid);
              gcry_sexp_release (s_hash);
              return 0; /* Successfully verified the signature. */
            }
          log_error ("responder certificate ");
          if (name)
            log_printf ("'/%s' ", name);
          if (keyid)
            {
              log_printf ("{");
              dump_serial (keyid);
              log_printf ("} ");
            }
          log_printf ("did not verify: %s\n", gpg_strerror (err));
        }
      ksba_free (name);
      ksba_free (keyid);
    }

  gcry_sexp_release (s_hash);
  log_error (_("no suitable certificate found to verify the OCSP response\n"));
  return gpg_error (GPG_ERR_NO_PUBKEY);
}


/* Check whether the certificate either given by fingerprint CERT_FPR
   or directly through the CERT object is valid by running an OCSP
   transaction.  With FORCE_DEFAULT_RESPONDER set only the configured
   default responder is used. */
gpg_error_t
ocsp_isvalid (ctrl_t ctrl, ksba_cert_t cert, const char *cert_fpr,
              int force_default_responder)
{
  gpg_error_t err;
  ksba_ocsp_t ocsp = NULL;
  ksba_cert_t issuer_cert = NULL;
  ksba_sexp_t sigval = NULL;
  gcry_sexp_t s_sig = NULL;
  ksba_isotime_t current_time;
  ksba_isotime_t this_update, next_update, revocation_time, produced_at;
  ksba_isotime_t tmp_time;
  ksba_status_t status;
  ksba_crl_reason_t reason;
  char *url_buffer = NULL;
  const char *url;
  gcry_md_hd_t md = NULL;
  int i, idx;
  char *oid;
  ksba_name_t name;
  fingerprint_list_t default_signer = NULL;

  /* Get the certificate.  */
  if (cert)
    {
      ksba_cert_ref (cert);

      err = find_issuing_cert (ctrl, cert, &issuer_cert);
      if (err)
        {
          log_error (_("issuer certificate not found: %s\n"),
                     gpg_strerror (err));
          goto leave;
        }
    }
  else
    {
      cert = get_cert_local (ctrl, cert_fpr);
      if (!cert)
        {
          log_error (_("caller did not return the target certificate\n"));
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
      issuer_cert = get_issuing_cert_local (ctrl, NULL);
      if (!issuer_cert)
        {
          log_error (_("caller did not return the issuing certificate\n"));
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
    }

  /* Create an OCSP instance.  */
  err = ksba_ocsp_new (&ocsp);
  if (err)
    {
      log_error (_("failed to allocate OCSP context: %s\n"),
                 gpg_strerror (err));
      goto leave;
    }

  /* Figure out the OCSP responder to use.
     1. Try to get the reponder from the certificate.
        We do only take http and https style URIs into account.
     2. If this fails use the default responder, if any.
   */
  url = NULL;
  for (idx=0; !url && !opt.ignore_ocsp_service_url && !force_default_responder
         && !(err=ksba_cert_get_authority_info_access (cert, idx,
                                                       &oid, &name)); idx++)
    {
      if ( !strcmp (oid, oidstr_ocsp) )
        {
          for (i=0; !url && ksba_name_enum (name, i); i++)
            {
              char *p = ksba_name_get_uri (name, i);
              if (p && (!ascii_strncasecmp (p, "http:", 5)
                        || !ascii_strncasecmp (p, "https:", 6)))
                url = url_buffer = p;
              else
                xfree (p);
            }
        }
      ksba_name_release (name);
      ksba_free (oid);
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    {
      log_error (_("can't get authorityInfoAccess: %s\n"), gpg_strerror (err));
      goto leave;
    }
  if (!url)
    {
      if (!opt.ocsp_responder || !*opt.ocsp_responder)
        {
          log_info (_("no default OCSP responder defined\n"));
          err = gpg_error (GPG_ERR_CONFIGURATION);
          goto leave;
        }
      if (!opt.ocsp_signer)
        {
          log_info (_("no default OCSP signer defined\n"));
          err = gpg_error (GPG_ERR_CONFIGURATION);
          goto leave;
        }
      url = opt.ocsp_responder;
      default_signer = opt.ocsp_signer;
      if (opt.verbose)
        log_info (_("using default OCSP responder '%s'\n"), url);
    }
  else
    {
      if (opt.verbose)
        log_info (_("using OCSP responder '%s'\n"), url);
    }

  /* Ask the OCSP responder. */
  err = do_ocsp_request (ctrl, ocsp, url, cert, issuer_cert,
                         &sigval, produced_at, &md);
  if (err)
    goto leave;

  /* It is sometimes useful to know the responder ID. */
  if (opt.verbose)
    {
      char *resp_name;
      ksba_sexp_t resp_keyid;

      err = ksba_ocsp_get_responder_id (ocsp, &resp_name, &resp_keyid);
      if (err)
        log_info (_("error getting responder ID: %s\n"), gpg_strerror (err));
      else
        {
          log_info ("responder id: ");
          if (resp_name)
            log_printf ("'/%s' ", resp_name);
          if (resp_keyid)
            {
              log_printf ("{");
              dump_serial (resp_keyid);
              log_printf ("} ");
            }
          log_printf ("\n");
        }
      ksba_free (resp_name);
      ksba_free (resp_keyid);
      err = 0;
    }

  /* We got a useful answer, check that the answer has a valid signature. */
  if (!sigval || !*produced_at || !md)
    {
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  if ( (err = canon_sexp_to_gcry (sigval, &s_sig)) )
    goto leave;
  xfree (sigval);
  sigval = NULL;
  err = check_signature (ctrl, ocsp, s_sig, md, default_signer);
  if (err)
    goto leave;

  /* We only support one certificate per request.  Check that the
     answer matches the right certificate. */
  err = ksba_ocsp_get_status (ocsp, cert,
                              &status, this_update, next_update,
                              revocation_time, &reason);
  if (err)
    {
      log_error (_("error getting OCSP status for target certificate: %s\n"),
                 gpg_strerror (err));
      goto leave;
    }

  /* In case the certificate has been revoked, we better invalidate
     our cached validation status. */
  if (status == KSBA_STATUS_REVOKED)
    {
      time_t validated_at = 0; /* That is: No cached validation available. */
      err = ksba_cert_set_user_data (cert, "validated_at",
                                     &validated_at, sizeof (validated_at));
      if (err)
        {
          log_error ("set_user_data(validated_at) failed: %s\n",
                     gpg_strerror (err));
          err = 0; /* The certificate is anyway revoked, and that is a
                      more important message than the failure of our
                      cache. */
        }
    }


  if (opt.verbose)
    {
      log_info (_("certificate status is: %s  (this=%s  next=%s)\n"),
                status == KSBA_STATUS_GOOD? _("good"):
                status == KSBA_STATUS_REVOKED? _("revoked"):
                status == KSBA_STATUS_UNKNOWN? _("unknown"):
                status == KSBA_STATUS_NONE? _("none"): "?",
                this_update, next_update);
      if (status == KSBA_STATUS_REVOKED)
        log_info (_("certificate has been revoked at: %s due to: %s\n"),
                  revocation_time,
                  reason == KSBA_CRLREASON_UNSPECIFIED?   "unspecified":
                  reason == KSBA_CRLREASON_KEY_COMPROMISE? "key compromise":
                  reason == KSBA_CRLREASON_CA_COMPROMISE?   "CA compromise":
                  reason == KSBA_CRLREASON_AFFILIATION_CHANGED?
                                                      "affiliation changed":
                  reason == KSBA_CRLREASON_SUPERSEDED?   "superseded":
                  reason == KSBA_CRLREASON_CESSATION_OF_OPERATION?
                                                  "cessation of operation":
                  reason == KSBA_CRLREASON_CERTIFICATE_HOLD?
                                                  "certificate on hold":
                  reason == KSBA_CRLREASON_REMOVE_FROM_CRL?
                                                  "removed from CRL":
                  reason == KSBA_CRLREASON_PRIVILEGE_WITHDRAWN?
                                                  "privilege withdrawn":
                  reason == KSBA_CRLREASON_AA_COMPROMISE? "AA compromise":
                  reason == KSBA_CRLREASON_OTHER?   "other":"?");

    }


  if (status == KSBA_STATUS_REVOKED)
    err = gpg_error (GPG_ERR_CERT_REVOKED);
  else if (status == KSBA_STATUS_UNKNOWN)
    err = gpg_error (GPG_ERR_NO_DATA);
  else if (status != KSBA_STATUS_GOOD)
    err = gpg_error (GPG_ERR_GENERAL);

  /* Allow for some clock skew. */
  gnupg_get_isotime (current_time);
  add_seconds_to_isotime (current_time, opt.ocsp_max_clock_skew);

  if (strcmp (this_update, current_time) > 0 )
    {
      log_error (_("OCSP responder returned a status in the future\n"));
      log_info ("used now: %s  this_update: %s\n", current_time, this_update);
      if (!err)
        err = gpg_error (GPG_ERR_TIME_CONFLICT);
    }

  /* Check that THIS_UPDATE is not too far back in the past. */
  gnupg_copy_time (tmp_time, this_update);
  add_seconds_to_isotime (tmp_time,
                          opt.ocsp_max_period+opt.ocsp_max_clock_skew);
  if (!*tmp_time || strcmp (tmp_time, current_time) < 0 )
    {
      log_error (_("OCSP responder returned a non-current status\n"));
      log_info ("used now: %s  this_update: %s\n",
                current_time, this_update);
      if (!err)
        err = gpg_error (GPG_ERR_TIME_CONFLICT);
    }

  /* Check that we are not beyound NEXT_UPDATE  (plus some extra time). */
  if (*next_update)
    {
      gnupg_copy_time (tmp_time, next_update);
      add_seconds_to_isotime (tmp_time,
                              opt.ocsp_current_period+opt.ocsp_max_clock_skew);
      if (!*tmp_time && strcmp (tmp_time, current_time) < 0 )
        {
          log_error (_("OCSP responder returned an too old status\n"));
          log_info ("used now: %s  next_update: %s\n",
                    current_time, next_update);
          if (!err)
            err = gpg_error (GPG_ERR_TIME_CONFLICT);
        }
    }


 leave:
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  xfree (sigval);
  ksba_cert_release (issuer_cert);
  ksba_cert_release (cert);
  ksba_ocsp_release (ocsp);
  xfree (url_buffer);
  return err;
}


/* Release the list of OCSP certificates hold in the CTRL object. */
void
release_ctrl_ocsp_certs (ctrl_t ctrl)
{
  while (ctrl->ocsp_certs)
    {
      cert_ref_t tmp = ctrl->ocsp_certs->next;
      xfree (ctrl->ocsp_certs);
      ctrl->ocsp_certs = tmp;
    }
}
