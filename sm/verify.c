/* verify.c - Verify a messages signature
 * Copyright (C) 2001, 2002, 2003, 2007,
 *               2010 Free Software Foundation, Inc.
 * Copyright (C) 2001-2019 Werner Koch
 * Copyright (C) 2015-2020 g10 Code GmbH
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/i18n.h"
#include "../common/compliance.h"

static char *
strtimestamp_r (ksba_isotime_t atime)
{
  char *buffer = xmalloc (15);

  if (!atime || !*atime)
    strcpy (buffer, "none");
  else
    sprintf (buffer, "%.4s-%.2s-%.2s", atime, atime+4, atime+6);
  return buffer;
}



/* Hash the data for a detached signature.  Returns 0 on success.  */
static gpg_error_t
hash_data (int fd, gcry_md_hd_t md)
{
  gpg_error_t err = 0;
  estream_t fp;
  char buffer[4096];
  int nread;

  fp = es_fdopen_nc (fd, "rb");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("fdopen(%d) failed: %s\n", fd, gpg_strerror (err));
      return err;
    }

  do
    {
      nread = es_fread (buffer, 1, DIM(buffer), fp);
      gcry_md_write (md, buffer, nread);
    }
  while (nread);
  if (es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("read error on fd %d: %s\n", fd, gpg_strerror (err));
    }
  es_fclose (fp);
  return err;
}




/* Perform a verify operation.  To verify detached signatures, DATA_FD
   must be different than -1.  With OUT_FP given and a non-detached
   signature, the signed material is written to that stream.  */
int
gpgsm_verify (ctrl_t ctrl, int in_fd, int data_fd, estream_t out_fp)
{
  int i, rc;
  gnupg_ksba_io_t b64reader = NULL;
  gnupg_ksba_io_t b64writer = NULL;
  ksba_reader_t reader;
  ksba_writer_t writer = NULL;
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  ksba_cert_t cert;
  KEYDB_HANDLE kh;
  gcry_md_hd_t data_md = NULL;
  int signer;
  const char *algoid;
  int algo;
  int is_detached, maybe_detached;
  estream_t in_fp = NULL;
  char *p;

  audit_set_type (ctrl->audit, AUDIT_TYPE_VERIFY);

  /* Although we detect detached signatures during the parsing phase,
   * we need to know it earlier and thus accept the caller's idea of
   * what to verify.  */
  maybe_detached = (data_fd != -1);

  kh = keydb_new ();
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }


  in_fp = es_fdopen_nc (in_fd, "rb");
  if (!in_fp)
    {
      rc = gpg_error_from_syserror ();
      log_error ("fdopen() failed: %s\n", strerror (errno));
      goto leave;
    }

  rc = gnupg_ksba_create_reader
    (&b64reader, ((ctrl->is_pem? GNUPG_KSBA_IO_PEM : 0)
                  | (ctrl->is_base64? GNUPG_KSBA_IO_BASE64 : 0)
                  | (ctrl->autodetect_encoding? GNUPG_KSBA_IO_AUTODETECT : 0)
                  | (maybe_detached? GNUPG_KSBA_IO_STRIP : 0)),
     in_fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gpg_strerror (rc));
      goto leave;
    }

  if (out_fp)
    {
      rc = gnupg_ksba_create_writer
        (&b64writer, ((ctrl->create_pem? GNUPG_KSBA_IO_PEM : 0)
                      | (ctrl->create_base64? GNUPG_KSBA_IO_BASE64 : 0)),
         ctrl->pem_name, out_fp, &writer);
      if (rc)
        {
          log_error ("can't create writer: %s\n", gpg_strerror (rc));
          goto leave;
        }
    }

  gnupg_ksba_set_progress_cb (b64writer, gpgsm_progress_cb, ctrl);
  if (ctrl->input_size_hint)
    gnupg_ksba_set_total (b64writer, ctrl->input_size_hint);

  rc = ksba_cms_new (&cms);
  if (rc)
    goto leave;

  rc = ksba_cms_set_reader_writer (cms, reader, writer);
  if (rc)
    {
      log_error ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (rc));
      goto leave;
    }

  rc = gcry_md_open (&data_md, 0, 0);
  if (rc)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
  if (DBG_HASHING)
    gcry_md_debug (data_md, "vrfy.data");

  audit_log (ctrl->audit, AUDIT_SETUP_READY);

  is_detached = 0;
  do
    {
      rc = ksba_cms_parse (cms, &stopreason);
      if (rc)
        {
          log_error ("ksba_cms_parse failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (stopreason == KSBA_SR_NEED_HASH)
        {
          is_detached = 1;
          audit_log (ctrl->audit, AUDIT_DETACHED_SIGNATURE);
          if (opt.verbose)
            log_info ("detached signature\n");
        }

      if (stopreason == KSBA_SR_NEED_HASH
          || stopreason == KSBA_SR_BEGIN_DATA)
        {
          audit_log (ctrl->audit, AUDIT_GOT_DATA);

          /* We are now able to enable the hash algorithms */
          for (i=0; (algoid=ksba_cms_get_digest_algo_list (cms, i)); i++)
            {
              algo = gcry_md_map_name (algoid);
              if (!algo)
                {
                  log_error ("unknown hash algorithm '%s'\n",
                             algoid? algoid:"?");
                  if (algoid
                      && (  !strcmp (algoid, "1.2.840.113549.1.1.2")
                          ||!strcmp (algoid, "1.2.840.113549.2.2")))
                    log_info (_("(this is the MD2 algorithm)\n"));
                  audit_log_s (ctrl->audit, AUDIT_BAD_DATA_HASH_ALGO, algoid);
                }
              else
                {
                  if (DBG_X509)
                    log_debug ("enabling hash algorithm %d (%s)\n",
                               algo, algoid? algoid:"");
                  gcry_md_enable (data_md, algo);
                  audit_log_i (ctrl->audit, AUDIT_DATA_HASH_ALGO, algo);
                }
            }
          if (opt.extra_digest_algo)
            {
              if (DBG_X509)
                log_debug ("enabling extra hash algorithm %d\n",
                           opt.extra_digest_algo);
              gcry_md_enable (data_md, opt.extra_digest_algo);
              audit_log_i (ctrl->audit, AUDIT_DATA_HASH_ALGO,
                           opt.extra_digest_algo);
            }
          if (is_detached)
            {
              if (data_fd == -1)
                {
                  log_info ("detached signature w/o data "
                            "- assuming certs-only\n");
                  audit_log (ctrl->audit, AUDIT_CERT_ONLY_SIG);
                }
              else
                audit_log_ok (ctrl->audit, AUDIT_DATA_HASHING,
                              hash_data (data_fd, data_md));
            }
          else
            {
              ksba_cms_set_hash_function (cms, HASH_FNC, data_md);
            }
        }
      else if (stopreason == KSBA_SR_END_DATA)
        { /* The data bas been hashed */
          audit_log_ok (ctrl->audit, AUDIT_DATA_HASHING, 0);
        }
    }
  while (stopreason != KSBA_SR_READY);

  if (b64writer)
    {
      rc = gnupg_ksba_finish_writer (b64writer);
      if (rc)
        {
          log_error ("write failed: %s\n", gpg_strerror (rc));
          audit_log_ok (ctrl->audit, AUDIT_WRITE_ERROR, rc);
          goto leave;
        }
    }

  if (data_fd != -1 && !is_detached)
    {
      log_error ("data given for a non-detached signature\n");
      rc = gpg_error (GPG_ERR_CONFLICT);
      audit_log (ctrl->audit, AUDIT_USAGE_ERROR);
      goto leave;
    }

  for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
    {
      /* Fixme: it might be better to check the validity of the
         certificate first before entering it into the DB.  This way
         we would avoid cluttering the DB with invalid
         certificates. */
      audit_log_cert (ctrl->audit, AUDIT_SAVE_CERT, cert,
                      keydb_store_cert (ctrl, cert, 0, NULL));
      ksba_cert_release (cert);
    }

  cert = NULL;
  for (signer=0; ; signer++)
    {
      char *issuer = NULL;
      gcry_sexp_t sigval = NULL;
      ksba_isotime_t sigtime, keyexptime;
      ksba_sexp_t serial;
      char *msgdigest = NULL;
      size_t msgdigestlen;
      char *ctattr;
      int sigval_hash_algo;
      int info_pkalgo;
      unsigned int nbits;
      int pkalgo;
      char *pkalgostr = NULL;
      char *pkcurve = NULL;
      char *pkfpr = NULL;
      unsigned int pkalgoflags, verifyflags;

      rc = ksba_cms_get_issuer_serial (cms, signer, &issuer, &serial);
      if (!signer && gpg_err_code (rc) == GPG_ERR_NO_DATA
          && data_fd == -1 && is_detached)
        {
          log_info ("certs-only message accepted\n");
          rc = 0;
          break;
        }
      if (rc)
        {
          if (signer && rc == -1)
            rc = 0;
          break;
        }

      gpgsm_status (ctrl, STATUS_NEWSIG, NULL);
      audit_log_i (ctrl->audit, AUDIT_NEW_SIG, signer);

      if (DBG_X509)
        {
          log_debug ("signer %d - issuer: '%s'\n",
                     signer, issuer? issuer:"[NONE]");
          log_debug ("signer %d - serial: ", signer);
          gpgsm_dump_serial (serial);
          log_printf ("\n");
        }
      if (ctrl->audit)
        {
          char *tmpstr = gpgsm_format_sn_issuer (serial, issuer);
          audit_log_s (ctrl->audit, AUDIT_SIG_NAME, tmpstr);
          xfree (tmpstr);
        }

      rc = ksba_cms_get_signing_time (cms, signer, sigtime);
      if (gpg_err_code (rc) == GPG_ERR_NO_DATA)
        *sigtime = 0;
      else if (rc)
        {
          log_error ("error getting signing time: %s\n", gpg_strerror (rc));
          *sigtime = 0; /* (we can't encode an error in the time string.) */
        }

      rc = ksba_cms_get_message_digest (cms, signer,
                                        &msgdigest, &msgdigestlen);
      if (!rc)
        {
          algoid = ksba_cms_get_digest_algo (cms, signer);
          algo = gcry_md_map_name (algoid);
          if (DBG_X509)
            log_debug ("signer %d - digest algo: %d\n", signer, algo);
          if (! gcry_md_is_enabled (data_md, algo))
            {
              log_error ("digest algo %d (%s) has not been enabled\n",
                         algo, algoid?algoid:"");
              audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "unsupported");
              goto next_signer;
            }
        }
      else if (gpg_err_code (rc) == GPG_ERR_NO_DATA)
        {
          assert (!msgdigest);
          rc = 0;
          algoid = NULL;
          algo = 0;
        }
      else /* real error */
        {
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "error");
          break;
        }

      rc = ksba_cms_get_sigattr_oids (cms, signer,
                                      "1.2.840.113549.1.9.3", &ctattr);
      if (!rc)
        {
          const char *s;

          if (DBG_X509)
            log_debug ("signer %d - content-type attribute: %s",
                       signer, ctattr);

          s = ksba_cms_get_content_oid (cms, 1);
          if (!s || strcmp (ctattr, s))
            {
              log_error ("content-type attribute does not match "
                         "actual content-type\n");
              ksba_free (ctattr);
              ctattr = NULL;
              audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "bad");
              goto next_signer;
            }
          ksba_free (ctattr);
          ctattr = NULL;
        }
      else if (rc != -1)
        {
          log_error ("error getting content-type attribute: %s\n",
                     gpg_strerror (rc));
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "bad");
          goto next_signer;
        }
      rc = 0;


      sigval = gpgsm_ksba_cms_get_sig_val (cms, signer);
      if (!sigval)
        {
          log_error ("no signature value available\n");
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "bad");
          goto next_signer;
        }

      sigval_hash_algo = gpgsm_get_hash_algo_from_sigval (sigval, &pkalgoflags);
      if (DBG_X509)
        {
          log_debug ("signer %d - signature available (sigval hash=%d pkaf=%u)",
                     signer, sigval_hash_algo, pkalgoflags);
        }
      if (!sigval_hash_algo)
        sigval_hash_algo = algo; /* Fallback used e.g. with old libksba. */

      /* Find the certificate of the signer */
      keydb_search_reset (kh);
      rc = keydb_search_issuer_sn (ctrl, kh, issuer, serial);
      if (rc)
        {
          if (rc == -1)
            {
              log_error ("certificate not found\n");
              rc = gpg_error (GPG_ERR_NO_PUBKEY);
            }
          else
            log_error ("failed to find the certificate: %s\n",
                       gpg_strerror(rc));
          {
            char numbuf[50];
            sprintf (numbuf, "%d", rc);

            gpgsm_status2 (ctrl, STATUS_ERROR, "verify.findkey",
                           numbuf, NULL);
          }
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "no-cert");
          goto next_signer;
        }

      rc = keydb_get_cert (kh, &cert);
      if (rc)
        {
          log_error ("failed to get cert: %s\n", gpg_strerror (rc));
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "error");
          goto next_signer;
        }

      pkfpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
      pkalgostr = gpgsm_pubkey_algo_string (cert, NULL);
      pkalgo = gpgsm_get_key_algo_info (cert, &nbits, &pkcurve);
      /* Remap the ECC algo to the algo we use.  Note that EdDSA has
       * already been mapped.  */
      if (pkalgo == GCRY_PK_ECC)
        pkalgo = GCRY_PK_ECDSA;

      log_info (_("Signature made "));
      if (*sigtime)
        {
          /* We take the freedom as noted in RFC3339 to use a space
           * instead of the "T" delimiter between date and time.  We
           * also append a separate UTC instead of a "Z" or "+00:00"
           * suffix because that makes it clear to everyone what kind
           * of time this is.  */
          dump_isotime (sigtime);
          log_printf (" UTC");
        }
      else
        log_printf (_("[date not given]"));
      log_info (_("               using %s key %s\n"), pkalgostr, pkfpr);
      if (opt.verbose)
        {
          log_info (_("algorithm:"));
          log_printf (" %s + %s",
                      pubkey_algo_to_string (pkalgo),
                      gcry_md_algo_name (sigval_hash_algo));
          if (algo != sigval_hash_algo)
            log_printf (" (%s)", gcry_md_algo_name (algo));
          log_printf ("\n");
        }

      audit_log_i (ctrl->audit, AUDIT_DATA_HASH_ALGO, algo);

      /* Check compliance.  */
      pkalgoflags |= PK_ALGO_FLAG_ECC18;
      if (! gnupg_pk_is_allowed (opt.compliance, PK_USE_VERIFICATION,
                                 pkalgo, pkalgoflags, NULL, nbits, pkcurve))
        {
          char  kidstr[10+1];

          snprintf (kidstr, sizeof kidstr, "0x%08lX",
                    gpgsm_get_short_fingerprint (cert, NULL));
          log_error (_("key %s may not be used for signing in %s mode\n"),
                     kidstr,
                     gnupg_compliance_option_string (opt.compliance));
          goto next_signer;
        }

      if (!gnupg_digest_is_allowed (opt.compliance, 0, sigval_hash_algo))
        {
          log_error (_("digest algorithm '%s' may not be used in %s mode\n"),
                     gcry_md_algo_name (sigval_hash_algo),
                     gnupg_compliance_option_string (opt.compliance));
          goto next_signer;
        }

      /* Print compliance warning for the key.  */
      if (!opt.quiet
          && !gnupg_pk_is_compliant (opt.compliance, pkalgo, pkalgoflags,
                                     NULL, nbits, pkcurve))
          {
            log_info (_("WARNING: This key is not suitable for signing"
                        " in %s mode\n"),
                      gnupg_compliance_option_string (opt.compliance));
          }

      /* Check compliance with CO_DE_VS.  */
      if (gnupg_pk_is_compliant (CO_DE_VS, pkalgo, pkalgoflags,
                                 NULL, nbits, pkcurve)
          && gnupg_gcrypt_is_compliant (CO_DE_VS)
          && gnupg_digest_is_compliant (CO_DE_VS, sigval_hash_algo))
        gpgsm_status (ctrl, STATUS_VERIFICATION_COMPLIANCE_MODE,
                      gnupg_status_compliance_flag (CO_DE_VS));
      else if (opt.require_compliance
               && opt.compliance == CO_DE_VS)
        {
          log_error (_("operation forced to fail due to"
                       " unfulfilled compliance rules\n"));
          gpgsm_errors_seen = 1;
        }

      /* Now we can check the signature.  */
      if (msgdigest)
        { /* Signed attributes are available. */
          gcry_md_hd_t md;
          unsigned char *s;

          /* Check that the message digest in the signed attributes
             matches the one we calculated on the data.  */
          s = gcry_md_read (data_md, algo);
          if ( !s || !msgdigestlen
               || gcry_md_get_algo_dlen (algo) != msgdigestlen
               || memcmp (s, msgdigest, msgdigestlen) )
            {
              char *fpr;

              log_error (_("invalid signature: message digest attribute "
                           "does not match computed one\n"));
              if (DBG_X509)
                {
                  if (msgdigest)
                    log_printhex (msgdigest, msgdigestlen, "message:  ");
                  if (s)
                    log_printhex (s, gcry_md_get_algo_dlen (algo),
                                  "computed: ");
                }
              fpr = gpgsm_fpr_and_name_for_status (cert);
              gpgsm_status (ctrl, STATUS_BADSIG, fpr);
              xfree (fpr);
              audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "bad");
              goto next_signer;
            }

          audit_log_i (ctrl->audit, AUDIT_ATTR_HASH_ALGO, sigval_hash_algo);
          rc = gcry_md_open (&md, sigval_hash_algo, 0);
          if (rc)
            {
              log_error ("md_open failed: %s\n", gpg_strerror (rc));
              audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "error");
              goto next_signer;
            }
          if (DBG_HASHING)
            gcry_md_debug (md, "vrfy.attr");

          ksba_cms_set_hash_function (cms, HASH_FNC, md);
          rc = ksba_cms_hash_signed_attrs (cms, signer);
          if (rc)
            {
              log_error ("hashing signed attrs failed: %s\n",
                         gpg_strerror (rc));
              gcry_md_close (md);
              audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "error");
              goto next_signer;
            }
          rc = gpgsm_check_cms_signature (cert, sigval, md, sigval_hash_algo,
                                          pkalgoflags, &info_pkalgo);
          gcry_md_close (md);
        }
      else
        {
          rc = gpgsm_check_cms_signature (cert, sigval, data_md,
                                          algo, pkalgoflags, &info_pkalgo);
        }

      if (rc)
        {
          char *fpr;

          log_error ("invalid signature: %s\n", gpg_strerror (rc));
          fpr = gpgsm_fpr_and_name_for_status (cert);
          gpgsm_status (ctrl, STATUS_BADSIG, fpr);
          xfree (fpr);
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "bad");
          goto next_signer;
        }
      rc = gpgsm_cert_use_verify_p (cert); /*(this displays an info message)*/
      if (rc)
        {
          gpgsm_status_with_err_code (ctrl, STATUS_ERROR, "verify.keyusage",
                                      gpg_err_code (rc));
          rc = 0;
        }

      if (DBG_X509)
        log_debug ("signature okay - checking certs\n");
      audit_log (ctrl->audit, AUDIT_VALIDATE_CHAIN);
      rc = gpgsm_validate_chain (ctrl, cert,
                                 *sigtime? sigtime : "19700101T000000",
                                 keyexptime, 0,
                                 NULL, 0, &verifyflags);
      {
        char *fpr, *buf, *tstr;

        fpr = gpgsm_fpr_and_name_for_status (cert);
        if (gpg_err_code (rc) == GPG_ERR_CERT_EXPIRED)
          {
            gpgsm_status (ctrl, STATUS_EXPKEYSIG, fpr);
            rc = 0;
          }
        else
          gpgsm_status (ctrl, STATUS_GOODSIG, fpr);

        xfree (fpr);

        fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
        tstr = strtimestamp_r (sigtime);
        buf = xasprintf ("%s %s %s %s 0 0 %d %d 00", fpr, tstr,
                         *sigtime? sigtime : "0",
                         *keyexptime? keyexptime : "0",
                         info_pkalgo, algo);
        xfree (tstr);
        xfree (fpr);
        gpgsm_status (ctrl, STATUS_VALIDSIG, buf);
        xfree (buf);
      }

      audit_log_ok (ctrl->audit, AUDIT_CHAIN_STATUS, rc);
      if (rc) /* of validate_chain */
        {
          log_error ("invalid certification chain: %s\n", gpg_strerror (rc));
          if (gpg_err_code (rc) == GPG_ERR_BAD_CERT_CHAIN
              || gpg_err_code (rc) == GPG_ERR_BAD_CERT
              || gpg_err_code (rc) == GPG_ERR_BAD_CA_CERT
              || gpg_err_code (rc) == GPG_ERR_CERT_REVOKED)
            gpgsm_status_with_err_code (ctrl, STATUS_TRUST_NEVER, NULL,
                                        gpg_err_code (rc));
          else
            gpgsm_status_with_err_code (ctrl, STATUS_TRUST_UNDEFINED, NULL,
                                        gpg_err_code (rc));
          audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "bad");
          goto next_signer;
        }

      audit_log_s (ctrl->audit, AUDIT_SIG_STATUS, "good");

      for (i=0; (p = ksba_cert_get_subject (cert, i)); i++)
        {
          log_info (!i? _("Good signature from")
                      : _("                aka"));
          log_printf (" \"");
          gpgsm_es_print_name (log_get_stream (), p);
          log_printf ("\"\n");
          ksba_free (p);
        }

      /* Print a note if this is a qualified signature.  */
      {
        size_t qualbuflen;
        char qualbuffer[1];

        rc = ksba_cert_get_user_data (cert, "is_qualified", &qualbuffer,
                                      sizeof (qualbuffer), &qualbuflen);
        if (!rc && qualbuflen)
          {
            if (*qualbuffer)
              {
                log_info (_("This is a qualified signature\n"));
                if (!opt.qualsig_approval)
                  log_info
                    (_("Note, that this software is not officially approved "
                       "to create or verify such signatures.\n"));
              }
          }
        else if (gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
          log_error ("get_user_data(is_qualified) failed: %s\n",
                     gpg_strerror (rc));
      }

      gpgsm_status (ctrl, STATUS_TRUST_FULLY,
                    (verifyflags & VALIDATE_FLAG_STEED)?
                    "0 steed":
                    (verifyflags & VALIDATE_FLAG_CHAIN_MODEL)?
                    "0 chain": "0 shell");

    next_signer:
      rc = 0;
      xfree (issuer);
      xfree (serial);
      gcry_sexp_release (sigval);
      xfree (msgdigest);
      xfree (pkalgostr);
      xfree (pkcurve);
      xfree (pkfpr);
      ksba_cert_release (cert);
      cert = NULL;
    }
  rc = 0;

 leave:
  ksba_cms_release (cms);
  gnupg_ksba_destroy_reader (b64reader);
  gnupg_ksba_destroy_writer (b64writer);
  keydb_release (kh);
  gcry_md_close (data_md);
  es_fclose (in_fp);

  if (rc)
    {
      char numbuf[50];
      sprintf (numbuf, "%d", rc );
      gpgsm_status2 (ctrl, STATUS_ERROR, "verify.leave",
                     numbuf, NULL);
    }

  return rc;
}
