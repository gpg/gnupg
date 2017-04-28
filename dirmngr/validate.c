/* validate.c - Validate a certificate chain.
 * Copyright (C) 2001, 2003, 2004, 2008 Free Software Foundation, Inc.
 * Copyright (C) 2004, 2006, 2008, 2017 g10 Code GmbH
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
#include <ctype.h>

#include "dirmngr.h"
#include "certcache.h"
#include "crlcache.h"
#include "validate.h"
#include "misc.h"


/* Mode parameters for cert_check_usage().  */
enum cert_usage_modes
  {
    CERT_USAGE_MODE_SIGN,  /* Usable for encryption.            */
    CERT_USAGE_MODE_ENCR,  /* Usable for signing.               */
    CERT_USAGE_MODE_VRFY,  /* Usable for verification.          */
    CERT_USAGE_MODE_DECR,  /* Usable for decryption.            */
    CERT_USAGE_MODE_CERT,  /* Usable for cert signing.          */
    CERT_USAGE_MODE_OCSP,  /* Usable for OCSP respone signing.  */
    CERT_USAGE_MODE_CRL    /* Usable for CRL signing.           */
  };


/* While running the validation function we need to keep track of the
   certificates and the validation outcome of each.  We use this type
   for it.  */
struct chain_item_s
{
  struct chain_item_s *next;
  ksba_cert_t cert;      /* The certificate.  */
  unsigned char fpr[20]; /* Fingerprint of the certificate.  */
  int is_self_signed;    /* This certificate is self-signed.  */
  int is_valid;          /* The certifiate is valid except for revocations.  */
};
typedef struct chain_item_s *chain_item_t;


/* A couple of constants with Object Identifiers.  */
static const char oid_kp_serverAuth[]     = "1.3.6.1.5.5.7.3.1";
static const char oid_kp_clientAuth[]     = "1.3.6.1.5.5.7.3.2";
static const char oid_kp_codeSigning[]    = "1.3.6.1.5.5.7.3.3";
static const char oid_kp_emailProtection[]= "1.3.6.1.5.5.7.3.4";
static const char oid_kp_timeStamping[]   = "1.3.6.1.5.5.7.3.8";
static const char oid_kp_ocspSigning[]    = "1.3.6.1.5.5.7.3.9";


/* Prototypes.  */
static gpg_error_t check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert);


/* Make sure that the values defined in the headers are correct.  We
 * can't use the preprocessor due to the use of enums.  */
static void
check_header_constants (void)
{
  log_assert (CERTTRUST_CLASS_SYSTEM   == VALIDATE_FLAG_TRUST_SYSTEM);
  log_assert (CERTTRUST_CLASS_CONFIG   == VALIDATE_FLAG_TRUST_CONFIG);
  log_assert (CERTTRUST_CLASS_HKP      == VALIDATE_FLAG_TRUST_HKP);
  log_assert (CERTTRUST_CLASS_HKPSPOOL == VALIDATE_FLAG_TRUST_HKPSPOOL);

#undef  X
#define X (VALIDATE_FLAG_TRUST_SYSTEM | VALIDATE_FLAG_TRUST_CONFIG  \
           | VALIDATE_FLAG_TRUST_HKP | VALIDATE_FLAG_TRUST_HKPSPOOL)

#if ( X & VALIDATE_FLAG_MASK_TRUST ) !=  X
# error VALIDATE_FLAG_MASK_TRUST is bad
#endif
#if ( ~X & VALIDATE_FLAG_MASK_TRUST )
# error VALIDATE_FLAG_MASK_TRUST is bad
#endif

#undef X
}


/* Check whether CERT contains critical extensions we don't know
   about.  */
static gpg_error_t
unknown_criticals (ksba_cert_t cert)
{
  static const char *known[] = {
    "2.5.29.15", /* keyUsage */
    "2.5.29.19", /* basic Constraints */
    "2.5.29.32", /* certificatePolicies */
    "2.5.29.37", /* extendedKeyUsage */
    NULL
  };
  int i, idx, crit;
  const char *oid;
  int unsupported;
  strlist_t sl;
  gpg_error_t err, rc;

  rc = 0;
  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &crit, NULL, NULL));idx++)
    {
      if (!crit)
        continue;
      for (i=0; known[i] && strcmp (known[i],oid); i++)
        ;
      unsupported = !known[i];

      /* If this critical extension is not supported, check the list
         of to be ignored extensions to see whether we claim that it
         is supported.  */
      if (unsupported && opt.ignored_cert_extensions)
        {
          for (sl=opt.ignored_cert_extensions;
               sl && strcmp (sl->d, oid); sl = sl->next)
            ;
          if (sl)
            unsupported = 0;
        }

      if (unsupported)
        {
          log_error (_("critical certificate extension %s is not supported"),
                     oid);
          rc = gpg_error (GPG_ERR_UNSUPPORTED_CERT);
        }
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    rc = err; /* Such an error takes precedence.  */

  return rc;
}


/* Basic check for supported policies.  */
static gpg_error_t
check_cert_policy (ksba_cert_t cert)
{
  static const char *allowed[] = {
    "2.289.9.9",
    NULL
  };
  gpg_error_t err;
  int idx;
  char *p, *haystack;
  char *policies;
  int any_critical;

  err = ksba_cert_get_cert_policies (cert, &policies);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return 0; /* No policy given. */
  if (err)
    return err;

  /* STRING is a line delimited list of certifiate policies as stored
     in the certificate.  The line itself is colon delimited where the
     first field is the OID of the policy and the second field either
     N or C for normal or critical extension */
  if (opt.verbose > 1)
    log_info ("certificate's policy list: %s\n", policies);

  /* The check is very minimal but won't give false positives */
  any_critical = !!strstr (policies, ":C");

  /* See whether we find ALLOWED (which is an OID) in POLICIES */
  for (idx=0; allowed[idx]; idx++)
    {
      for (haystack=policies; (p=strstr (haystack, allowed[idx]));
           haystack = p+1)
        {
          if ( !(p == policies || p[-1] == '\n') )
            continue; /* Does not match the begin of a line. */
          if (p[strlen (allowed[idx])] != ':')
            continue; /* The length does not match. */
          /* Yep - it does match: Return okay. */
          ksba_free (policies);
          return 0;
        }
    }

  if (!any_critical)
    {
      log_info (_("Note: non-critical certificate policy not allowed"));
      err = 0;
    }
  else
    {
      log_info (_("certificate policy not allowed"));
      err = gpg_error (GPG_ERR_NO_POLICY_MATCH);
    }

  ksba_free (policies);
  return err;
}


static gpg_error_t
allowed_ca (ksba_cert_t cert, int *chainlen)
{
  gpg_error_t err;
  int flag;

  err = ksba_cert_is_ca (cert, &flag, chainlen);
  if (err)
    return err;
  if (!flag)
    {
      if (!is_trusted_cert (cert, CERTTRUST_CLASS_CONFIG))
        {
          /* The German SigG Root CA's certificate does not flag
             itself as a CA; thus we relax this requirement if we
             trust a root CA.  I think this is reasonable.  Note, that
             gpgsm implements a far stricter scheme here. */
          if (chainlen)
            *chainlen = 3; /* That is what the SigG implements. */
          if (opt.verbose)
            log_info (_("accepting root CA not marked as a CA"));
        }
      else
        {
          log_error (_("issuer certificate is not marked as a CA"));
          return gpg_error (GPG_ERR_BAD_CA_CERT);
        }
    }
  return 0;
}

/* Helper for validate_cert_chain.  */
static gpg_error_t
check_revocations (ctrl_t ctrl, chain_item_t chain)
{
  gpg_error_t err = 0;
  int any_revoked = 0;
  int any_no_crl = 0;
  int any_crl_too_old = 0;
  chain_item_t ci;

  log_assert (ctrl->check_revocations_nest_level >= 0);
  log_assert (chain);

  if (ctrl->check_revocations_nest_level > 10)
    {
      log_error (_("CRL checking too deeply nested\n"));
      return gpg_error(GPG_ERR_BAD_CERT_CHAIN);
    }
  ctrl->check_revocations_nest_level++;


  for (ci=chain; ci; ci = ci->next)
    {
      assert (ci->cert);
      if (ci == chain)
        {
          /* It does not make sense to check the root certificate for
             revocations.  In almost all cases this will lead to a
             catch-22 as the root certificate is the final trust
             anchor for the certificates and the CRLs.  We expect the
             user to remove root certificates from the list of trusted
             certificates in case they have been revoked. */
          if (opt.verbose)
            cert_log_name (_("not checking CRL for"), ci->cert);
          continue;
        }

      if (opt.verbose)
        cert_log_name (_("checking CRL for"), ci->cert);
      err = crl_cache_cert_isvalid (ctrl, ci->cert, 0);
      if (gpg_err_code (err) == GPG_ERR_NO_CRL_KNOWN)
        {
          err = crl_cache_reload_crl (ctrl, ci->cert);
          if (!err)
            err = crl_cache_cert_isvalid (ctrl, ci->cert, 0);
        }
      switch (gpg_err_code (err))
        {
        case 0: err = 0; break;
        case GPG_ERR_CERT_REVOKED: any_revoked = 1; err = 0; break;
        case GPG_ERR_NO_CRL_KNOWN: any_no_crl = 1; err = 0; break;
        case GPG_ERR_CRL_TOO_OLD: any_crl_too_old = 1; err = 0; break;
        default: break;
        }
    }
  ctrl->check_revocations_nest_level--;


  if (err)
    ;
  else if (any_revoked)
    err = gpg_error (GPG_ERR_CERT_REVOKED);
  else if (any_no_crl)
    err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
  else if (any_crl_too_old)
    err = gpg_error (GPG_ERR_CRL_TOO_OLD);
  else
    err = 0;
  return err;
}


/* Check whether CERT is a root certificate.  ISSUERDN and SUBJECTDN
   are the DNs already extracted by the caller from CERT.  Returns
   True if this is the case. */
static int
is_root_cert (ksba_cert_t cert, const char *issuerdn, const char *subjectdn)
{
  gpg_error_t err;
  int result = 0;
  ksba_sexp_t serialno;
  ksba_sexp_t ak_keyid;
  ksba_name_t ak_name;
  ksba_sexp_t ak_sn;
  const char *ak_name_str;
  ksba_sexp_t subj_keyid = NULL;

  if (!issuerdn || !subjectdn)
    return 0;  /* No.  */

  if (strcmp (issuerdn, subjectdn))
    return 0;  /* No.  */

  err = ksba_cert_get_auth_key_id (cert, &ak_keyid, &ak_name, &ak_sn);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_NO_DATA)
        return 1; /* Yes. Without a authorityKeyIdentifier this needs
                     to be the Root certificate (our trust anchor).  */
      log_error ("error getting authorityKeyIdentifier: %s\n",
                 gpg_strerror (err));
      return 0; /* Well, it is broken anyway.  Return No. */
    }

  serialno = ksba_cert_get_serial (cert);
  if (!serialno)
    {
      log_error ("error getting serialno: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Check whether the auth name's matches the issuer name+sn.  If
     that is the case this is a root certificate.  */
  ak_name_str = ksba_name_enum (ak_name, 0);
  if (ak_name_str
      && !strcmp (ak_name_str, issuerdn)
      && !cmp_simple_canon_sexp (ak_sn, serialno))
    {
      result = 1;  /* Right, CERT is self-signed.  */
      goto leave;
    }

  /* Similar for the ak_keyid. */
  if (ak_keyid && !ksba_cert_get_subj_key_id (cert, NULL, &subj_keyid)
      && !cmp_simple_canon_sexp (ak_keyid, subj_keyid))
    {
      result = 1;  /* Right, CERT is self-signed.  */
      goto leave;
    }


 leave:
  ksba_free (subj_keyid);
  ksba_free (ak_keyid);
  ksba_name_release (ak_name);
  ksba_free (ak_sn);
  ksba_free (serialno);
  return result;
}


/* Validate the certificate CHAIN up to the trust anchor. Optionally
   return the closest expiration time in R_EXPTIME (this is useful for
   caching issues).  MODE is one of the VALIDATE_MODE_* constants.

   Note that VALIDATE_MODE_OCSP is not used due to the removal of the
   system service in 2.1.15.  Instead only the callback to gpgsm to
   validate a certificate is used.

   If R_TRUST_ANCHOR is not NULL and the validation would fail only
   because the root certificate is not trusted, the hexified
   fingerprint of that root certificate is stored at R_TRUST_ANCHOR
   and success is returned.  The caller needs to free the value at
   R_TRUST_ANCHOR; in all other cases NULL is stored there.  */
gpg_error_t
validate_cert_chain (ctrl_t ctrl, ksba_cert_t cert, ksba_isotime_t r_exptime,
                     unsigned int flags, char **r_trust_anchor)
{
  gpg_error_t err = 0;
  int depth, maxdepth;
  char *issuer = NULL;
  char *subject = NULL;
  ksba_cert_t subject_cert = NULL;
  ksba_cert_t issuer_cert = NULL;
  ksba_isotime_t current_time;
  ksba_isotime_t exptime;
  int any_expired = 0;
  int any_no_policy_match = 0;
  chain_item_t chain;

  check_header_constants ();

  if (r_exptime)
    *r_exptime = 0;
  *exptime = 0;

  if (r_trust_anchor)
    *r_trust_anchor = NULL;

  if (DBG_X509)
    dump_cert ("subject", cert);

  /* May the target certificate be used for this purpose?  */
  if ((flags & VALIDATE_FLAG_OCSP) && (err = check_cert_use_ocsp (cert)))
    return err;
  if ((flags & VALIDATE_FLAG_CRL) && (err = check_cert_use_crl (cert)))
    return err;

  /* If we already validated the certificate not too long ago, we can
     avoid the excessive computations and lookups unless the caller
     asked for the expiration time.  */
  if (!r_exptime)
    {
      size_t buflen;
      time_t validated_at;

      err = ksba_cert_get_user_data (cert, "validated_at",
                                     &validated_at, sizeof (validated_at),
                                     &buflen);
      if (err || buflen != sizeof (validated_at) || !validated_at)
        err = 0; /* Not available or other error. */
      else
        {
          /* If the validation is not older than 30 minutes we are ready. */
          if (validated_at < gnupg_get_time () + (30*60))
            {
              if (opt.verbose)
                log_info ("certificate is good (cached)\n");
              /* Note, that we can't jump to leave here as this would
                 falsely updated the validation timestamp.  */
              return 0;
            }
        }
    }

  /* Get the current time. */
  gnupg_get_isotime (current_time);

  /* We walk up the chain until we find a trust anchor. */
  subject_cert = cert;
  maxdepth = 10;  /* Sensible limit on the length of the chain.  */
  chain = NULL;
  depth = 0;
  for (;;)
    {
      /* Get the subject and issuer name from the current
         certificate.  */
      ksba_free (issuer);
      ksba_free (subject);
      issuer = ksba_cert_get_issuer (subject_cert, 0);
      subject = ksba_cert_get_subject (subject_cert, 0);

      if (!issuer)
        {
          log_error (_("no issuer found in certificate\n"));
          err = gpg_error (GPG_ERR_BAD_CERT);
          goto leave;
        }

      /* Handle the notBefore and notAfter timestamps.  */
      {
        ksba_isotime_t not_before, not_after;

        err = ksba_cert_get_validity (subject_cert, 0, not_before);
        if (!err)
          err = ksba_cert_get_validity (subject_cert, 1, not_after);
        if (err)
          {
            log_error (_("certificate with invalid validity: %s"),
                       gpg_strerror (err));
            err = gpg_error (GPG_ERR_BAD_CERT);
            goto leave;
          }

        /* Keep track of the nearest expiration time in EXPTIME.  */
        if (*not_after)
          {
            if (!*exptime)
              gnupg_copy_time (exptime, not_after);
            else if (strcmp (not_after, exptime) < 0 )
              gnupg_copy_time (exptime, not_after);
          }

        /* Check whether the certificate is already valid.  */
        if (*not_before && strcmp (current_time, not_before) < 0 )
          {
            log_error (_("certificate not yet valid"));
            log_info ("(valid from ");
            dump_isotime (not_before);
            log_printf (")\n");
            err = gpg_error (GPG_ERR_CERT_TOO_YOUNG);
            goto leave;
          }

        /* Now check whether the certificate has expired.  */
        if (*not_after && strcmp (current_time, not_after) > 0 )
          {
            log_error (_("certificate has expired"));
            log_info ("(expired at ");
            dump_isotime (not_after);
            log_printf (")\n");
            any_expired = 1;
          }
      }

      /* Do we have any critical extensions in the certificate we
         can't handle? */
      err = unknown_criticals (subject_cert);
      if (err)
        goto leave; /* yes. */

      /* Check that given policies are allowed.  */
      err = check_cert_policy (subject_cert);
      if (gpg_err_code (err) == GPG_ERR_NO_POLICY_MATCH)
        {
          any_no_policy_match = 1;
          err = 0;
        }
      else if (err)
        goto leave;

      /* Is this a self-signed certificate? */
      if (is_root_cert (subject_cert, issuer, subject))
        {
          /* Yes, this is our trust anchor.  */
          if (check_cert_sig (subject_cert, subject_cert) )
            {
              log_error (_("selfsigned certificate has a BAD signature"));
              err = gpg_error (depth? GPG_ERR_BAD_CERT_CHAIN
                                    : GPG_ERR_BAD_CERT);
              goto leave;
            }

          /* Is this certificate allowed to act as a CA.  */
          err = allowed_ca (subject_cert, NULL);
          if (err)
            goto leave;  /* No. */

          err = is_trusted_cert (subject_cert,
                                 (flags & VALIDATE_FLAG_MASK_TRUST));
          if (!err)
            ; /* Yes we trust this cert.  */
          else if (gpg_err_code (err) == GPG_ERR_NOT_TRUSTED)
            {
              char *fpr;

              log_error (_("root certificate is not marked trusted"));
              fpr = get_fingerprint_hexstring (subject_cert);
              log_info (_("fingerprint=%s\n"), fpr? fpr : "?");
              dump_cert ("issuer", subject_cert);
              if (r_trust_anchor)
                {
                  /* Caller wants to do another trustiness check.  */
                  *r_trust_anchor = fpr;
                  err = 0;
                }
              else
                xfree (fpr);
            }
          else
            {
              log_error (_("checking trustworthiness of "
                           "root certificate failed: %s\n"),
                         gpg_strerror (err));
            }
          if (err)
            goto leave;

          /* Prepend the certificate to our list.  */
          {
            chain_item_t ci;

            ci = xtrycalloc (1, sizeof *ci);
            if (!ci)
              {
                err = gpg_error_from_errno (errno);
                goto leave;
              }
            ksba_cert_ref (subject_cert);
            ci->cert = subject_cert;
            cert_compute_fpr (subject_cert, ci->fpr);
            ci->next = chain;
            chain = ci;
          }

          if (opt.verbose)
            {
              if (r_trust_anchor && *r_trust_anchor)
                log_info ("root certificate is good but not trusted\n");
              else
                log_info ("root certificate is good and trusted\n");
            }

          break;  /* Okay: a self-signed certificate is an end-point. */
        }

      /* To avoid loops, we use an arbitrary limit on the length of
         the chain. */
      depth++;
      if (depth > maxdepth)
        {
          log_error (_("certificate chain too long\n"));
          err = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
          goto leave;
        }

      /* Find the next cert up the tree. */
      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      err = find_issuing_cert (ctrl, subject_cert, &issuer_cert);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            {
              log_error (_("issuer certificate not found"));
              log_info ("issuer certificate: #/");
              dump_string (issuer);
              log_printf ("\n");
            }
          else
            log_error (_("issuer certificate not found: %s\n"),
                         gpg_strerror (err));
          /* Use a better understandable error code.  */
          err = gpg_error (GPG_ERR_MISSING_ISSUER_CERT);
          goto leave;
        }

/*     try_another_cert: */
      if (DBG_X509)
        {
          log_debug ("got issuer's certificate:\n");
          dump_cert ("issuer", issuer_cert);
        }

      /* Now check the signature of the certificate.  FIXME: we should
       * delay this until later so that faked certificates can't be
       * turned into a DoS easily.  */
      err = check_cert_sig (issuer_cert, subject_cert);
      if (err)
        {
          log_error (_("certificate has a BAD signature"));
#if 0
          if (gpg_err_code (err) == GPG_ERR_BAD_SIGNATURE)
            {
              /* We now try to find other issuer certificates which
                 might have been used.  This is required because some
                 CAs are reusing the issuer and subject DN for new
                 root certificates without using a  authorityKeyIdentifier. */
              rc = find_up (kh, subject_cert, issuer, 1);
              if (!rc)
                {
                  ksba_cert_t tmp_cert;

                  rc = keydb_get_cert (kh, &tmp_cert);
                  if (rc || !compare_certs (issuer_cert, tmp_cert))
                    {
                      /* The find next did not work or returned an
                         identical certificate.  We better stop here
                         to avoid infinite checks. */
                      rc = gpg_error (GPG_ERR_BAD_SIGNATURE);
                      ksba_cert_release (tmp_cert);
                    }
                  else
                    {
                      do_list (0, lm, fp, _("found another possible matching "
                                            "CA certificate - trying again"));
                      ksba_cert_release (issuer_cert);
                      issuer_cert = tmp_cert;
                      goto try_another_cert;
                    }
                }
            }
#endif
          /* Return a more descriptive error code than the one
           * returned from the signature checking.  */
          err = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
          goto leave;
        }

      /* Check that the length of the chain is not longer than allowed
       * by the CA.  */
      {
        int chainlen;

        err = allowed_ca (issuer_cert, &chainlen);
        if (err)
          goto leave;
        if (chainlen >= 0 && (depth - 1) > chainlen)
          {
            log_error (_("certificate chain longer than allowed by CA (%d)"),
                       chainlen);
            err = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
            goto leave;
          }
      }

      /* May that certificate be used for certification? */
      err = check_cert_use_cert (issuer_cert);
      if (err)
        goto leave;  /* No.  */

      /* Prepend the certificate to our list.  */
      {
        chain_item_t ci;

        ci = xtrycalloc (1, sizeof *ci);
        if (!ci)
          {
            err = gpg_error_from_errno (errno);
            goto leave;
          }
        ksba_cert_ref (subject_cert);
        ci->cert = subject_cert;
        cert_compute_fpr (subject_cert, ci->fpr);
        ci->next = chain;
        chain = ci;
      }

      if (opt.verbose)
        log_info (_("certificate is good\n"));

      /* Now to the next level up.  */
      subject_cert = issuer_cert;
      issuer_cert = NULL;
    }

  /* Even if we have no error here we need to check whether we
   * encountered an error somewhere during the checks.  Set the error
   * code to the most critical one.  */
  if (!err)
    {
      if (any_expired)
        err = gpg_error (GPG_ERR_CERT_EXPIRED);
      else if (any_no_policy_match)
        err = gpg_error (GPG_ERR_NO_POLICY_MATCH);
    }

  if (!err && opt.verbose)
    {
      chain_item_t citem;

      log_info (_("certificate chain is good\n"));
      for (citem = chain; citem; citem = citem->next)
        cert_log_name ("  certificate", citem->cert);
    }

  /* Now check for revocations unless CRL checks are disabled or we
   * are non-recursive CRL mode.  */
  if (!err
      && !(flags & VALIDATE_FLAG_NOCRLCHECK)
      && !((flags & VALIDATE_FLAG_CRL)
           && !(flags & VALIDATE_FLAG_RECURSIVE)))
    { /* Now that everything is fine, walk the chain and check each
       * certificate for revocations.
       *
       * 1. item in the chain  - The root certificate.
       * 2. item               - the CA below the root
       * last item             - the target certificate.
       *
       * Now for each certificate in the chain check whether it has
       * been included in a CRL and thus be revoked.  We don't do OCSP
       * here because this does not seem to make much sense.  This
       * might become a recursive process and we should better cache
       * our validity results to avoid double work.  Far worse a
       * catch-22 may happen for an improper setup hierarchy and we
       * need a way to break up such a deadlock.  */
      err = check_revocations (ctrl, chain);
    }

  if (!err && opt.verbose)
    {
      if (r_trust_anchor && *r_trust_anchor)
        log_info ("target certificate may be valid\n");
      else
        log_info ("target certificate is valid\n");
    }
  else if (err && opt.verbose)
    log_info ("target certificate is NOT valid\n");


 leave:
  if (!err && !(r_trust_anchor && *r_trust_anchor))
    {
      /* With no error we can update the validation cache.  We do this
       * for all certificates in the chain.  Note that we can't use
       * the cache if the caller requested to check the trustiness of
       * the root certificate himself.  Adding such a feature would
       * require us to also store the fingerprint of root
       * certificate.  */
      chain_item_t citem;
      time_t validated_at = gnupg_get_time ();

      for (citem = chain; citem; citem = citem->next)
        {
          err = ksba_cert_set_user_data (citem->cert, "validated_at",
                                         &validated_at, sizeof (validated_at));
          if (err)
            {
              log_error ("set_user_data(validated_at) failed: %s\n",
                         gpg_strerror (err));
              err = 0;
            }
        }
    }

  if (r_exptime)
    gnupg_copy_time (r_exptime, exptime);
  ksba_free (issuer);
  ksba_free (subject);
  ksba_cert_release (issuer_cert);
  if (subject_cert != cert)
    ksba_cert_release (subject_cert);
  while (chain)
    {
      chain_item_t ci_next = chain->next;
      if (chain->cert)
        ksba_cert_release (chain->cert);
      xfree (chain);
      chain = ci_next;
    }
  if (err && r_trust_anchor && *r_trust_anchor)
    {
      xfree (*r_trust_anchor);
      *r_trust_anchor = NULL;
    }
  return err;
}



/* Return the public key algorithm id from the S-expression PKEY.
   FIXME: libgcrypt should provide such a function.  Note that this
   implementation uses the names as used by libksba.  */
static int
pk_algo_from_sexp (gcry_sexp_t pkey)
{
  gcry_sexp_t l1, l2;
  const char *name;
  size_t n;
  int algo;

  l1 = gcry_sexp_find_token (pkey, "public-key", 0);
  if (!l1)
    return 0; /* Not found.  */
  l2 = gcry_sexp_cadr (l1);
  gcry_sexp_release (l1);

  name = gcry_sexp_nth_data (l2, 0, &n);
  if (!name)
    algo = 0; /* Not found. */
  else if (n==3 && !memcmp (name, "rsa", 3))
    algo = GCRY_PK_RSA;
  else if (n==3 && !memcmp (name, "dsa", 3))
    algo = GCRY_PK_DSA;
  else if (n==13 && !memcmp (name, "ambiguous-rsa", 13))
    algo = GCRY_PK_RSA;
  else
    algo = 0;
  gcry_sexp_release (l2);
  return algo;
}


/* Check the signature on CERT using the ISSUER_CERT.  This function
 * does only test the cryptographic signature and nothing else.  It is
 * assumed that the ISSUER_CERT is valid.  */
static gpg_error_t
check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert)
{
  gpg_error_t err;
  const char *algoid;
  gcry_md_hd_t md;
  int i, algo;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig, s_hash, s_pkey;
  const char *s;
  char algo_name[16+1]; /* hash algorithm name converted to lower case. */
  int digestlen;
  unsigned char *digest;

  /* Hash the target certificate using the algorithm from that certificate.  */
  algoid = ksba_cert_get_digest_algo (cert);
  algo = gcry_md_map_name (algoid);
  if (!algo)
    {
      log_error (_("unknown hash algorithm '%s'\n"), algoid? algoid:"?");
      return gpg_error (GPG_ERR_GENERAL);
    }
  s = gcry_md_algo_name (algo);
  for (i=0; *s && i < sizeof algo_name - 1; s++, i++)
    algo_name[i] = tolower (*s);
  algo_name[i] = 0;

  err = gcry_md_open (&md, algo, 0);
  if (err)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (err));
      return err;
    }
  if (DBG_HASHING)
    gcry_md_debug (md, "hash.cert");

  err = ksba_cert_hash (cert, 1, HASH_FNC, md);
  if (err)
    {
      log_error ("ksba_cert_hash failed: %s\n", gpg_strerror (err));
      gcry_md_close (md);
      return err;
    }
  gcry_md_final (md);

  /* Get the signature value out of the target certificate.  */
  p = ksba_cert_get_sig_val (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      gcry_md_close (md);
      ksba_free (p);
      return gpg_error (GPG_ERR_BUG);
    }
  if (DBG_CRYPTO)
    {
      int j;
      log_debug ("signature value:");
      for (j=0; j < n; j++)
        log_printf (" %02X", p[j]);
      log_printf ("\n");
    }

  err = gcry_sexp_sscan ( &s_sig, NULL, p, n);
  ksba_free (p);
  if (err)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (err));
      gcry_md_close (md);
      return err;
    }

  /* Get the public key from the issuer certificate.  */
  p = ksba_cert_get_public_key (issuer_cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      gcry_md_close (md);
      ksba_free (p);
      gcry_sexp_release (s_sig);
      return gpg_error (GPG_ERR_BUG);
    }
  err = gcry_sexp_sscan ( &s_pkey, NULL, p, n);
  ksba_free (p);
  if (err)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (err));
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      return err;
    }


  /* Prepare the values for signature verification. At this point we
   * have these values:
   *
   * S_PKEY    - S-expression with the issuer's public key.
   * S_SIG     - Signature value as given in the certificate.
   * MD        - Finalized hash context with hash of the certificate.
   * ALGO_NAME - Lowercase hash algorithm name
   */
  digestlen = gcry_md_get_algo_dlen (algo);
  digest = gcry_md_read (md, algo);
  if (pk_algo_from_sexp (s_pkey) == GCRY_PK_DSA)
    {
      /* NB.: We support only SHA-1 here because we had problems back
       * then to get test data for DSA-2.  Meanwhile DSA has been
       * replaced by ECDSA which we do not yet support.  */
      if (digestlen != 20)
        {
          log_error ("DSA requires the use of a 160 bit hash algorithm\n");
          gcry_md_close (md);
          gcry_sexp_release (s_sig);
          gcry_sexp_release (s_pkey);
          return gpg_error (GPG_ERR_INTERNAL);
        }
      if ( gcry_sexp_build (&s_hash, NULL, "(data(flags raw)(value %b))",
                            (int)digestlen, digest) )
        BUG ();
    }
  else /* Not DSA - we assume RSA  */
    {
      if ( gcry_sexp_build (&s_hash, NULL, "(data(flags pkcs1)(hash %s %b))",
                            algo_name, (int)digestlen, digest) )
        BUG ();

    }

  err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (DBG_X509)
    log_debug ("gcry_pk_verify: %s\n", gpg_strerror (err));
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}



/* Return 0 if CERT is usable for MODE.  */
static gpg_error_t
check_cert_usage (ksba_cert_t cert, enum cert_usage_modes mode)
{
  gpg_error_t err;
  unsigned int use;
  char *extkeyusages;
  int have_ocsp_signing = 0;

  err = ksba_cert_get_ext_key_usages (cert, &extkeyusages);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0; /* No policy given. */
  if (!err)
    {
      unsigned int extusemask = ~0; /* Allow all. */

      if (extkeyusages)
        {
          char *p, *pend;
          int any_critical = 0;

          extusemask = 0;

          p = extkeyusages;
          while (p && (pend=strchr (p, ':')))
            {
              *pend++ = 0;
              /* Only care about critical flagged usages. */
              if ( *pend == 'C' )
                {
                  any_critical = 1;
                  if ( !strcmp (p, oid_kp_serverAuth))
                    extusemask |= (KSBA_KEYUSAGE_DIGITAL_SIGNATURE
                                   | KSBA_KEYUSAGE_KEY_ENCIPHERMENT
                                   | KSBA_KEYUSAGE_KEY_AGREEMENT);
                  else if ( !strcmp (p, oid_kp_clientAuth))
                    extusemask |= (KSBA_KEYUSAGE_DIGITAL_SIGNATURE
                                   | KSBA_KEYUSAGE_KEY_AGREEMENT);
                  else if ( !strcmp (p, oid_kp_codeSigning))
                    extusemask |= (KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
                  else if ( !strcmp (p, oid_kp_emailProtection))
                    extusemask |= (KSBA_KEYUSAGE_DIGITAL_SIGNATURE
                                   | KSBA_KEYUSAGE_NON_REPUDIATION
                                   | KSBA_KEYUSAGE_KEY_ENCIPHERMENT
                                   | KSBA_KEYUSAGE_KEY_AGREEMENT);
                  else if ( !strcmp (p, oid_kp_timeStamping))
                    extusemask |= (KSBA_KEYUSAGE_DIGITAL_SIGNATURE
                                   | KSBA_KEYUSAGE_NON_REPUDIATION);
                }

              /* This is a hack to cope with OCSP.  Note that we do
                 not yet fully comply with the requirements and that
                 the entire CRL/OCSP checking thing should undergo a
                 thorough review and probably redesign. */
              if ( !strcmp (p, oid_kp_ocspSigning))
                have_ocsp_signing = 1;

              if ((p = strchr (pend, '\n')))
                p++;
            }
          ksba_free (extkeyusages);
          extkeyusages = NULL;

          if (!any_critical)
            extusemask = ~0; /* Reset to the don't care mask. */
        }


      err = ksba_cert_get_key_usage (cert, &use);
      if (gpg_err_code (err) == GPG_ERR_NO_DATA)
        {
          err = 0;
          if (opt.verbose && (mode == CERT_USAGE_MODE_SIGN
                              || mode == CERT_USAGE_MODE_ENCR))
            log_info (_("no key usage specified - assuming all usages\n"));
          use = ~0;
        }

      /* Apply extKeyUsage. */
      use &= extusemask;

    }
  if (err)
    {
      log_error (_("error getting key usage information: %s\n"),
                 gpg_strerror (err));
      ksba_free (extkeyusages);
      return err;
    }

  switch (mode)
    {
    case CERT_USAGE_MODE_SIGN:
    case CERT_USAGE_MODE_VRFY:
      if ((use & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE
                  | KSBA_KEYUSAGE_NON_REPUDIATION)))
        return 0;
      log_info (mode == CERT_USAGE_MODE_VRFY
                ? _("certificate should not have been used for signing\n")
                : _("certificate is not usable for signing\n"));
      break;

    case CERT_USAGE_MODE_ENCR:
    case CERT_USAGE_MODE_DECR:
      if ((use & (KSBA_KEYUSAGE_KEY_ENCIPHERMENT
                  | KSBA_KEYUSAGE_DATA_ENCIPHERMENT)))
        return 0;
      log_info (mode == CERT_USAGE_MODE_DECR
                ? _("certificate should not have been used for encryption\n")
                : _("certificate is not usable for encryption\n"));
      break;

    case CERT_USAGE_MODE_CERT:
      if ((use & (KSBA_KEYUSAGE_KEY_CERT_SIGN)))
        return 0;
      log_info (_("certificate should not have "
                  "been used for certification\n"));
      break;

    case CERT_USAGE_MODE_OCSP:
      if (use != ~0
          && (have_ocsp_signing
              || (use & (KSBA_KEYUSAGE_KEY_CERT_SIGN
                         |KSBA_KEYUSAGE_CRL_SIGN))))
        return 0;
      log_info (_("certificate should not have "
                  "been used for OCSP response signing\n"));
      break;

    case CERT_USAGE_MODE_CRL:
      if ((use & (KSBA_KEYUSAGE_CRL_SIGN)))
        return 0;
      log_info (_("certificate should not have "
                  "been used for CRL signing\n"));
      break;
    }

  return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
}


/* Return 0 if the certificate CERT is usable for certification.  */
gpg_error_t
check_cert_use_cert (ksba_cert_t cert)
{
  return check_cert_usage (cert, CERT_USAGE_MODE_CERT);
}

/* Return 0 if the certificate CERT is usable for signing OCSP
   responses.  */
gpg_error_t
check_cert_use_ocsp (ksba_cert_t cert)
{
  return check_cert_usage (cert, CERT_USAGE_MODE_OCSP);
}

/* Return 0 if the certificate CERT is usable for signing CRLs. */
gpg_error_t
check_cert_use_crl (ksba_cert_t cert)
{
  return check_cert_usage (cert, CERT_USAGE_MODE_CRL);
}
