/* certlist.c - build list of certificates
 * Copyright (C) 2001, 2003, 2004, 2005, 2007,
 *               2008, 2011 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/i18n.h"

/* Mode values for cert_usage_p.
 * Take care: the values have a  semantic.  */
#define USE_MODE_SIGN 0
#define USE_MODE_ENCR 1
#define USE_MODE_VRFY 2
#define USE_MODE_DECR 3
#define USE_MODE_CERT 4
#define USE_MODE_OCSP 5

/* OIDs we use here.  */
static const char oid_kp_serverAuth[]     = "1.3.6.1.5.5.7.3.1";
static const char oid_kp_clientAuth[]     = "1.3.6.1.5.5.7.3.2";
static const char oid_kp_codeSigning[]    = "1.3.6.1.5.5.7.3.3";
static const char oid_kp_emailProtection[]= "1.3.6.1.5.5.7.3.4";
static const char oid_kp_timeStamping[]   = "1.3.6.1.5.5.7.3.8";
static const char oid_kp_ocspSigning[]    = "1.3.6.1.5.5.7.3.9";


/* Return 0 if the cert is usable for encryption.  A MODE of 0 checks
   for signing a MODE of 1 checks for encryption, a MODE of 2 checks
   for verification and a MODE of 3 for decryption (just for
   debugging).  MODE 4 is for certificate signing, MODE for COSP
   response signing. */
static int
cert_usage_p (ksba_cert_t cert, int mode, int silent)
{
  gpg_error_t err;
  unsigned int use;
  unsigned int encr_bits, sign_bits;
  char *extkeyusages;
  int have_ocsp_signing = 0;


  err = ksba_cert_get_ext_key_usages (cert, &extkeyusages);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0; /* no policy given */
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
          xfree (extkeyusages);
          extkeyusages = NULL;

          if (!any_critical)
            extusemask = ~0; /* Reset to the don't care mask. */
        }


      err = ksba_cert_get_key_usage (cert, &use);
      if (gpg_err_code (err) == GPG_ERR_NO_DATA)
        {
          err = 0;
          if (opt.verbose && mode < USE_MODE_VRFY && !silent)
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
      xfree (extkeyusages);
      return err;
    }

  if (mode == USE_MODE_CERT)
    {
      if ((use & (KSBA_KEYUSAGE_KEY_CERT_SIGN)))
        return 0;
      if (!silent)
        log_info (_("certificate should not have "
                    "been used for certification\n"));
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  if (mode == USE_MODE_OCSP)
    {
      if (use != ~0
          && (have_ocsp_signing
              || (use & (KSBA_KEYUSAGE_KEY_CERT_SIGN
                         |KSBA_KEYUSAGE_CRL_SIGN))))
        return 0;
      if (!silent)
        log_info (_("certificate should not have "
                    "been used for OCSP response signing\n"));
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  encr_bits = (KSBA_KEYUSAGE_KEY_ENCIPHERMENT|KSBA_KEYUSAGE_DATA_ENCIPHERMENT);
  if ((opt.compat_flags & COMPAT_ALLOW_KA_TO_ENCR)
      || gpgsm_is_ecc_key (cert))
    encr_bits |= KSBA_KEYUSAGE_KEY_AGREEMENT;

  sign_bits = (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_NON_REPUDIATION);

  if ((use & ((mode&1)? encr_bits : sign_bits)))
    return 0;

  if (!silent)
    log_info (mode == USE_MODE_DECR?
              _("certificate should not have been used for encryption\n") :
              mode == USE_MODE_VRFY?
              _("certificate should not have been used for signing\n") :
              mode == USE_MODE_ENCR?
              _("certificate is not usable for encryption\n") :
              _("certificate is not usable for signing\n"));

  return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
}


/* Return 0 if the cert is usable for signing */
int
gpgsm_cert_use_sign_p (ksba_cert_t cert, int silent)
{
  return cert_usage_p (cert, USE_MODE_SIGN, silent);
}


/* Return 0 if the cert is usable for encryption */
int
gpgsm_cert_use_encrypt_p (ksba_cert_t cert)
{
  return cert_usage_p (cert, USE_MODE_ENCR, 0);
}

int
gpgsm_cert_use_verify_p (ksba_cert_t cert)
{
  return cert_usage_p (cert, USE_MODE_VRFY, 0);
}

int
gpgsm_cert_use_decrypt_p (ksba_cert_t cert)
{
  return cert_usage_p (cert, USE_MODE_DECR, 0);
}

int
gpgsm_cert_use_cert_p (ksba_cert_t cert)
{
  return cert_usage_p (cert, USE_MODE_CERT, 0);
}

int
gpgsm_cert_use_ocsp_p (ksba_cert_t cert)
{
  return cert_usage_p (cert, USE_MODE_OCSP, 0);
}


/* Return true if CERT has the well known private key extension.  */
int
gpgsm_cert_has_well_known_private_key (ksba_cert_t cert)
{
  int idx;
  const char *oid;

  for (idx=0; !ksba_cert_get_extension (cert, idx,
                                        &oid, NULL, NULL, NULL);idx++)
    if (!strcmp (oid, "1.3.6.1.4.1.11591.2.2.2") )
      return 1; /* Yes.  */
  return 0; /* No.  */
}


static int
same_subject_issuer (const char *subject, const char *issuer, ksba_cert_t cert)
{
  char *subject2 = ksba_cert_get_subject (cert, 0);
  char *issuer2 = ksba_cert_get_issuer (cert, 0);
  int tmp;

  tmp = (subject && subject2
         && !strcmp (subject, subject2)
         && issuer && issuer2
         && !strcmp (issuer, issuer2));
  xfree (subject2);
  xfree (issuer2);
  return tmp;
}


/* Return true if CERT_A is the same as CERT_B.  */
int
gpgsm_certs_identical_p (ksba_cert_t cert_a, ksba_cert_t cert_b)
{
  const unsigned char *img_a, *img_b;
  size_t len_a, len_b;

  img_a = ksba_cert_get_image (cert_a, &len_a);
  if (img_a)
    {
      img_b = ksba_cert_get_image (cert_b, &len_b);
      if (img_b && len_a == len_b && !memcmp (img_a, img_b, len_a))
        return 1; /* Identical. */
    }
  return 0;
}


/* Return true if CERT is already contained in CERTLIST. */
static int
is_cert_in_certlist (ksba_cert_t cert, certlist_t certlist)
{
  const unsigned char *img_a, *img_b;
  size_t len_a, len_b;

  img_a = ksba_cert_get_image (cert, &len_a);
  if (img_a)
    {
      for ( ; certlist; certlist = certlist->next)
        {
          img_b = ksba_cert_get_image (certlist->cert, &len_b);
          if (img_b && len_a == len_b && !memcmp (img_a, img_b, len_a))
            return 1; /* Already contained. */
        }
    }
  return 0;
}


/* Add CERT to the list of certificates at CERTADDR but avoid
   duplicates. */
int
gpgsm_add_cert_to_certlist (ctrl_t ctrl, ksba_cert_t cert,
                            certlist_t *listaddr, int is_encrypt_to)
{
  (void)ctrl;

  if (!is_cert_in_certlist (cert, *listaddr))
    {
      certlist_t cl = xtrycalloc (1, sizeof *cl);
      if (!cl)
        return out_of_core ();
      cl->cert = cert;
      ksba_cert_ref (cert);
      cl->next = *listaddr;
      cl->is_encrypt_to = is_encrypt_to;
      *listaddr = cl;
    }
   return 0;
}

/* Add a certificate to a list of certificate and make sure that it is
   a valid certificate.  With SECRET set to true a secret key must be
   available for the certificate. IS_ENCRYPT_TO sets the corresponding
   flag in the new create LISTADDR item.  */
int
gpgsm_add_to_certlist (ctrl_t ctrl, const char *name, int secret,
                       certlist_t *listaddr, int is_encrypt_to)
{
  int rc;
  KEYDB_SEARCH_DESC desc;
  KEYDB_HANDLE kh = NULL;
  ksba_cert_t cert = NULL;

  rc = classify_user_id (name, &desc, 0);
  if (!rc)
    {
      kh = keydb_new (ctrl);
      if (!kh)
        rc = gpg_error (GPG_ERR_ENOMEM);
      else
        {
          int wrong_usage = 0;
          char *first_subject = NULL;
          char *first_issuer = NULL;

        get_next:
          rc = keydb_search (ctrl, kh, &desc, 1);
          if (!rc)
            rc = keydb_get_cert (kh, &cert);
          if (!rc)
            {
              if (!first_subject)
                {
                  /* Save the subject and the issuer for key usage
                     and ambiguous name tests. */
                  first_subject = ksba_cert_get_subject (cert, 0);
                  first_issuer = ksba_cert_get_issuer (cert, 0);
                }
              rc = secret? gpgsm_cert_use_sign_p (cert, 0)
                         : gpgsm_cert_use_encrypt_p (cert);
              if (gpg_err_code (rc) == GPG_ERR_WRONG_KEY_USAGE)
                {
                  /* There might be another certificate with the
                     correct usage, so we try again */
                  if (!wrong_usage
                      || same_subject_issuer (first_subject, first_issuer,cert))
                    {
                      if (!wrong_usage)
                        wrong_usage = rc; /* save error of the first match */
                      ksba_cert_release (cert);
                      cert = NULL;
                      log_info (_("looking for another certificate\n"));
                      goto get_next;
                    }
                  else
                    wrong_usage = rc;

                }
            }
          /* We want the error code from the first match in this case. */
          if (rc && wrong_usage)
            rc = wrong_usage;

          if (!rc)
            {
              certlist_t dup_certs = NULL;

            next_ambigious:
              rc = keydb_search (ctrl, kh, &desc, 1);
              if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
                rc = 0;
              else if (!rc)
                {
                  ksba_cert_t cert2 = NULL;

                  /* If this is the first possible duplicate, add the original
                     certificate to our list of duplicates.  */
                  if (!dup_certs)
                    gpgsm_add_cert_to_certlist (ctrl, cert, &dup_certs, 0);

                  /* We have to ignore ambiguous names as long as
                     there only fault is a bad key usage.  This is
                     required to support encryption and signing
                     certificates of the same subject.

                     Further we ignore them if they are due to an
                     identical certificate (which may happen if a
                     certificate is accidentally duplicated in the
                     keybox).  */
                  if (!keydb_get_cert (kh, &cert2))
                    {
                      int tmp = (same_subject_issuer (first_subject,
                                                      first_issuer,
                                                      cert2)
                                 && ((gpg_err_code (
                                      secret? gpgsm_cert_use_sign_p (cert2,0)
                                            : gpgsm_cert_use_encrypt_p (cert2)
                                      )
                                     )  == GPG_ERR_WRONG_KEY_USAGE));
                      if (tmp)
                        gpgsm_add_cert_to_certlist (ctrl, cert2,
                                                    &dup_certs, 0);
                      else
                        {
                          if (is_cert_in_certlist (cert2, dup_certs))
                            tmp = 1;
                        }

                      ksba_cert_release (cert2);
                      if (tmp)
                        goto next_ambigious;
                    }
                  rc = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
                }
              gpgsm_release_certlist (dup_certs);
            }
          xfree (first_subject);
          xfree (first_issuer);
          first_subject = NULL;
          first_issuer = NULL;

          if (!rc && !is_cert_in_certlist (cert, *listaddr))
            {
              unsigned int valflags = 0;

              if (!secret && (opt.always_trust || ctrl->always_trust))
                valflags |= VALIDATE_FLAG_BYPASS;

              if (!rc && secret)
                {
                  char *p;

                  rc = gpg_error (GPG_ERR_NO_SECKEY);
                  p = gpgsm_get_keygrip_hexstring (cert);
                  if (p)
                    {
                      if (!gpgsm_agent_havekey (ctrl, p))
                        rc = 0;
                      xfree (p);
                    }
                }

              if (!rc)
                rc = gpgsm_validate_chain (ctrl, cert, GNUPG_ISOTIME_NONE, NULL,
                                           0, NULL, valflags, NULL);
              if (!rc)
                {
                  certlist_t cl = xtrycalloc (1, sizeof *cl);
                  if (!cl)
                    rc = gpg_error_from_syserror ();
                  else
                    {
                      cl->cert = cert; cert = NULL;
                      cl->next = *listaddr;
                      cl->is_encrypt_to = is_encrypt_to;
                      *listaddr = cl;
                    }
                }
            }
        }
    }

  keydb_release (kh);
  ksba_cert_release (cert);
  return (gpg_err_code (rc) == GPG_ERR_NOT_FOUND
          ? gpg_error (GPG_ERR_NO_PUBKEY): rc);
}


void
gpgsm_release_certlist (certlist_t list)
{
  while (list)
    {
      certlist_t cl = list->next;
      ksba_cert_release (list->cert);
      xfree (list);
      list = cl;
    }
}


/* Like gpgsm_add_to_certlist, but look only for one certificate.  No
   chain validation is done.  If KEYID is not NULL it is taken as an
   additional filter value which must match the
   subjectKeyIdentifier. */
int
gpgsm_find_cert (ctrl_t ctrl,
                 const char *name, ksba_sexp_t keyid, ksba_cert_t *r_cert,
                 unsigned int flags)
{
  int rc;
  KEYDB_SEARCH_DESC desc;
  KEYDB_HANDLE kh = NULL;
  int allow_ambiguous = (flags & FIND_CERT_ALLOW_AMBIG);

  *r_cert = NULL;
  rc = classify_user_id (name, &desc, 0);
  if (!rc)
    {
      kh = keydb_new (ctrl);
      if (!kh)
        rc = gpg_error (GPG_ERR_ENOMEM);
      else
        {
          if ((flags & FIND_CERT_WITH_EPHEM))
            keydb_set_ephemeral (kh, 1);

        nextone:
          rc = keydb_search (ctrl, kh, &desc, 1);
          if (!rc)
            {
              rc = keydb_get_cert (kh, r_cert);
              if (!rc && keyid)
                {
                  ksba_sexp_t subj;

                  rc = ksba_cert_get_subj_key_id (*r_cert, NULL, &subj);
                  if (!rc)
                    {
                      if (cmp_simple_canon_sexp (keyid, subj))
                        {
                          xfree (subj);
                          goto nextone;
                        }
                      xfree (subj);
                      /* Okay: Here we know that the certificate's
                         subjectKeyIdentifier matches the requested
                         one. */
                    }
                  else if (gpg_err_code (rc) == GPG_ERR_NO_DATA)
                    goto nextone;
                }
            }

          /* If we don't have the KEYID filter we need to check for
             ambiguous search results.  Note, that it is somewhat
             reasonable to assume that a specification of a KEYID
             won't lead to ambiguous names. */
          if (!rc && !keyid)
            {
              ksba_isotime_t notbefore = "";
              const unsigned char *image = NULL;
              size_t length = 0;
              if (allow_ambiguous)
                {
                  /* We want to return the newest certificate */
                  if (ksba_cert_get_validity (*r_cert, 0, notbefore))
                    *notbefore = '\0';
                  image = ksba_cert_get_image (*r_cert, &length);
                }
            next_ambiguous:
              rc = keydb_search (ctrl, kh, &desc, 1);
              if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
                rc = 0;
              else
                {
                  if (!rc)
                    {
                      ksba_cert_t cert2 = NULL;
                      ksba_isotime_t notbefore2 = "";
                      const unsigned char *image2 = NULL;
                      size_t length2 = 0;
                      int cmp = 0;

                      if (!keydb_get_cert (kh, &cert2))
                        {
                          if (gpgsm_certs_identical_p (*r_cert, cert2))
                            {
                              ksba_cert_release (cert2);
                              goto next_ambiguous;
                            }
                          if (allow_ambiguous)
                            {
                              if (ksba_cert_get_validity (cert2, 0, notbefore2))
                                *notbefore2 = '\0';
                              image2 = ksba_cert_get_image (cert2, &length2);
                              cmp = strcmp (notbefore, notbefore2);
                              /* use certificate image bits as last resort for stable ordering */
                              if (!cmp)
                                cmp = memcmp (image, image2, length < length2 ? length : length2);
                              if (!cmp)
                                cmp = length < length2 ? -1 : length > length2 ? 1 : 0;
                              if (cmp < 0)
                                {
                                  ksba_cert_release (*r_cert);
                                  *r_cert = cert2;
                                  strcpy (notbefore, notbefore2);
                                  image = image2;
                                  length = length2;
                                }
                              else
                                ksba_cert_release (cert2);
                              goto next_ambiguous;
                            }
                          ksba_cert_release (cert2);
                        }
                      rc = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
                    }
                  ksba_cert_release (*r_cert);
                  *r_cert = NULL;
                }
            }
        }
    }

  keydb_release (kh);
  return (gpg_err_code (rc) == GPG_ERR_NOT_FOUND?
          gpg_error (GPG_ERR_NO_PUBKEY): rc);
}
