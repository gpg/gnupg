/* certpath.c - path validation
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
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
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>
#include <ksba.h>

#include "gpgsm.h"
#include "keydb.h"
#include "i18n.h"

static int
unknown_criticals (KsbaCert cert)
{
  static const char *known[] = {
    "2.5.29.15", /* keyUsage */
    "2.5.29.19", /* basic Constraints */
    "2.5.29.32", /* certificatePolicies */
    NULL
  };
  int rc = 0, i, idx, crit;
  const char *oid;
  KsbaError err;

  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &crit, NULL, NULL));idx++)
    {
      if (!crit)
        continue;
      for (i=0; known[i] && strcmp (known[i],oid); i++)
        ;
      if (!known[i])
        {
          log_error (_("critical certificate extension %s is not supported\n"),
                     oid);
          rc = GNUPG_Unsupported_Certificate;
        }
    }
  if (err && err != -1)
    rc = map_ksba_err (err);

  return rc;
}

static int
allowed_ca (KsbaCert cert, int *pathlen)
{
  KsbaError err;
  int flag;

  err = ksba_cert_is_ca (cert, &flag, pathlen);
  if (err)
    return map_ksba_err (err);
  if (!flag)
    {
      log_error (_("issuer certificate is not marked as a CA\n"));
      return GNUPG_Bad_CA_Certificate;
    }
  return 0;
}


int
gpgsm_validate_path (KsbaCert cert)
{
  int rc = 0, depth = 0, maxdepth;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);
  KsbaCert subject_cert = NULL, issuer_cert = NULL;
  time_t current_time = time (NULL);

  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }

  if (DBG_X509)
    gpgsm_dump_cert ("subject", cert);

  subject_cert = cert;
  maxdepth = 50;

  for (;;)
    {
      xfree (issuer);
      xfree (subject);
      issuer = ksba_cert_get_issuer (subject_cert, 0);
      subject = ksba_cert_get_subject (subject_cert, 0);

      if (!issuer)
        {
          log_error ("no issuer found in certificate\n");
          rc = GNUPG_Bad_Certificate;
          goto leave;
        }

      {
        time_t not_before, not_after;

        not_before = ksba_cert_get_validity (subject_cert, 0);
        not_after = ksba_cert_get_validity (subject_cert, 1);
        if (not_before == (time_t)(-1) || not_after == (time_t)(-1))
          {
            log_error ("certificate with invalid validity\n");
            rc = GNUPG_Bad_Certificate;
            goto leave;
          }

        if (current_time < not_before)
          {
            log_error ("certificate to young; valid from ");
            gpgsm_dump_time (not_before);
            log_printf ("\n");
            rc = GNUPG_Certificate_Too_Young;
            goto leave;
          }            
        if (current_time > not_after)
          {
            log_error ("certificate has expired at ");
            gpgsm_dump_time (not_after);
            log_printf ("\n");
            rc = GNUPG_Certificate_Expired;
            goto leave;
          }            
      }

      rc = unknown_criticals (subject_cert);
      if (rc)
        goto leave;
        
      if (!opt.no_crl_check)
        {
          rc = gpgsm_dirmngr_isvalid (subject_cert);
          if (rc)
            {
              switch (rc)
                {
                case GNUPG_Certificate_Revoked:
                  log_error (_("the certificate has been revoked\n"));
                  break;
                case GNUPG_No_CRL_Known:
                  log_error (_("no CRL found for certificate\n"));
                  break;
                case GNUPG_CRL_Too_Old:
                  log_error (_("the available CRL is too old\n"));
                  log_info (_("please make sure that the "
                              "\"dirmngr\" is properly installed\n"));
                  break;
                default:
                  log_error (_("checking the CRL failed: %s\n"),
                             gnupg_strerror (rc));
                  break;
                }
              goto leave;
            }
        }

      if (subject && !strcmp (issuer, subject))
        {
          if (gpgsm_check_cert_sig (subject_cert, subject_cert) )
            {
              log_error ("selfsigned certificate has a BAD signatures\n");
              rc = depth? GNUPG_Bad_Certificate_Path : GNUPG_Bad_Certificate;
              goto leave;
            }
          rc = allowed_ca (subject_cert, NULL);
          if (rc)
            goto leave;

          rc = gpgsm_agent_istrusted (subject_cert);
          if (!rc)
            ;
          else if (rc == GNUPG_Not_Trusted)
            {
              char *fpr = gpgsm_get_fingerprint_string (subject_cert,
                                                        GCRY_MD_SHA1);
              log_error (_("root certificate is not marked trusted\n"));
              log_info (_("fingerprint=%s\n"), fpr? fpr : "?");
              xfree (fpr);
              /* fixme: print a note while we have not yet the code to
                 ask whether the cert should be entered into the trust
                 list */
              gpgsm_dump_cert ("issuer", subject_cert);
              log_info ("after checking the fingerprint, you may want "
                        "to enter it into \"~/.gnupg-test/trustlist.txt\"\n");
            }
          else 
            {
              log_error (_("checking the trust list failed: %s\n"),
                         gnupg_strerror (rc));
            }
          
          break;  /* okay, a self-signed certicate is an end-point */
        }
      
      depth++;
      if (depth > maxdepth)
        {
          log_error (_("certificate path too long\n"));
          rc = GNUPG_Bad_Certificate_Path;
          goto leave;
        }

      /* find the next cert up the tree */
      keydb_search_reset (kh);
      rc = keydb_search_subject (kh, issuer);
      if (rc)
        {
          if (rc == -1)
            {
              log_info ("issuer certificate (");
              gpgsm_dump_string (issuer);
              log_printf (") not found\n");
            }
          else
            log_error ("failed to find issuer's certificate: rc=%d\n", rc);
          rc = GNUPG_Missing_Certificate;
          goto leave;
        }

      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_error ("failed to get cert: rc=%d\n", rc);
          rc = GNUPG_General_Error;
          goto leave;
        }

      if (DBG_X509)
        {
          log_debug ("got issuer's certificate:\n");
          gpgsm_dump_cert ("issuer", issuer_cert);
        }

      if (gpgsm_check_cert_sig (issuer_cert, subject_cert) )
        {
          log_error ("certificate has a BAD signatures\n");
          rc = GNUPG_Bad_Certificate_Path;
          goto leave;
        }

      {
        int pathlen;
        rc = allowed_ca (issuer_cert, &pathlen);
        if (rc)
          goto leave;
        if (pathlen >= 0 && (depth - 1) > pathlen)
          {
            log_error (_("certificate path longer than allowed by CA (%d)\n"),
                       pathlen);
            rc = GNUPG_Bad_Certificate_Path;
            goto leave;
          }
      }

      log_info ("certificate is good\n");
      
      keydb_search_reset (kh);
      subject_cert = issuer_cert;
      issuer_cert = NULL;
    }

  if (opt.no_crl_check)
    log_info ("CRL was not checked due to --no-crl-cechk option\n");

  
 leave:
  xfree (issuer);
  keydb_release (kh); 
  ksba_cert_release (issuer_cert);
  if (subject_cert != cert)
    ksba_cert_release (subject_cert);
  return rc;
}


/* Check that the given certificate is valid but DO NOT check any
   constraints.  We assume that the issuers certificate is already in
   the DB and that this one is valid; which it should be because it
   has been checked using this function. */
int
gpgsm_basic_cert_check (KsbaCert cert)
{
  int rc = 0;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);
  KsbaCert issuer_cert = NULL;

  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }

  issuer = ksba_cert_get_issuer (cert, 0);
  subject = ksba_cert_get_subject (cert, 0);
  if (!issuer)
    {
      if (DBG_X509)
        log_debug ("ERROR: issuer missing\n");
      rc = GNUPG_Bad_Certificate;
      goto leave;
    }

  if (subject && !strcmp (issuer, subject))
    {
      if (gpgsm_check_cert_sig (cert, cert) )
        {
          log_error ("selfsigned certificate has a BAD signatures\n");
          rc = GNUPG_Bad_Certificate;
          goto leave;
        }
    }
  else
    {
      /* find the next cert up the tree */
      keydb_search_reset (kh);
      rc = keydb_search_subject (kh, issuer);
      if (rc)
        {
          if (rc == -1)
            {
              log_info ("issuer certificate (");
              gpgsm_dump_string (issuer);
              log_printf (") not found\n");
            }
          else
            log_error ("failed to find issuer's certificate: rc=%d\n", rc);
          rc = GNUPG_Missing_Certificate;
          goto leave;
        }
      
      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_error ("failed to get cert: rc=%d\n", rc);
          rc = GNUPG_General_Error;
          goto leave;
        }

      if (gpgsm_check_cert_sig (issuer_cert, cert) )
        {
          log_error ("certificate has a BAD signatures\n");
          rc = GNUPG_Bad_Certificate;
          goto leave;
        }
      if (opt.verbose)
        log_info ("certificate is good\n");
    }

 leave:
  xfree (issuer);
  keydb_release (kh); 
  ksba_cert_release (issuer_cert);
  return rc;
}

