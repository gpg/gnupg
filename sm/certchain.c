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


static int
check_cert_policy (KsbaCert cert)
{
  KsbaError err;
  char *policies;
  FILE *fp;
  int any_critical;

  err = ksba_cert_get_cert_policies (cert, &policies);
  if (err == KSBA_No_Data)
    return 0; /* no policy given */
  if (err)
    return map_ksba_err (err);

  /* STRING is a line delimited list of certifiate policies as stored
     in the certificate.  The line itself is colon delimted where the
     first field is the OID of the policy and the second field either
     N or C for normal or critical extension */

  /* The check is very minimal but won't give false positives */
  any_critical = !!strstr (policies, ":C");

  if (!opt.policy_file)
    { 
      xfree (policies);
      if (any_critical)
        {
          log_error ("critical marked policy without configured policies\n");
          return GNUPG_No_Policy_Match;
        }
      return 0;
    }

  fp = fopen (opt.policy_file, "r");
  if (!fp)
    {
      log_error ("failed to open `%s': %s\n",
                 opt.policy_file, strerror (errno));
      xfree (policies);
      return GNUPG_Configuration_Error;
    }

  for (;;) 
    {
      int c;
      char *p, line[256];
      char *haystack, *allowed;

      /* read line */
      do
        {
          if (!fgets (line, DIM(line)-1, fp) )
            {
              xfree (policies);
              if (feof (fp))
                {
                  fclose (fp);
                  log_error (_("certificate policy not allowed\n"));
                  /* with no critical policies this is only a warning */
                  return any_critical? GNUPG_No_Policy_Match : 0;
                }
              fclose (fp);
              return GNUPG_Read_Error;
            }
      
          if (!*line || line[strlen(line)-1] != '\n')
            {
              /* eat until end of line */
              while ( (c=getc (fp)) != EOF && c != '\n')
                ;
              fclose (fp);
              xfree (policies);
              return *line? GNUPG_Line_Too_Long: GNUPG_Incomplete_Line;
            }
          
          /* Allow for empty lines and spaces */
          for (p=line; spacep (p); p++)
            ;
        }
      while (!*p || *p == '\n' || *p == '#');
  
      /* parse line */
      for (allowed=line; spacep (allowed); allowed++)
        ;
      p = strpbrk (allowed, " :\n");
      if (!*p || p == allowed)
        {
          fclose (fp);
          xfree (policies);
          return GNUPG_Configuration_Error;
        }
      *p = 0; /* strip the rest of the line */
      /* See whether we find ALLOWED (which is an OID) in POLICIES */
      for (haystack=policies; (p=strstr (haystack, allowed)); haystack = p+1)
        {
          if ( !(p == policies || p[-1] == '\n') )
            continue; /* does not match the begin of a line */
          if (p[strlen (allowed)] != ':')
            continue; /* the length does not match */
          /* Yep - it does match so return okay */
          fclose (fp);
          xfree (policies);
          return 0;
        }
    }
}

/* Return the next certificate up in the chain starting at START.
   Returns -1 when there are no more certificates. */
int
gpgsm_walk_cert_chain (KsbaCert start, KsbaCert *r_next)
{
  int rc = 0; 
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);

  *r_next = NULL;
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }

  issuer = ksba_cert_get_issuer (start, 0);
  subject = ksba_cert_get_subject (start, 0);
  if (!issuer)
    {
      log_error ("no issuer found in certificate\n");
      rc = GNUPG_Bad_Certificate;
      goto leave;
    }
  if (!subject)
    {
      log_error ("no subject found in certificate\n");
      rc = GNUPG_Bad_Certificate;
      goto leave;
    }

  if (!strcmp (issuer, subject))
    {
      rc = -1; /* we are at the root */
      goto leave; 
    }
 
  rc = keydb_search_subject (kh, issuer);
  if (rc)
    {
      log_error ("failed to find issuer's certificate: rc=%d\n", rc);
      rc = GNUPG_Missing_Certificate;
      goto leave;
    }

  rc = keydb_get_cert (kh, r_next);
  if (rc)
    {
      log_error ("failed to get cert: rc=%d\n", rc);
      rc = GNUPG_General_Error;
    }

 leave:
  xfree (issuer);
  xfree (subject);
  keydb_release (kh); 
  return rc;
}


/* Check whether the CERT is a root certificate.  Returns True if this
   is the case. */
int
gpgsm_is_root_cert (KsbaCert cert)
{
  char *issuer;
  char *subject;
  int yes;

  issuer = ksba_cert_get_issuer (cert, 0);
  subject = ksba_cert_get_subject (cert, 0);
  yes = (issuer && subject && !strcmp (issuer, subject));
  xfree (issuer);
  xfree (subject);
  return yes;
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

  if ((opt.debug & 4096))
    {
      log_info ("WARNING: bypassing path validation\n");
      return 0;
    }
      

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

      if (!opt.no_policy_check)
        {
          rc = check_cert_policy (subject_cert);
          if (rc)
            goto leave;
        }

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
              int rc2;

              char *fpr = gpgsm_get_fingerprint_string (subject_cert,
                                                        GCRY_MD_SHA1);
              log_info (_("root certificate is not marked trusted\n"));
              log_info (_("fingerprint=%s\n"), fpr? fpr : "?");
              xfree (fpr);
              rc2 = gpgsm_agent_marktrusted (subject_cert);
              if (!rc2)
                {
                  log_info (_("root certificate has now"
                              " been marked as trusted\n"));
                  rc = 0;
                }
              else 
                {
                  gpgsm_dump_cert ("issuer", subject_cert);
                  log_info ("after checking the fingerprint, you may want "
                            "to enter it manually into "
                            "\"~/.gnupg-test/trustlist.txt\"\n");
                }
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

  if (opt.no_policy_check)
    log_info ("policies not checked due to --disable-policy-checks option\n");
  if (opt.no_crl_check)
    log_info ("CRLs not checked due to --disable-crl-checks option\n");
  
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

  if ((opt.debug & 4096))
    {
      log_info ("WARNING: bypassing basic certificate checks\n");
      return 0;
    }

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
      log_error ("no issuer found in certificate\n");
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

