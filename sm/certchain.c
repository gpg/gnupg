/* certchain.c - certificate chain validation
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <assert.h>

#define JNLIB_NEED_LOG_LOGV /* We need log_logv. */

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../kbx/keybox.h" /* for KEYBOX_FLAG_* */
#include "i18n.h"


/* If LISTMODE is true, print FORMAT in liting mode to FP.  If
   LISTMODE is false, use the string to print an log_info or, if
   IS_ERROR is true, an log_error. */
static void
do_list (int is_error, int listmode, FILE *fp, const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format) ;
  if (listmode)
    {
      if (fp)
        {
          fputs ("  [", fp);
          vfprintf (fp, format, arg_ptr);
          fputs ("]\n", fp);
        }
    }
  else
    {
      log_logv (is_error? JNLIB_LOG_ERROR: JNLIB_LOG_INFO, format, arg_ptr);
      log_printf ("\n");
    }
  va_end (arg_ptr);
}

/* Return 0 if A and B are equal. */
static int
compare_certs (ksba_cert_t a, ksba_cert_t b)
{
  const unsigned char *img_a, *img_b;
  size_t len_a, len_b;

  img_a = ksba_cert_get_image (a, &len_a);
  if (!img_a)
    return 1;
  img_b = ksba_cert_get_image (b, &len_b);
  if (!img_b)
    return 1;
  return !(len_a == len_b && !memcmp (img_a, img_b, len_a));
}


static int
unknown_criticals (ksba_cert_t cert, int listmode, FILE *fp)
{
  static const char *known[] = {
    "2.5.29.15", /* keyUsage */
    "2.5.29.19", /* basic Constraints */
    "2.5.29.32", /* certificatePolicies */
    "2.5.29.37", /* extendedKeyUsage - handled by certlist.c */
    NULL
  };
  int rc = 0, i, idx, crit;
  const char *oid;
  gpg_error_t err;

  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &crit, NULL, NULL));idx++)
    {
      if (!crit)
        continue;
      for (i=0; known[i] && strcmp (known[i],oid); i++)
        ;
      if (!known[i])
        {
          do_list (1, listmode, fp,
                   _("critical certificate extension %s is not supported"),
                   oid);
          rc = gpg_error (GPG_ERR_UNSUPPORTED_CERT);
        }
    }
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    rc = err;

  return rc;
}

static int
allowed_ca (ksba_cert_t cert, int *chainlen, int listmode, FILE *fp)
{
  gpg_error_t err;
  int flag;

  err = ksba_cert_is_ca (cert, &flag, chainlen);
  if (err)
    return err;
  if (!flag)
    {
      do_list (1, listmode, fp,_("issuer certificate is not marked as a CA"));
      return gpg_error (GPG_ERR_BAD_CA_CERT);
    }
  return 0;
}


static int
check_cert_policy (ksba_cert_t cert, int listmode, FILE *fplist)
{
  gpg_error_t err;
  char *policies;
  FILE *fp;
  int any_critical;

  err = ksba_cert_get_cert_policies (cert, &policies);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return 0; /* no policy given */
  if (err)
    return err;

  /* STRING is a line delimited list of certifiate policies as stored
     in the certificate.  The line itself is colon delimited where the
     first field is the OID of the policy and the second field either
     N or C for normal or critical extension */

  if (opt.verbose > 1 && !listmode)
    log_info ("certificate's policy list: %s\n", policies);

  /* The check is very minimal but won't give false positives */
  any_critical = !!strstr (policies, ":C");

  if (!opt.policy_file)
    { 
      xfree (policies);
      if (any_critical)
        {
          do_list (1, listmode, fplist,
                   _("critical marked policy without configured policies"));
          return gpg_error (GPG_ERR_NO_POLICY_MATCH);
        }
      return 0;
    }

  fp = fopen (opt.policy_file, "r");
  if (!fp)
    {
      log_error ("failed to open `%s': %s\n",
                 opt.policy_file, strerror (errno));
      xfree (policies);
      /* With no critical policies this is only a warning */
      if (!any_critical)
        {
          do_list (0, listmode, fplist,
                   _("note: non-critical certificate policy not allowed"));
          return 0;
        }
      do_list (1, listmode, fplist,
               _("certificate policy not allowed"));
      return gpg_error (GPG_ERR_NO_POLICY_MATCH);
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
              gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));

              xfree (policies);
              if (feof (fp))
                {
                  fclose (fp);
                  /* With no critical policies this is only a warning */
                  if (!any_critical)
                    {
                      do_list (0, listmode, fplist,
                     _("note: non-critical certificate policy not allowed"));
                      return 0;
                    }
                  do_list (1, listmode, fplist,
                           _("certificate policy not allowed"));
                  return gpg_error (GPG_ERR_NO_POLICY_MATCH);
                }
              fclose (fp);
              return tmperr;
            }
      
          if (!*line || line[strlen(line)-1] != '\n')
            {
              /* eat until end of line */
              while ( (c=getc (fp)) != EOF && c != '\n')
                ;
              fclose (fp);
              xfree (policies);
              return gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                                     : GPG_ERR_INCOMPLETE_LINE);
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
          return gpg_error (GPG_ERR_CONFIGURATION);
        }
      *p = 0; /* strip the rest of the line */
      /* See whether we find ALLOWED (which is an OID) in POLICIES */
      for (haystack=policies; (p=strstr (haystack, allowed)); haystack = p+1)
        {
          if ( !(p == policies || p[-1] == '\n') )
            continue; /* Does not match the begin of a line. */
          if (p[strlen (allowed)] != ':')
            continue; /* The length does not match. */
          /* Yep - it does match so return okay. */
          fclose (fp);
          xfree (policies);
          return 0;
        }
    }
}


static void
find_up_store_certs_cb (void *cb_value, ksba_cert_t cert)
{
  if (keydb_store_cert (cert, 1, NULL))
    log_error ("error storing issuer certificate as ephemeral\n");
  ++*(int*)cb_value;
}


static int
find_up (KEYDB_HANDLE kh, ksba_cert_t cert, const char *issuer, int find_next)
{
  ksba_name_t authid;
  ksba_sexp_t authidno;
  int rc = -1;

  if (!ksba_cert_get_auth_key_id (cert, NULL, &authid, &authidno))
    {
      const char *s = ksba_name_enum (authid, 0);
      if (s && *authidno)
        {
          rc = keydb_search_issuer_sn (kh, s, authidno);
          if (rc)
              keydb_search_reset (kh);
          
          /* In case of an error try the ephemeral DB.  We can't do
             that in find-netx mode because we can't keep the search
             state then. */
          if (rc == -1 && !find_next)
            { 
              int old = keydb_set_ephemeral (kh, 1);
              if (!old)
                {
                  rc = keydb_search_issuer_sn (kh, s, authidno);
                  if (rc)
                    keydb_search_reset (kh);
                }
              keydb_set_ephemeral (kh, old);
            }
        }
      /* Print a note so that the user does not feel too helpless when
         an issuer certificate was found and gpgsm prints BAD
         signature because it is not the correct one. */
      if (rc == -1)
        {
          log_info ("issuer certificate (#");
          gpgsm_dump_serial (authidno);
          log_printf ("/");
          gpgsm_dump_string (s);
          log_printf (") not found\n");
        }
      else if (rc)
        log_error ("failed to find authorityKeyIdentifier: rc=%d\n", rc);
      ksba_name_release (authid);
      xfree (authidno);
      /* Fixme: don't know how to do dirmngr lookup with serial+issuer. */
    }
  
  if (rc) /* not found via authorithyKeyIdentifier, try regular issuer name */
    rc = keydb_search_subject (kh, issuer);
  if (rc == -1 && !find_next)
    {
      /* Not found, lets see whether we have one in the ephemeral key DB. */
      int old = keydb_set_ephemeral (kh, 1);
      if (!old)
        {
          keydb_search_reset (kh);
          rc = keydb_search_subject (kh, issuer);
        }
      keydb_set_ephemeral (kh, old);
    }

  if (rc == -1 && opt.auto_issuer_key_retrieve && !find_next)
    {
      STRLIST names = NULL;
      int count = 0;
      char *pattern;
      const char *s;
      
      if (opt.verbose)
        log_info (_("looking up issuer at external location\n"));
      /* dirmngr is confused about unknown attributes so as a quick
         and ugly hack we locate the CN and use this and the
         following.  Fixme: we should have far better parsing in the
         dirmngr. */
      s = strstr (issuer, "CN=");
      if (!s || s == issuer || s[-1] != ',')
        s = issuer;

      pattern = xtrymalloc (strlen (s)+2);
      if (!pattern)
        return OUT_OF_CORE (errno);
      strcpy (stpcpy (pattern, "/"), s);
      add_to_strlist (&names, pattern);
      xfree (pattern);
      rc = gpgsm_dirmngr_lookup (NULL, names, find_up_store_certs_cb, &count);
      free_strlist (names);
      if (opt.verbose)
        log_info (_("number of issuers matching: %d\n"), count);
      if (rc) 
        {
          log_error ("external key lookup failed: %s\n", gpg_strerror (rc));
          rc = -1;
        }
      else if (!count)
        rc = -1;
      else
        {
          int old;
          /* The issuers are currently stored in the ephemeral key
             DB, so we temporary switch to ephemeral mode. */
          old = keydb_set_ephemeral (kh, 1);
          keydb_search_reset (kh);
          rc = keydb_search_subject (kh, issuer);
          keydb_set_ephemeral (kh, old);
        }
    }
  return rc;
}


/* Return the next certificate up in the chain starting at START.
   Returns -1 when there are no more certificates. */
int
gpgsm_walk_cert_chain (ksba_cert_t start, ksba_cert_t *r_next)
{
  int rc = 0; 
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);

  *r_next = NULL;
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  issuer = ksba_cert_get_issuer (start, 0);
  subject = ksba_cert_get_subject (start, 0);
  if (!issuer)
    {
      log_error ("no issuer found in certificate\n");
      rc = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }
  if (!subject)
    {
      log_error ("no subject found in certificate\n");
      rc = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }

  if (!strcmp (issuer, subject))
    {
      rc = -1; /* we are at the root */
      goto leave; 
    }

  rc = find_up (kh, start, issuer, 0);
  if (rc)
    {
      /* it is quite common not to have a certificate, so better don't
         print an error here */
      if (rc != -1 && opt.verbose > 1)
        log_error ("failed to find issuer's certificate: rc=%d\n", rc);
      rc = gpg_error (GPG_ERR_MISSING_CERT);
      goto leave;
    }

  rc = keydb_get_cert (kh, r_next);
  if (rc)
    {
      log_error ("failed to get cert: rc=%d\n", rc);
      rc = gpg_error (GPG_ERR_GENERAL);
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
gpgsm_is_root_cert (ksba_cert_t cert)
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


/* This is a helper for gpgsm_validate_chain. */
static gpg_error_t 
is_cert_still_valid (ctrl_t ctrl, int lm, FILE *fp,
                     ksba_cert_t subject_cert, ksba_cert_t issuer_cert,
                     int *any_revoked, int *any_no_crl, int *any_crl_too_old)
{
  if (!opt.no_crl_check || ctrl->use_ocsp)
    {
      gpg_error_t err;

      err = gpgsm_dirmngr_isvalid (ctrl,
                                   subject_cert, issuer_cert, ctrl->use_ocsp);
      if (err)
        {
          /* Fixme: We should change the wording because we may
             have used OCSP. */
          switch (gpg_err_code (err))
            {
            case GPG_ERR_CERT_REVOKED:
              do_list (1, lm, fp, _("certificate has been revoked"));
              *any_revoked = 1;
              /* Store that in the keybox so that key listings are
                 able to return the revoked flag.  We don't care
                 about error, though. */
              keydb_set_cert_flags (subject_cert, KEYBOX_FLAG_VALIDITY, 0,
                                    VALIDITY_REVOKED);
              break;
            case GPG_ERR_NO_CRL_KNOWN:
              do_list (1, lm, fp, _("no CRL found for certificate"));
              *any_no_crl = 1;
              break;
            case GPG_ERR_CRL_TOO_OLD:
              do_list (1, lm, fp, _("the available CRL is too old"));
              if (!lm)
                log_info (_("please make sure that the "
                            "\"dirmngr\" is properly installed\n"));
              *any_crl_too_old = 1;
              break;
            default:
              do_list (1, lm, fp, _("checking the CRL failed: %s"),
                       gpg_strerror (err));
              return err;
            }
        }
    }
  return 0;
}



/* Validate a chain and optionally return the nearest expiration time
   in R_EXPTIME. With LISTMODE set to 1 a special listmode is
   activated where only information about the certificate is printed
   to FP and no output is send to the usual log stream. 

   Defined flag bits: 0 - do not do any dirmngr isvalid checks.
*/
int
gpgsm_validate_chain (ctrl_t ctrl, ksba_cert_t cert, ksba_isotime_t r_exptime,
                      int listmode, FILE *fp, unsigned int flags)
{
  int rc = 0, depth = 0, maxdepth;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);
  ksba_cert_t subject_cert = NULL, issuer_cert = NULL;
  ksba_isotime_t current_time;
  ksba_isotime_t exptime;
  int any_expired = 0;
  int any_revoked = 0;
  int any_no_crl = 0;
  int any_crl_too_old = 0;
  int any_no_policy_match = 0;
  int lm = listmode;

  gnupg_get_isotime (current_time);
  if (r_exptime)
    *r_exptime = 0;
  *exptime = 0;

  if (opt.no_chain_validation && !listmode)
    {
      log_info ("WARNING: bypassing certificate chain validation\n");
      return 0;
    }
  
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (DBG_X509 && !listmode)
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
          do_list (1, lm, fp,  _("no issuer found in certificate"));
          rc = gpg_error (GPG_ERR_BAD_CERT);
          goto leave;
        }

      {
        ksba_isotime_t not_before, not_after;

        rc = ksba_cert_get_validity (subject_cert, 0, not_before);
        if (!rc)
          rc = ksba_cert_get_validity (subject_cert, 1, not_after);
        if (rc)
          {
            do_list (1, lm, fp, _("certificate with invalid validity: %s"),
                     gpg_strerror (rc));
            rc = gpg_error (GPG_ERR_BAD_CERT);
            goto leave;
          }

        if (*not_after)
          {
            if (!*exptime)
              gnupg_copy_time (exptime, not_after);
            else if (strcmp (not_after, exptime) < 0 )
              gnupg_copy_time (exptime, not_after);
          }

        if (*not_before && strcmp (current_time, not_before) < 0 )
          {
            do_list (1, lm, fp, _("certificate not yet valid"));
            if (!lm)
              {
                log_info ("(valid from ");
                gpgsm_dump_time (not_before);
                log_printf (")\n");
              }
            rc = gpg_error (GPG_ERR_CERT_TOO_YOUNG);
            goto leave;
          }            
        if (*not_after && strcmp (current_time, not_after) > 0 )
          {
            do_list (opt.ignore_expiration?0:1, lm, fp,
                     _("certificate has expired"));
            if (!lm)
              {
                log_info ("(expired at ");
                gpgsm_dump_time (not_after);
                log_printf (")\n");
              }
            if (opt.ignore_expiration)
                log_info ("WARNING: ignoring expiration\n");
            else
              any_expired = 1;
          }            
      }

      rc = unknown_criticals (subject_cert, listmode, fp);
      if (rc)
        goto leave;

      if (!opt.no_policy_check)
        {
          rc = check_cert_policy (subject_cert, listmode, fp);
          if (gpg_err_code (rc) == GPG_ERR_NO_POLICY_MATCH)
            {
              any_no_policy_match = 1;
              rc = 1;
            }
          else if (rc)
            goto leave;
        }


      /* Is this a self-signed certificate? */
      if (subject && !strcmp (issuer, subject))
        {  /* Yes. */
          if (gpgsm_check_cert_sig (subject_cert, subject_cert) )
            {
              do_list (1, lm, fp,
                       _("selfsigned certificate has a BAD signature"));
              rc = gpg_error (depth? GPG_ERR_BAD_CERT_CHAIN
                                   : GPG_ERR_BAD_CERT);
              goto leave;
            }
          rc = allowed_ca (subject_cert, NULL, listmode, fp);
          if (rc)
            goto leave;

          rc = gpgsm_agent_istrusted (ctrl, subject_cert);
          if (!rc)
            ;
          else if (gpg_err_code (rc) == GPG_ERR_NOT_TRUSTED)
            {
              do_list (0, lm, fp, _("root certificate is not marked trusted"));
              if (!lm)
                {
                  int rc2;
                  char *fpr = gpgsm_get_fingerprint_string (subject_cert,
                                                            GCRY_MD_SHA1);
                  log_info (_("fingerprint=%s\n"), fpr? fpr : "?");
                  xfree (fpr);
                  rc2 = gpgsm_agent_marktrusted (ctrl, subject_cert);
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
                                "to add it manually to the list of trusted "
                                "certificates.\n");
                    }
                }
            }
          else 
            {
              log_error (_("checking the trust list failed: %s\n"),
                         gpg_strerror (rc));
            }
          
          /* Check for revocations etc. */
          if ((flags & 1))
            rc = 0;
          else
            rc = is_cert_still_valid (ctrl, lm, fp,
                                      subject_cert, subject_cert,
                                      &any_revoked, &any_no_crl,
                                      &any_crl_too_old);
          if (rc)
            goto leave;

          break;  /* Okay: a self-signed certicate is an end-point. */
        }
      
      depth++;
      if (depth > maxdepth)
        {
          do_list (1, lm, fp, _("certificate chain too long\n"));
          rc = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
          goto leave;
        }

      /* find the next cert up the tree */
      keydb_search_reset (kh);
      rc = find_up (kh, subject_cert, issuer, 0);
      if (rc)
        {
          if (rc == -1)
            {
              do_list (0, lm, fp, _("issuer certificate not found"));
              if (!lm)
                {
                  log_info ("issuer certificate: #/");
                  gpgsm_dump_string (issuer);
                  log_printf ("\n");
                }
            }
          else
            log_error ("failed to find issuer's certificate: rc=%d\n", rc);
          rc = gpg_error (GPG_ERR_MISSING_CERT);
          goto leave;
        }

      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_error ("failed to get cert: rc=%d\n", rc);
          rc = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

    try_another_cert:
      if (DBG_X509)
        {
          log_debug ("got issuer's certificate:\n");
          gpgsm_dump_cert ("issuer", issuer_cert);
        }

      rc = gpgsm_check_cert_sig (issuer_cert, subject_cert);
      if (rc)
        {
          do_list (0, lm, fp, _("certificate has a BAD signature"));
          if (gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE)
            {
              /* We now try to find other issuer certificates which
                 might have been used.  This is rquired because some
                 CAs are reusing the issuer and subject DN for new
                 root certificates. */
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

          /* We give a more descriptive error code than the one
             returned from the signature checking. */
          rc = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
          goto leave;
        }

      {
        int chainlen;
        rc = allowed_ca (issuer_cert, &chainlen, listmode, fp);
        if (rc)
          goto leave;
        if (chainlen >= 0 && (depth - 1) > chainlen)
          {
            do_list (1, lm, fp,
                     _("certificate chain longer than allowed by CA (%d)"),
                     chainlen);
            rc = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
            goto leave;
          }
      }

      if (!listmode)
        {
          rc = gpgsm_cert_use_cert_p (issuer_cert);
          if (rc)
            {
              char numbuf[50];
              sprintf (numbuf, "%d", rc);
              gpgsm_status2 (ctrl, STATUS_ERROR, "certcert.issuer.keyusage",
                             numbuf, NULL);
              goto leave;
            }
        }

      /* Check for revocations etc. */
      if ((flags & 1))
        rc = 0;
      else
        rc = is_cert_still_valid (ctrl, lm, fp,
                                  subject_cert, issuer_cert,
                                  &any_revoked, &any_no_crl, &any_crl_too_old);
      if (rc)
        goto leave;


      if (opt.verbose && !listmode)
        log_info ("certificate is good\n");
      
      keydb_search_reset (kh);
      subject_cert = issuer_cert;
      issuer_cert = NULL;
    }

  if (!listmode)
    {
      if (opt.no_policy_check)
        log_info ("policies not checked due to %s option\n",
                  "--disable-policy-checks");
      if (opt.no_crl_check && !ctrl->use_ocsp)
        log_info ("CRLs not checked due to %s option\n",
                  "--disable-crl-checks");
    }

  if (!rc)
    { /* If we encountered an error somewhere during the checks, set
         the error code to the most critical one */
      if (any_revoked)
        rc = gpg_error (GPG_ERR_CERT_REVOKED);
      else if (any_no_crl)
        rc = gpg_error (GPG_ERR_NO_CRL_KNOWN);
      else if (any_crl_too_old)
        rc = gpg_error (GPG_ERR_CRL_TOO_OLD);
      else if (any_no_policy_match)
        rc = gpg_error (GPG_ERR_NO_POLICY_MATCH);
      else if (any_expired)
        rc = gpg_error (GPG_ERR_CERT_EXPIRED);
    }
  
 leave:
  if (r_exptime)
    gnupg_copy_time (r_exptime, exptime);
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
gpgsm_basic_cert_check (ksba_cert_t cert)
{
  int rc = 0;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);
  ksba_cert_t issuer_cert = NULL;
  
  if (opt.no_chain_validation)
    {
      log_info ("WARNING: bypassing basic certificate checks\n");
      return 0;
    }

  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  issuer = ksba_cert_get_issuer (cert, 0);
  subject = ksba_cert_get_subject (cert, 0);
  if (!issuer)
    {
      log_error ("no issuer found in certificate\n");
      rc = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }

  if (subject && !strcmp (issuer, subject))
    {
      if (gpgsm_check_cert_sig (cert, cert) )
        {
          log_error ("selfsigned certificate has a BAD signature\n");
          rc = gpg_error (GPG_ERR_BAD_CERT);
          goto leave;
        }
    }
  else
    {
      /* find the next cert up the tree */
      keydb_search_reset (kh);
      rc = find_up (kh, cert, issuer, 0);
      if (rc)
        {
          if (rc == -1)
            {
              log_info ("issuer certificate (#/");
              gpgsm_dump_string (issuer);
              log_printf (") not found\n");
            }
          else
            log_error ("failed to find issuer's certificate: rc=%d\n", rc);
          rc = gpg_error (GPG_ERR_MISSING_CERT);
          goto leave;
        }
      
      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_error ("failed to get cert: rc=%d\n", rc);
          rc = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

      if (gpgsm_check_cert_sig (issuer_cert, cert) )
        {
          log_error ("certificate has a BAD signature\n");
          rc = gpg_error (GPG_ERR_BAD_CERT);
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

