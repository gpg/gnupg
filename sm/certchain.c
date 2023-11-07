/* certchain.c - certificate chain validation
 * Copyright (C) 2001, 2002, 2003, 2004, 2005,
 *               2006, 2007, 2008, 2011 Free Software Foundation, Inc.
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
#include <stdarg.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../kbx/keybox.h" /* for KEYBOX_FLAG_* */
#include "../common/i18n.h"
#include "../common/tlv.h"


/* The OID for the authorityInfoAccess's caIssuers.  */
static const char oidstr_caIssuers[] = "1.3.6.1.5.5.7.48.2";


/* Object to keep track of certain root certificates. */
struct marktrusted_info_s
{
  struct marktrusted_info_s *next;
  unsigned char fpr[20];
};
static struct marktrusted_info_s *marktrusted_info;


/* While running the validation function we want to keep track of the
   certificates in the chain.  This type is used for that.  */
struct chain_item_s
{
  struct chain_item_s *next;
  ksba_cert_t cert;      /* The certificate.  */
  int is_root;           /* The certificate is the root certificate.  */
};
typedef struct chain_item_s *chain_item_t;


static int is_root_cert (ksba_cert_t cert,
                         const char *issuerdn, const char *subjectdn);
static int get_regtp_ca_info (ctrl_t ctrl, ksba_cert_t cert, int *chainlen);


/* This function returns true if we already asked during this session
   whether the root certificate CERT shall be marked as trusted.  */
static int
already_asked_marktrusted (ksba_cert_t cert)
{
  unsigned char fpr[20];
  struct marktrusted_info_s *r;

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, fpr, NULL);
  /* No context switches in the loop! */
  for (r=marktrusted_info; r; r= r->next)
    if (!memcmp (r->fpr, fpr, 20))
      return 1;
  return 0;
}

/* Flag certificate CERT as already asked whether it shall be marked
   as trusted.  */
static void
set_already_asked_marktrusted (ksba_cert_t cert)
{
 unsigned char fpr[20];
 struct marktrusted_info_s *r;

 gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, fpr, NULL);
 for (r=marktrusted_info; r; r= r->next)
   if (!memcmp (r->fpr, fpr, 20))
     return; /* Already marked. */
 r = xtrycalloc (1, sizeof *r);
 if (!r)
   return;
 memcpy (r->fpr, fpr, 20);
 r->next = marktrusted_info;
 marktrusted_info = r;
}

/* If LISTMODE is true, print FORMAT using LISTMODE to FP.  If
   LISTMODE is false, use the string to print an log_info or, if
   IS_ERROR is true, and log_error. */
static void
do_list (int is_error, int listmode, estream_t fp, const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format) ;
  if (listmode)
    {
      if (fp)
        {
          es_fputs ("  [", fp);
          es_vfprintf (fp, format, arg_ptr);
          es_fputs ("]\n", fp);
        }
    }
  else
    {
      es_fflush (es_stdout);
      log_logv (is_error? GPGRT_LOGLVL_ERROR: GPGRT_LOGLVL_INFO,
                format, arg_ptr);
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


/* Return true if CERT has the validityModel extensions and defines
   the use of the chain model.  */
static int
has_validation_model_chain (ksba_cert_t cert, int listmode, estream_t listfp)
{
  gpg_error_t err;
  int idx, yes;
  const char *oid;
  size_t off, derlen, objlen, hdrlen;
  const unsigned char *der;
  int class, tag, constructed, ndef;
  char *oidbuf;

  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, NULL, &off, &derlen));idx++)
    if (!strcmp (oid, "1.3.6.1.4.1.8301.3.5") )
      break;
  if (err)
    return 0; /* Not found.  */
  der = ksba_cert_get_image (cert, NULL);
  if (!der)
    {
      err = gpg_error (GPG_ERR_INV_OBJ); /* Oops  */
      goto leave;
    }
  der += off;

  err = parse_ber_header (&der, &derlen, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > derlen || tag != TAG_SEQUENCE))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;
  derlen = objlen;
  err = parse_ber_header (&der, &derlen, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > derlen || tag != TAG_OBJECT_ID))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;
  oidbuf = ksba_oid_to_str (der, objlen);
  if (!oidbuf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (opt.verbose)
    do_list (0, listmode, listfp,
             _("validation model requested by certificate: %s"),
              !strcmp (oidbuf, "1.3.6.1.4.1.8301.3.5.1")? _("chain") :
              !strcmp (oidbuf, "1.3.6.1.4.1.8301.3.5.2")? _("shell") :
              /* */                                       oidbuf);
  yes = !strcmp (oidbuf, "1.3.6.1.4.1.8301.3.5.1");
  ksba_free (oidbuf);
  return yes;


 leave:
  log_error ("error parsing validityModel: %s\n", gpg_strerror (err));
  return 0;
}



static int
unknown_criticals (ksba_cert_t cert, int listmode, estream_t fp)
{
  static const char *known[] = {
    "2.5.29.15", /* keyUsage */
    "2.5.29.17", /* subjectAltName
                    Japanese DoCoMo certs mark them as critical.  PKIX
                    only requires them as critical if subjectName is
                    empty.  I don't know whether our code gracefully
                    handles such empry subjectNames but that is
                    another story. */
    "2.5.29.19", /* basic Constraints */
    "2.5.29.32", /* certificatePolicies */
    "2.5.29.37", /* extendedKeyUsage - handled by certlist.c */
    "1.3.6.1.4.1.8301.3.5", /* validityModel - handled here. */
    NULL
  };
  int rc = 0, i, idx, crit;
  const char *oid;
  gpg_error_t err;
  int unsupported;
  strlist_t sl;

  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &crit, NULL, NULL));idx++)
    {
      if (!crit)
        continue;
      for (i=0; known[i] && strcmp (known[i],oid); i++)
        ;
      unsupported = !known[i];

      /* If this critical extension is not supported.  Check the list
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
          do_list (1, listmode, fp,
                   _("critical certificate extension %s is not supported"),
                   oid);
          rc = gpg_error (GPG_ERR_UNSUPPORTED_CERT);
        }
    }
  /* We ignore the error codes EOF as well as no-value. The later will
     occur for certificates with no extensions at all. */
  if (err
      && gpg_err_code (err) != GPG_ERR_EOF
      && gpg_err_code (err) != GPG_ERR_NO_VALUE)
    rc = err;

  return rc;
}


/* Check whether CERT is an allowed certificate.  This requires that
   CERT matches all requirements for such a CA, i.e. the
   BasicConstraints extension.  The function returns 0 on success and
   the allowed length of the chain at CHAINLEN. */
static int
allowed_ca (ctrl_t ctrl,
            ksba_cert_t cert, int *chainlen, int listmode, estream_t fp)
{
  gpg_error_t err;
  int flag;

  err = ksba_cert_is_ca (cert, &flag, chainlen);
  if (err)
    return err;
  if (!flag)
    {
      if (get_regtp_ca_info (ctrl, cert, chainlen))
        {
          /* Note that dirmngr takes a different way to cope with such
             certs. */
          return 0; /* RegTP issued certificate. */
        }

      do_list (1, listmode, fp,_("issuer certificate is not marked as a CA"));
      return gpg_error (GPG_ERR_BAD_CA_CERT);
    }
  return 0;
}


static int
check_cert_policy (ksba_cert_t cert, int listmode, estream_t fplist)
{
  static int no_policy_file;
  gpg_error_t err;
  char *policies;
  estream_t fp;
  int any_critical;

  err = ksba_cert_get_cert_policies (cert, &policies);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return 0; /* No policy given. */
  if (err)
    return err;

  /* STRING is a line delimited list of certificate policies as stored
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

  if (no_policy_file)
    {
      /* Avoid trying to open the policy file if we already know that
       * it does not exist.  */
      fp = NULL;
      gpg_err_set_errno (ENOENT);
    }
  else
    fp = es_fopen (opt.policy_file, "r");
  if (!fp)
    {
      if ((opt.verbose || errno != ENOENT) && !no_policy_file)
        log_info (_("failed to open '%s': %s\n"),
                  opt.policy_file, strerror (errno));

      if (errno == ENOENT)
        no_policy_file = 1;

      xfree (policies);
      /* With no critical policies this is only a warning */
      if (!any_critical)
        {
          if (opt.verbose)
            do_list (0, listmode, fplist,
                     _("Note: non-critical certificate policy not allowed"));
          return 0;
        }
      do_list (1, listmode, fplist,
               _("certificate policy not allowed"));
      return gpg_error (GPG_ERR_NO_POLICY_MATCH);
    }

  /* FIXME: Cache the policy file content.  */

  for (;;)
    {
      int c;
      char *p, line[256];
      char *haystack, *allowed;

      /* read line */
      do
        {
          if (!es_fgets (line, DIM(line)-1, fp) )
            {
              gpg_error_t tmperr = gpg_error_from_syserror ();

              xfree (policies);
              if (es_feof (fp))
                {
                  es_fclose (fp);
                  /* With no critical policies this is only a warning */
                  if (!any_critical)
                    {
                      if (opt.verbose)
                        do_list (0, listmode, fplist,
                     _("Note: non-critical certificate policy not allowed"));
                      return 0;
                    }
                  do_list (1, listmode, fplist,
                           _("certificate policy not allowed"));
                  return gpg_error (GPG_ERR_NO_POLICY_MATCH);
                }
              es_fclose (fp);
              return tmperr;
            }

          if (!*line || line[strlen(line)-1] != '\n')
            {
              /* eat until end of line */
              while ((c = es_getc (fp)) != EOF && c != '\n')
                ;
              es_fclose (fp);
              xfree (policies);
              return gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                                     : GPG_ERR_INCOMPLETE_LINE);
            }

          /* Allow for empty lines and spaces */
          for (p=line; spacep (p); p++)
            ;
        }
      while (!*p || *p == '\n' || *p == '#');

      /* Parse line.  Note that the line has always a LF and spacep
         does not consider a LF a space.  Thus strpbrk will always
         succeed.  */
      for (allowed=line; spacep (allowed); allowed++)
        ;
      p = strpbrk (allowed, " :\n");
      if (!*p || p == allowed)
        {
          es_fclose (fp);
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
          es_fclose (fp);
          xfree (policies);
          return 0;
        }
    }
}


/* Helper function for find_up.  This resets the key handle and search
   for an issuer ISSUER with a subjectKeyIdentifier of KEYID.  Returns
   0 on success or GPG_ERR_NOT_FOUND when not found. */
static int
find_up_search_by_keyid (ctrl_t ctrl, KEYDB_HANDLE kh,
                         const char *issuer, ksba_sexp_t keyid)
{
  int rc;
  ksba_cert_t cert = NULL;
  ksba_sexp_t subj = NULL;
  ksba_isotime_t not_before, not_after, last_not_before, ne_last_not_before;
  ksba_cert_t found_cert = NULL;
  ksba_cert_t ne_found_cert = NULL;

  keydb_search_reset (kh);
  while (!(rc = keydb_search_subject (ctrl, kh, issuer)))
    {
      ksba_cert_release (cert); cert = NULL;
      rc = keydb_get_cert (kh, &cert);
      if (rc)
        {
          log_error ("keydb_get_cert failed in %s: %s <%s>\n",
                     __func__, gpg_strerror (rc), gpg_strsource (rc));
          rc = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
      xfree (subj);
      if (!ksba_cert_get_subj_key_id (cert, NULL, &subj))
        {
          if (!cmp_simple_canon_sexp (keyid, subj))
            {
              /* Found matching cert. */
              rc = ksba_cert_get_validity (cert, 0, not_before);
              if (!rc)
                rc = ksba_cert_get_validity (cert, 1, not_after);
              if (rc)
                {
                  log_error ("keydb_get_validity() failed: rc=%d\n", rc);
                  rc = gpg_error (GPG_ERR_NOT_FOUND);
                  goto leave;
                }

              if (!found_cert
                  || strcmp (last_not_before, not_before) < 0)
                {
                  /* This certificate is the first one found or newer
                   * than the previous one.  This copes with
                   * re-issuing CA certificates while keeping the same
                   * key information.  */
                  gnupg_copy_time (last_not_before, not_before);
                  ksba_cert_release (found_cert);
                  ksba_cert_ref ((found_cert = cert));
                  keydb_push_found_state (kh);
                }

              if (*not_after && strcmp (ctrl->current_time, not_after) > 0 )
                ; /* CERT has expired - don't consider it.  */
              else if (!ne_found_cert
                       || strcmp (ne_last_not_before, not_before) < 0)
                {
                  /* This certificate is the first non-expired one
                   * found or newer than the previous non-expired one.  */
                  gnupg_copy_time (ne_last_not_before, not_before);
                  ksba_cert_release (ne_found_cert);
                  ksba_cert_ref ((ne_found_cert = cert));
                }
            }
        }
    }

  if (!found_cert)
    goto leave;

  /* Take the last saved one.  Note that push/pop_found_state are
   * misnomers because there is no stack of states.  Renaming them to
   * save/restore_found_state would be better.  */
  keydb_pop_found_state (kh);
  rc = 0;  /* Ignore EOF or other error after the first cert.  */

  /* We need to consider some corner cases.  It is possible that we
   * have a long term certificate (e.g. valid from 2008 to 2033) as
   * well as a re-issued (i.e. using the same key material) short term
   * certificate (say from 2016 to 2019).  Using the short term
   * certificate is the proper solution.  But we need to take care if
   * there is no re-issued new short term certificate (e.g. from 2020
   * to 2023) available.  In that case it is better to use the long
   * term certificate which is still valid.  The code may run into
   * minor problems in the case of the chain validation mode.  Given
   * that this corner case is due to non-diligent PKI management we
   * ignore this problem.  */

  /* The most common case is that the found certificate is not expired
   * and thus identical to the one found from the list of non-expired
   * certs.  We can stop here.  */
  if (found_cert == ne_found_cert)
    goto leave;
  /* If we do not have a non expired certificate the actual cert is
   * expired and we can also stop here.  */
  if (!ne_found_cert)
    goto leave;
  /* Now we need to see whether the found certificate is expired and
   * only in this case we return the certificate found in the list of
   * non-expired certs.  */
  rc = ksba_cert_get_validity (found_cert, 1, not_after);
  if (rc)
    {
      log_error ("keydb_get_validity() failed: rc=%d\n", rc);
      rc = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }
  if (*not_after && strcmp (ctrl->current_time, not_after) > 0 )
    { /* CERT has expired.  Use the NE_FOUND_CERT.  Because we have no
       * found state for this we need to search for it again.  */
      unsigned char fpr[20];

      gpgsm_get_fingerprint (ne_found_cert, GCRY_MD_SHA1, fpr, NULL);
      keydb_search_reset (kh);
      rc = keydb_search_fpr (ctrl, kh, fpr);
      if (rc)
        {
          log_error ("keydb_search_fpr() failed: rc=%d\n", rc);
          rc = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
      /* Ready.  The NE_FOUND_CERT is available via keydb_get_cert.  */
    }

 leave:
  ksba_cert_release (found_cert);
  ksba_cert_release (ne_found_cert);
  ksba_cert_release (cert);
  xfree (subj);
  return rc? gpg_error (GPG_ERR_NOT_FOUND) : 0;
}


struct find_up_store_certs_s
{
  ctrl_t ctrl;
  int count;
  unsigned int want_fpr:1;
  unsigned int got_fpr:1;
  unsigned char fpr[20];
};

static void
find_up_store_certs_cb (void *cb_value, ksba_cert_t cert)
{
  struct find_up_store_certs_s *parm = cb_value;

  if (keydb_store_cert (parm->ctrl, cert, 1, NULL))
    log_error ("error storing issuer certificate as ephemeral\n");
  else if (parm->want_fpr && !parm->got_fpr)
    {
      if (!gpgsm_get_fingerprint (cert, 0, parm->fpr, NULL))
        log_error (_("failed to get the fingerprint\n"));
      else
        parm->got_fpr = 1;
    }
  parm->count++;
}


/* Helper for find_up().  Locate the certificate for ISSUER using an
   external lookup.  KH is the keydb context we are currently using.
   On success 0 is returned and the certificate may be retrieved from
   the keydb using keydb_get_cert().  KEYID is the keyIdentifier from
   the AKI or NULL.  */
static int
find_up_external (ctrl_t ctrl, KEYDB_HANDLE kh,
                  const char *issuer, ksba_sexp_t keyid)
{
  int rc;
  strlist_t names = NULL;
  struct find_up_store_certs_s find_up_store_certs_parm;
  char *pattern;
  const char *s;

  find_up_store_certs_parm.ctrl = ctrl;
  find_up_store_certs_parm.want_fpr = 0;
  find_up_store_certs_parm.got_fpr = 0;
  find_up_store_certs_parm.count = 0;

  if (opt.verbose)
    log_info (_("looking up issuer at external location\n"));
  /* The Dirmngr process is confused about unknown attributes.  As a
     quick and ugly hack we locate the CN and use the issuer string
     starting at this attribite.  Fixme: we should have far better
     parsing for external lookups in the Dirmngr. */
  s = strstr (issuer, "CN=");
  if (!s || s == issuer || s[-1] != ',')
    s = issuer;
  pattern = xtrymalloc (strlen (s)+2);
  if (!pattern)
    return gpg_error_from_syserror ();
  strcpy (stpcpy (pattern, "/"), s);
  add_to_strlist (&names, pattern);
  xfree (pattern);

  rc = gpgsm_dirmngr_lookup (ctrl, names, NULL, 0, find_up_store_certs_cb,
                             &find_up_store_certs_parm);
  free_strlist (names);

  if (opt.verbose)
    log_info (_("number of issuers matching: %d\n"),
              find_up_store_certs_parm.count);
  if (rc)
    {
      log_error ("external key lookup failed: %s\n", gpg_strerror (rc));
      rc = gpg_error (GPG_ERR_NOT_FOUND);
    }
  else if (!find_up_store_certs_parm.count)
    rc = gpg_err_code (rc) == GPG_ERR_NOT_FOUND;
  else
    {
      int old;
      /* The issuers are currently stored in the ephemeral key DB, so
         we temporary switch to ephemeral mode. */
      old = keydb_set_ephemeral (kh, 1);
      if (keyid)
        rc = find_up_search_by_keyid (ctrl, kh, issuer, keyid);
      else
        {
          keydb_search_reset (kh);
          rc = keydb_search_subject (ctrl, kh, issuer);
        }
      keydb_set_ephemeral (kh, old);
    }
  return rc;
}


/* Helper for find_up().  Locate the certificate for CERT using the
 * caIssuer from the authorityInfoAccess.  KH is the keydb context we
 * are currently using.  On success 0 is returned and the certificate
 * may be retrieved from the keydb using keydb_get_cert().  If no
 * suitable authorityInfoAccess is encoded in the certificate
 * GPG_ERR_NOT_FOUND is returned. */
static gpg_error_t
find_up_via_auth_info_access (ctrl_t ctrl, KEYDB_HANDLE kh, ksba_cert_t cert)
{
  gpg_error_t err;
  struct find_up_store_certs_s find_up_store_certs_parm;
  char *url, *ldapurl;
  int idx, i;
  char *oid;
  ksba_name_t name;

  find_up_store_certs_parm.ctrl = ctrl;
  find_up_store_certs_parm.want_fpr = 1;
  find_up_store_certs_parm.got_fpr = 0;
  find_up_store_certs_parm.count = 0;

  /* Find suitable URLs; if there is a http scheme we prefer that.  */
  url = ldapurl = NULL;
  for (idx=0;
       !url && !(err = ksba_cert_get_authority_info_access (cert, idx,
                                                            &oid, &name));
       idx++)
    {
      if (!strcmp (oid, oidstr_caIssuers))
        {
          for (i=0; !url && ksba_name_enum (name, i); i++)
            {
              char *p = ksba_name_get_uri (name, i);
              if (p)
                {
                  if (!strncmp (p, "http:", 5) || !strncmp (p, "https:", 6))
                    url = p;
                  else if (ldapurl)
                    xfree (p); /* We already got one.  */
                  else if (!strncmp (p, "ldap:",5) || !strncmp (p, "ldaps:",6))
                    ldapurl = p;
                }
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
      return err;
    }
  if (!url && ldapurl)
    {
      /* No HTTP scheme; fallback to LDAP if available.  */
      url = ldapurl;
      ldapurl = NULL;
    }
  xfree (ldapurl);
  if (!url)
    return gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.verbose)
    log_info ("looking up issuer via authorityInfoAccess.caIssuers\n");

  err = gpgsm_dirmngr_lookup (ctrl, NULL, url, 0, find_up_store_certs_cb,
                              &find_up_store_certs_parm);

  /* Although we might receive several certificates we use only the
   * first one.  Or more exacty the first one for which we retrieved
   * the fingerprint.  */
  if (opt.verbose)
    log_info ("number of caIssuers found: %d\n",
              find_up_store_certs_parm.count);
  if (err)
    {
      log_error ("external URL lookup failed: %s\n", gpg_strerror (err));
      err = gpg_error (GPG_ERR_NOT_FOUND);
    }
  else if (!find_up_store_certs_parm.got_fpr)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  else
    {
      int old;
      /* The retrieved certificates are currently stored in the
       * ephemeral key DB, so we temporary switch to ephemeral
       * mode. */
      old = keydb_set_ephemeral (kh, 1);
      keydb_search_reset (kh);
      err = keydb_search_fpr (ctrl, kh, find_up_store_certs_parm.fpr);
      keydb_set_ephemeral (kh, old);
    }

  return err;
}


/* Helper for find_up().  Ask the dirmngr for the certificate for
   ISSUER with optional SERIALNO.  KH is the keydb context we are
   currently using.  With SUBJECT_MODE set, ISSUER is searched as the
   subject.  On success 0 is returned and the certificate is available
   in the ephemeral DB.  */
static int
find_up_dirmngr (ctrl_t ctrl, KEYDB_HANDLE kh,
                 ksba_sexp_t serialno, const char *issuer, int subject_mode)
{
  int rc;
  strlist_t names = NULL;
  struct find_up_store_certs_s find_up_store_certs_parm;
  char *pattern;

  (void)kh;

  find_up_store_certs_parm.ctrl = ctrl;
  find_up_store_certs_parm.count = 0;

  if (opt.verbose)
    log_info (_("looking up issuer from the Dirmngr cache\n"));
  if (subject_mode)
    {
      pattern = xtrymalloc (strlen (issuer)+2);
      if (pattern)
        strcpy (stpcpy (pattern, "/"), issuer);
    }
  else if (serialno)
    pattern = gpgsm_format_sn_issuer (serialno, issuer);
  else
    {
      pattern = xtrymalloc (strlen (issuer)+3);
      if (pattern)
        strcpy (stpcpy (pattern, "#/"), issuer);
    }
  if (!pattern)
    return gpg_error_from_syserror ();
  add_to_strlist (&names, pattern);
  xfree (pattern);

  rc = gpgsm_dirmngr_lookup (ctrl, names, NULL, 1, find_up_store_certs_cb,
                             &find_up_store_certs_parm);
  free_strlist (names);

  if (opt.verbose)
    log_info (_("number of matching certificates: %d\n"),
              find_up_store_certs_parm.count);
  if (rc && opt.verbose)
    log_info (_("dirmngr cache-only key lookup failed: %s\n"),
              gpg_strerror (rc));
  return ((!rc && find_up_store_certs_parm.count)
          ? 0 : gpg_error (GPG_ERR_NOT_FOUND));
}



/* Locate issuing certificate for CERT. ISSUER is the name of the
   issuer used as a fallback if the other methods don't work.  If
   FIND_NEXT is true, the function shall return the next possible
   issuer.  The certificate itself is not directly returned but a
   keydb_get_cert on the keydb context KH will return it.  Returns 0
   on success, GPG_ERR_NOT_FOUND if not found or another error code.  */
static gpg_error_t
find_up (ctrl_t ctrl, KEYDB_HANDLE kh,
         ksba_cert_t cert, const char *issuer, int find_next)
{
  ksba_name_t authid;
  ksba_sexp_t authidno;
  ksba_sexp_t keyid;
  gpg_error_t err = gpg_error (GPG_ERR_NOT_FOUND);

  if (DBG_X509)
    log_debug ("looking for parent certificate\n");
  if (!ksba_cert_get_auth_key_id (cert, &keyid, &authid, &authidno))
    {
      const char *s = ksba_name_enum (authid, 0);
      if (s && *authidno)
        {
          err = keydb_search_issuer_sn (ctrl, kh, s, authidno);
          if (err)
            keydb_search_reset (kh);

          if (!err && DBG_X509)
            log_debug ("  found via authid and sn+issuer\n");

          /* In case of an error, try to get the certificate from the
             dirmngr.  That is done by trying to put that certificate
             into the ephemeral DB and let the code below do the
             actual retrieve.  Thus there is no error checking.
             Skipped in find_next mode as usual. */
          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && !find_next)
            find_up_dirmngr (ctrl, kh, authidno, s, 0);

          /* In case of an error try the ephemeral DB.  We can't do
             that in find_next mode because we can't keep the search
             state then. */
          if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && !find_next)
            {
              int old = keydb_set_ephemeral (kh, 1);
              if (!old)
                {
                  err = keydb_search_issuer_sn (ctrl, kh, s, authidno);
                  if (err)
                    keydb_search_reset (kh);

                  if (!err && DBG_X509)
                    log_debug ("  found via authid and sn+issuer (ephem)\n");
                }
              keydb_set_ephemeral (kh, old);
            }
          if (err) /* Need to make sure to have this error code. */
            err = gpg_error (GPG_ERR_NOT_FOUND);
        }

      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && keyid && !find_next)
        {
          /* Not found by AKI.issuer_sn.  Lets try the AKI.ki
             instead. Loop over all certificates with that issuer as
             subject and stop for the one with a matching
             subjectKeyIdentifier. */
          /* Fixme: Should we also search in the dirmngr?  */
          err = find_up_search_by_keyid (ctrl, kh, issuer, keyid);
          if (!err && DBG_X509)
            log_debug ("  found via authid and keyid\n");
          if (err)
            {
              int old = keydb_set_ephemeral (kh, 1);
              if (!old)
                err = find_up_search_by_keyid (ctrl, kh, issuer, keyid);
              if (!err && DBG_X509)
                log_debug ("  found via authid and keyid (ephem)\n");
              keydb_set_ephemeral (kh, old);
            }
          if (err) /* Need to make sure to have this error code. */
            err = gpg_error (GPG_ERR_NOT_FOUND);
        }

      /* If we still didn't found it, try to find it via the subject
         from the dirmngr-cache.  */
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && !find_next)
        {
          if (!find_up_dirmngr (ctrl, kh, NULL, issuer, 1))
            {
              int old = keydb_set_ephemeral (kh, 1);
              if (keyid)
                err = find_up_search_by_keyid (ctrl, kh, issuer, keyid);
              else
                {
                  keydb_search_reset (kh);
                  err = keydb_search_subject (ctrl, kh, issuer);
                }
              keydb_set_ephemeral (kh, old);
            }
          if (err) /* Need to make sure to have this error code. */
            err = gpg_error (GPG_ERR_NOT_FOUND);

          if (!err && DBG_X509)
            log_debug ("  found via authid and issuer from dirmngr cache\n");
        }

      /* If we still didn't found it, try an external lookup.  */
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND
          && !find_next && !ctrl->offline)
        {
          /* We allow AIA also if CRLs are enabled; both can be used
           * as a web bug so it does not make sense to not use AIA if
           * CRL checks are enabled.  */
          if ((opt.auto_issuer_key_retrieve || !opt.no_crl_check)
              && !find_up_via_auth_info_access (ctrl, kh, cert))
            {
              if (DBG_X509)
                log_debug ("  found via authorityInfoAccess.caIssuers\n");
              err = 0;
            }
          else if (opt.auto_issuer_key_retrieve)
            {
              err = find_up_external (ctrl, kh, issuer, keyid);
              if (!err && DBG_X509)
                log_debug ("  found via authid and external lookup\n");
            }
        }


      /* Print a note so that the user does not feel too helpless when
         an issuer certificate was found and gpgsm prints BAD
         signature because it is not the correct one. */
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && opt.quiet)
        ;
      else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
        {
          if (!opt.quiet)
            {
              log_info ("%sissuer certificate ", find_next?"next ":"");
              if (keyid)
                {
                  log_printf ("{");
                  gpgsm_dump_serial (keyid);
                  log_printf ("} ");
                }
              if (authidno)
                {
                  log_printf ("(#");
                  gpgsm_dump_serial (authidno);
                  log_printf ("/");
                  gpgsm_dump_string (s);
                  log_printf (") ");
                }
              log_printf ("not found using authorityKeyIdentifier\n");
            }
        }
      else if (err)
        log_error ("failed to find authorityKeyIdentifier: err=%d\n", err);
      xfree (keyid);
      ksba_name_release (authid);
      xfree (authidno);
    }

  if (err) /* Not found via authorithyKeyIdentifier, try regular issuer name. */
    err = keydb_search_subject (ctrl, kh, issuer);
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && !find_next)
    {
      int old;

      /* Also try to get it from the Dirmngr cache.  The function
         merely puts it into the ephemeral database.  */
      find_up_dirmngr (ctrl, kh, NULL, issuer, 0);

      /* Not found, let us see whether we have one in the ephemeral key DB. */
      old = keydb_set_ephemeral (kh, 1);
      if (!old)
        {
          keydb_search_reset (kh);
          err = keydb_search_subject (ctrl, kh, issuer);
        }
      keydb_set_ephemeral (kh, old);

      if (!err && DBG_X509)
        log_debug ("  found via issuer\n");
    }

  /* Still not found.  If enabled, try an external lookup.  */
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND && !find_next && !ctrl->offline)
    {
      if ((opt.auto_issuer_key_retrieve || !opt.no_crl_check)
          && !find_up_via_auth_info_access (ctrl, kh, cert))
        {
          if (DBG_X509)
            log_debug ("  found via authorityInfoAccess.caIssuers\n");
          err = 0;
        }
      else if (opt.auto_issuer_key_retrieve)
        {
          err = find_up_external (ctrl, kh, issuer, NULL);
          if (!err && DBG_X509)
            log_debug ("  found via issuer and external lookup\n");
        }
    }

  return err;
}


/* Return the next certificate up in the chain starting at START.
   Returns GPG_ERR_NOT_FOUND when there are no more certificates. */
gpg_error_t
gpgsm_walk_cert_chain (ctrl_t ctrl, ksba_cert_t start, ksba_cert_t *r_next)
{
  gpg_error_t err = 0;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (ctrl);

  *r_next = NULL;
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  issuer = ksba_cert_get_issuer (start, 0);
  subject = ksba_cert_get_subject (start, 0);
  if (!issuer)
    {
      log_error ("no issuer found in certificate\n");
      err = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }
  if (!subject)
    {
      log_error ("no subject found in certificate\n");
      err = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }

  if (is_root_cert (start, issuer, subject))
    {
      err = gpg_error (GPG_ERR_NOT_FOUND); /* we are at the root */
      goto leave;
    }

  err = find_up (ctrl, kh, start, issuer, 0);
  if (err)
    {
      /* It is quite common not to have a certificate, so better don't
         print an error here.  */
      if (gpg_err_code (err) != GPG_ERR_NOT_FOUND && opt.verbose > 1)
        log_error ("failed to find issuer's certificate: %s <%s>\n",
                   gpg_strerror (err), gpg_strsource (err));
      err = gpg_error (GPG_ERR_MISSING_ISSUER_CERT);
      goto leave;
    }

  err = keydb_get_cert (kh, r_next);
  if (err)
    {
      log_error ("keydb_get_cert failed in %s: %s <%s>\n",
                 __func__, gpg_strerror (err), gpg_strsource (err));
      err = gpg_error (GPG_ERR_GENERAL);
    }

 leave:
  xfree (issuer);
  xfree (subject);
  keydb_release (kh);
  return err;
}


/* Helper for gpgsm_is_root_cert.  This one is used if the subject and
   issuer DNs are already known.  */
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
  yes = is_root_cert (cert, issuer, subject);
  xfree (issuer);
  xfree (subject);
  return yes;
}


/* This is a helper for gpgsm_validate_chain. */
static gpg_error_t
is_cert_still_valid (ctrl_t ctrl, int chain_model, int lm, estream_t fp,
                     ksba_cert_t subject_cert, ksba_cert_t issuer_cert,
                     int *any_revoked, int *any_no_crl, int *any_crl_too_old)
{
  gpg_error_t err;
  gnupg_isotime_t revoked_at;
  char *reason;

  if (ctrl->offline || (opt.no_crl_check && !ctrl->use_ocsp))
    {
      audit_log_ok (ctrl->audit, AUDIT_CRL_CHECK,
                    gpg_error (GPG_ERR_NOT_ENABLED));
      return 0;
    }


  if (!(chain_model || ctrl->use_ocsp)
      && !opt.enable_issuer_based_crl_check)
    {
      err = ksba_cert_get_crl_dist_point (subject_cert, 0, NULL, NULL, NULL);
      if (gpg_err_code (err) == GPG_ERR_EOF)
        {
          /* No DP specified in the certificate.  Thus the CA does not
           * consider a CRL useful and the user of the certificate
           * also does not consider this to be a critical thing.  In
           * this case we can conclude that the certificate shall not
           * be revocable.  Note that we reach this point here only if
           * no OCSP responder shall be used.  */
          audit_log_ok (ctrl->audit, AUDIT_CRL_CHECK, gpg_error (GPG_ERR_TRUE));
          return 0;
        }
    }

  err = gpgsm_dirmngr_isvalid (ctrl,
                               subject_cert, issuer_cert,
                               chain_model? 2 : !!ctrl->use_ocsp,
                               revoked_at, &reason);
  if (gpg_err_code (err) == GPG_ERR_CERT_REVOKED)
    {
      gnupg_copy_time (ctrl->revoked_at, revoked_at);
      xfree (ctrl->revocation_reason);
      ctrl->revocation_reason = reason;
      reason = NULL;
    }
  else
    {
      xfree (reason);
      reason = (NULL);
    }
  audit_log_ok (ctrl->audit, AUDIT_CRL_CHECK, err);

  if (err)
    {
      if (!lm)
        gpgsm_cert_log_name (NULL, subject_cert);
      switch (gpg_err_code (err))
        {
        case GPG_ERR_CERT_REVOKED:
          if (!check_isotime (ctrl->revoked_at))
            {
              char *tmpstr;
              const unsigned char *t = ctrl->revoked_at;

              tmpstr = xtryasprintf ("%.4s-%.2s-%.2s %.2s:%.2s:%s (%s)",
                                     t, t+4, t+6, t+9, t+11, t+13,
                                     ctrl->revocation_reason?
                                     ctrl->revocation_reason : "");

              do_list (1, lm, fp, "%s: %s",
                       _("certificate has been revoked"), tmpstr);
              xfree (tmpstr);
            }
          else
            do_list (1, lm, fp, _("certificate has been revoked"));
          *any_revoked = 1;
          /* Store that in the keybox so that key listings are able to
             return the revoked flag.  We don't care about error,
             though. */
          keydb_set_cert_flags (ctrl, subject_cert, 1, KEYBOX_FLAG_VALIDITY, 0,
                                ~0, VALIDITY_REVOKED);
          break;

        case GPG_ERR_NO_CRL_KNOWN:
          do_list (1, lm, fp, _("no CRL found for certificate"));
          *any_no_crl = 1;
          break;

        case GPG_ERR_NO_DATA:
          do_list (1, lm, fp, _("the status of the certificate is unknown"));
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
  return 0;
}


/* Helper for gpgsm_validate_chain to check the validity period of
   SUBJECT_CERT.  The caller needs to pass EXPTIME which will be
   updated to the nearest expiration time seen.  A DEPTH of 0 indicates
   the target certificate, -1 the final root certificate and other
   values intermediate certificates. */
static gpg_error_t
check_validity_period (ksba_isotime_t current_time,
                       ksba_cert_t subject_cert,
                       ksba_isotime_t exptime,
                       int listmode, estream_t listfp, int depth)
{
  gpg_error_t err;
  ksba_isotime_t not_before, not_after;

  err = ksba_cert_get_validity (subject_cert, 0, not_before);
  if (!err)
    err = ksba_cert_get_validity (subject_cert, 1, not_after);
  if (err)
    {
      do_list (1, listmode, listfp,
               _("certificate with invalid validity: %s"), gpg_strerror (err));
      return gpg_error (GPG_ERR_BAD_CERT);
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
      do_list (1, listmode, listfp,
               depth ==  0 ? _("certificate not yet valid") :
               depth == -1 ? _("root certificate not yet valid") :
               /* other */   _("intermediate certificate not yet valid"));
      if (!listmode)
        {
          log_info ("  (valid from ");
          dump_isotime (not_before);
          log_printf (")\n");
        }
      return gpg_error (GPG_ERR_CERT_TOO_YOUNG);
    }

  if (*not_after && strcmp (current_time, not_after) > 0 )
    {
      do_list (opt.ignore_expiration?0:1, listmode, listfp,
               depth == 0  ? _("certificate has expired") :
               depth == -1 ? _("root certificate has expired") :
               /* other  */  _("intermediate certificate has expired"));
      if (!listmode)
        {
          log_info ("  (expired at ");
          dump_isotime (not_after);
          log_printf (")\n");
        }
      if (opt.ignore_expiration)
        log_info ("WARNING: ignoring expiration\n");
      else
        return gpg_error (GPG_ERR_CERT_EXPIRED);
    }

  return 0;
}

/* This is a variant of check_validity_period used with the chain
   model.  The extra constraint here is that notBefore and notAfter
   must exists and if the additional argument CHECK_TIME is given this
   time is used to check the validity period of SUBJECT_CERT.  */
static gpg_error_t
check_validity_period_cm (ksba_isotime_t current_time,
                          ksba_isotime_t check_time,
                          ksba_cert_t subject_cert,
                          ksba_isotime_t exptime,
                          int listmode, estream_t listfp, int depth)
{
  gpg_error_t err;
  ksba_isotime_t not_before, not_after;

  err = ksba_cert_get_validity (subject_cert, 0, not_before);
  if (!err)
    err = ksba_cert_get_validity (subject_cert, 1, not_after);
  if (err)
    {
      do_list (1, listmode, listfp,
               _("certificate with invalid validity: %s"), gpg_strerror (err));
      return gpg_error (GPG_ERR_BAD_CERT);
    }
  if (!*not_before || !*not_after)
    {
      do_list (1, listmode, listfp,
               _("required certificate attributes missing: %s%s%s"),
               !*not_before? "notBefore":"",
               (!*not_before && !*not_after)? ", ":"",
               !*not_before? "notAfter":"");
      return gpg_error (GPG_ERR_BAD_CERT);
    }
  if (strcmp (not_before, not_after) > 0 )
    {
      do_list (1, listmode, listfp,
               _("certificate with invalid validity"));
      log_info ("  (valid from ");
      dump_isotime (not_before);
      log_printf (" expired at ");
      dump_isotime (not_after);
      log_printf (")\n");
      return gpg_error (GPG_ERR_BAD_CERT);
    }

  if (!*exptime)
    gnupg_copy_time (exptime, not_after);
  else if (strcmp (not_after, exptime) < 0 )
    gnupg_copy_time (exptime, not_after);

  if (strcmp (current_time, not_before) < 0 )
    {
      do_list (1, listmode, listfp,
               depth ==  0 ? _("certificate not yet valid") :
               depth == -1 ? _("root certificate not yet valid") :
               /* other */   _("intermediate certificate not yet valid"));
      if (!listmode)
        {
          log_info ("  (valid from ");
          dump_isotime (not_before);
          log_printf (")\n");
        }
      return gpg_error (GPG_ERR_CERT_TOO_YOUNG);
    }

  if (*check_time
      && (strcmp (check_time, not_before) < 0
          || strcmp (check_time, not_after) > 0))
    {
      /* Note that we don't need a case for the root certificate
         because its own consistency has already been checked.  */
      do_list(opt.ignore_expiration?0:1, listmode, listfp,
              depth == 0 ?
              _("signature not created during lifetime of certificate") :
              depth == 1 ?
              _("certificate not created during lifetime of issuer") :
              _("intermediate certificate not created during lifetime "
                "of issuer"));
      if (!listmode)
        {
          log_info (depth== 0? _("  (  signature created at ") :
                    /* */      _("  (certificate created at ") );
          dump_isotime (check_time);
          log_printf (")\n");
          log_info (depth==0? _("  (certificate valid from ") :
                    /* */     _("  (     issuer valid from ") );
          dump_isotime (not_before);
          log_info (" to ");
          dump_isotime (not_after);
          log_printf (")\n");
        }
      if (opt.ignore_expiration)
        log_info ("WARNING: ignoring expiration\n");
      else
        return gpg_error (GPG_ERR_CERT_EXPIRED);
    }

  return 0;
}



/* Ask the user whether he wants to mark the certificate CERT trusted.
   Returns true if the CERT is the trusted.  We also check whether the
   agent is at all enabled to allow marktrusted and don't call it in
   this session again if it is not.  */
static int
ask_marktrusted (ctrl_t ctrl, ksba_cert_t cert, int listmode)
{
  static int no_more_questions;
  int rc;
  char *fpr;
  int success = 0;

  fpr = gpgsm_get_fingerprint_string (cert, GCRY_MD_SHA1);
  es_fflush (es_stdout);
  log_info (_("fingerprint=%s\n"), fpr? fpr : "?");
  xfree (fpr);

  if (no_more_questions)
    rc = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    rc = gpgsm_agent_marktrusted (ctrl, cert);
  if (!rc)
    {
      log_info (_("root certificate has now been marked as trusted\n"));
      success = 1;
    }
  else if (!listmode)
    {
      gpgsm_dump_cert ("issuer", cert);
      log_info ("after checking the fingerprint, you may want "
                "to add it manually to the list of trusted certificates.\n");
    }

  if (gpg_err_code (rc) == GPG_ERR_NOT_SUPPORTED)
    {
      if (!no_more_questions)
        log_info (_("interactive marking as trusted "
                    "not enabled in gpg-agent\n"));
      no_more_questions = 1;
    }
  else if (gpg_err_code (rc) == GPG_ERR_CANCELED)
    {
      log_info (_("interactive marking as trusted "
                  "disabled for this session\n"));
      no_more_questions = 1;
    }
  else
    set_already_asked_marktrusted (cert);

  return success;
}




/* Validate a chain and optionally return the nearest expiration time
   in R_EXPTIME. With LISTMODE set to 1 a special listmode is
   activated where only information about the certificate is printed
   to LISTFP and no output is send to the usual log stream.  If
   CHECKTIME_ARG is set, it is used only in the chain model instead of the
   current time.

   Defined flag bits

   VALIDATE_FLAG_NO_DIRMNGR  - Do not do any dirmngr isvalid checks.
   VALIDATE_FLAG_CHAIN_MODEL - Check according to chain model.
   VALIDATE_FLAG_STEED       - Check according to the STEED model.
*/
static int
do_validate_chain (ctrl_t ctrl, ksba_cert_t cert, ksba_isotime_t checktime_arg,
                   ksba_isotime_t r_exptime,
                   int listmode, estream_t listfp, unsigned int flags,
                   struct rootca_flags_s *rootca_flags)
{
  int rc = 0, depth, maxdepth;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = NULL;
  ksba_cert_t subject_cert = NULL, issuer_cert = NULL;
  ksba_isotime_t current_time;
  ksba_isotime_t check_time;
  ksba_isotime_t exptime;
  int any_expired = 0;
  int any_revoked = 0;
  int any_no_crl = 0;
  int any_crl_too_old = 0;
  int any_no_policy_match = 0;
  int is_qualified = -1; /* Indicates whether the certificate stems
                            from a qualified root certificate.
                            -1 = unknown, 0 = no, 1 = yes. */
  chain_item_t chain = NULL; /* A list of all certificates in the chain.  */


  gnupg_get_isotime (current_time);
  gnupg_copy_time (ctrl->current_time, current_time);

  if ( (flags & VALIDATE_FLAG_CHAIN_MODEL) )
    {
      if (!strcmp (checktime_arg, "19700101T000000"))
        {
          do_list (1, listmode, listfp,
                   _("WARNING: creation time of signature not known - "
                     "assuming current time"));
          gnupg_copy_time (check_time, current_time);
        }
      else
        gnupg_copy_time (check_time, checktime_arg);
    }
  else
    *check_time = 0;

  if (r_exptime)
    *r_exptime = 0;
  *exptime = 0;

  if (opt.no_chain_validation && !listmode)
    {
      log_info ("WARNING: bypassing certificate chain validation\n");
      return 0;
    }

  kh = keydb_new (ctrl);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (DBG_X509 && !listmode)
    gpgsm_dump_cert ("target", cert);

  subject_cert = cert;
  ksba_cert_ref (subject_cert);
  maxdepth = 50;
  depth = 0;

  for (;;)
    {
      int is_root;
      gpg_error_t istrusted_rc = gpg_error (GPG_ERR_NOT_TRUSTED);

      /* Put the certificate on our list.  */
      {
        chain_item_t ci;

        ci = xtrycalloc (1, sizeof *ci);
        if (!ci)
          {
            rc = gpg_error_from_syserror ();
            goto leave;
          }
        ksba_cert_ref (subject_cert);
        ci->cert = subject_cert;
        ci->next = chain;
        chain = ci;
      }

      xfree (issuer);
      xfree (subject);
      issuer = ksba_cert_get_issuer (subject_cert, 0);
      subject = ksba_cert_get_subject (subject_cert, 0);

      if (!issuer)
        {
          do_list (1, listmode, listfp,  _("no issuer found in certificate"));
          rc = gpg_error (GPG_ERR_BAD_CERT);
          goto leave;
        }


      /* Is this a self-issued certificate (i.e. the root certificate)?  */
      is_root = is_root_cert (subject_cert, issuer, subject);
      if (is_root)
        {
          chain->is_root = 1;
          /* Check early whether the certificate is listed as trusted.
             We used to do this only later but changed it to call the
             check right here so that we can access special flags
             associated with that specific root certificate.  */
          if (gpgsm_cert_has_well_known_private_key (subject_cert))
            {
              memset (rootca_flags, 0, sizeof *rootca_flags);
              istrusted_rc = ((flags & VALIDATE_FLAG_STEED)
                              ? 0 : gpg_error (GPG_ERR_NOT_TRUSTED));
            }
          else
            istrusted_rc = gpgsm_agent_istrusted (ctrl, subject_cert, NULL,
                                                  rootca_flags);
          audit_log_cert (ctrl->audit, AUDIT_ROOT_TRUSTED,
                          subject_cert, istrusted_rc);
          /* If the chain model extended attribute is used, make sure
             that our chain model flag is set. */
          if (!(flags & VALIDATE_FLAG_STEED)
              && has_validation_model_chain (subject_cert, listmode, listfp))
            rootca_flags->chain_model = 1;
        }


      /* Check the validity period. */
      if ( (flags & VALIDATE_FLAG_CHAIN_MODEL) )
        rc = check_validity_period_cm (current_time, check_time, subject_cert,
                                       exptime, listmode, listfp,
                                       (depth && is_root)? -1: depth);
      else
        rc = check_validity_period (current_time, subject_cert,
                                    exptime, listmode, listfp,
                                    (depth && is_root)? -1: depth);
      if (gpg_err_code (rc) == GPG_ERR_CERT_EXPIRED)
        any_expired = 1;
      else if (rc)
        goto leave;


      /* Assert that we understand all critical extensions. */
      rc = unknown_criticals (subject_cert, listmode, listfp);
      if (rc)
        goto leave;

      /* Do a policy check. */
      if (!opt.no_policy_check)
        {
          rc = check_cert_policy (subject_cert, listmode, listfp);
          if (gpg_err_code (rc) == GPG_ERR_NO_POLICY_MATCH)
            {
              any_no_policy_match = 1;
              rc = 1;  /* Be on the safe side and set RC.  */
            }
          else if (rc)
            goto leave;
        }


      /* If this is the root certificate we are at the end of the chain.  */
      if (is_root)
        {
          if (!istrusted_rc)
            ; /* No need to check the certificate for a trusted one. */
          else if (gpgsm_check_cert_sig (subject_cert, subject_cert) )
            {
              /* We only check the signature if the certificate is not
                 trusted for better diagnostics. */
              do_list (1, listmode, listfp,
                       _("self-signed certificate has a BAD signature"));
              if (DBG_X509)
                {
                  gpgsm_dump_cert ("self-signing cert", subject_cert);
                }
              rc = gpg_error (depth? GPG_ERR_BAD_CERT_CHAIN
                                   : GPG_ERR_BAD_CERT);
              goto leave;
            }
          if (!rootca_flags->relax)
            {
              rc = allowed_ca (ctrl, subject_cert, NULL, listmode, listfp);
              if (rc)
                goto leave;
            }


          /* Set the flag for qualified signatures.  This flag is
             deduced from a list of root certificates allowed for
             qualified signatures. */
          if (is_qualified == -1 && !(flags & VALIDATE_FLAG_STEED))
            {
              gpg_error_t err;
              size_t buflen;
              char buf[1];

              if (!ksba_cert_get_user_data (cert, "is_qualified",
                                            &buf, sizeof (buf),
                                            &buflen) && buflen)
                {
                  /* We already checked this for this certificate,
                     thus we simply take it from the user data. */
                  is_qualified = !!*buf;
                }
              else
                {
                  /* Need to consult the list of root certificates for
                     qualified signatures.  But first we check the
                     modern way by looking at the root ca flag.  */
                  if (rootca_flags->qualified)
                    err = 0;
                  else
                    err = gpgsm_is_in_qualified_list (ctrl, subject_cert, NULL);
                  if (!err)
                    is_qualified = 1;
                  else if ( gpg_err_code (err) == GPG_ERR_NOT_FOUND)
                    is_qualified = 0;
                  else
                    log_error ("checking the list of qualified "
                               "root certificates failed: %s\n",
                               gpg_strerror (err));
                  if ( is_qualified != -1 )
                    {
                      /* Cache the result but don't care too much
                         about an error. */
                      buf[0] = !!is_qualified;
                      err = ksba_cert_set_user_data (subject_cert,
                                                     "is_qualified", buf, 1);
                      if (err)
                        log_error ("set_user_data(is_qualified) failed: %s\n",
                                   gpg_strerror (err));
                    }
                }
            }


          /* Act on the check for a trusted root certificates. */
          rc = istrusted_rc;
          if (!rc)
            ;
          else if (gpg_err_code (rc) == GPG_ERR_NOT_TRUSTED)
            {
              do_list (0, listmode, listfp,
                       _("root certificate is not marked trusted"));
              /* If we already figured out that the certificate is
                 expired it does not make much sense to ask the user
                 whether they want to trust the root certificate.  We
                 should do this only if the certificate under question
                 will then be usable.  If the certificate has a well
                 known private key asking the user does not make any
                 sense.  */
              if ( !any_expired
                   && !gpgsm_cert_has_well_known_private_key (subject_cert)
                   && (!listmode || !already_asked_marktrusted (subject_cert))
                   && ask_marktrusted (ctrl, subject_cert, listmode) )
                rc = 0;
            }
          else
            {
              log_error (_("checking the trust list failed: %s\n"),
                         gpg_strerror (rc));
            }

          if (rc)
            goto leave;

          /* Check for revocations etc. */
          if ((flags & VALIDATE_FLAG_NO_DIRMNGR))
            ;
          else if ((flags & VALIDATE_FLAG_STEED))
            ; /* Fixme: check revocations via DNS.  */
          else if (opt.no_trusted_cert_crl_check || rootca_flags->relax)
            ;
          else
            rc = is_cert_still_valid (ctrl,
                                      (flags & VALIDATE_FLAG_CHAIN_MODEL),
                                      listmode, listfp,
                                      subject_cert, subject_cert,
                                      &any_revoked, &any_no_crl,
                                      &any_crl_too_old);
          if (rc)
            goto leave;

          break;  /* Okay: a self-signed certificate is an end-point. */
        } /* End is_root.  */


      /* Take care that the chain does not get too long. */
      if ((depth+1) > maxdepth)
        {
          do_list (1, listmode, listfp, _("certificate chain too long\n"));
          rc = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
          goto leave;
        }

      /* Find the next cert up the tree. */
      keydb_search_reset (kh);
      rc = find_up (ctrl, kh, subject_cert, issuer, 0);
      if (rc)
        {
          if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
            {
              do_list (0, listmode, listfp, _("issuer certificate not found"));
              if (!listmode && !opt.quiet)
                {
                  log_info ("issuer certificate: #/");
                  gpgsm_dump_string (issuer);
                  log_printf ("\n");
                }
            }
          else
            log_error ("failed to find issuer's certificate: %s <%s>\n",
                       gpg_strerror (rc), gpg_strsource (rc));
          rc = gpg_error (GPG_ERR_MISSING_ISSUER_CERT);
          goto leave;
        }

      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_error ("keydb_get_cert failed in %s: %s <%s>\n",
                     __func__, gpg_strerror (rc), gpg_strsource (rc));
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
          do_list (0, listmode, listfp, _("certificate has a BAD signature"));
          if (DBG_X509)
            {
              gpgsm_dump_cert ("signing issuer", issuer_cert);
              gpgsm_dump_cert ("signed subject", subject_cert);
            }
          if (gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE)
            {
              /* We now try to find other issuer certificates which
                 might have been used.  This is required because some
                 CAs are reusing the issuer and subject DN for new
                 root certificates. */
              /* FIXME: Do this only if we don't have an
                 AKI.keyIdentifier */
              rc = find_up (ctrl, kh, subject_cert, issuer, 1);
              if (!rc)
                {
                  ksba_cert_t tmp_cert;

                  rc = keydb_get_cert (kh, &tmp_cert);
                  if (rc || !compare_certs (issuer_cert, tmp_cert))
                    {
                      /* The find next did not work or returned an
                         identical certificate.  We better stop here
                         to avoid infinite checks. */
                      /* No need to set RC because it is not used:
                         rc = gpg_error (GPG_ERR_BAD_SIGNATURE);  */
                      ksba_cert_release (tmp_cert);
                    }
                  else
                    {
                      do_list (0, listmode, listfp,
                               _("found another possible matching "
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

      is_root = gpgsm_is_root_cert (issuer_cert);
      istrusted_rc = gpg_error (GPG_ERR_NOT_TRUSTED);


      /* Check that a CA is allowed to issue certificates. */
      {
        int chainlen;

        rc = allowed_ca (ctrl, issuer_cert, &chainlen, listmode, listfp);
        if (rc)
          {
            /* Not allowed.  Check whether this is a trusted root
               certificate and whether we allow special exceptions.
               We could carry the result of the test over to the
               regular root check at the top of the loop but for
               clarity we won't do that.  Given that the majority of
               certificates carry proper BasicContraints our way of
               overriding an error in the way is justified for
               performance reasons. */
            if (is_root)
              {
                if (gpgsm_cert_has_well_known_private_key (issuer_cert))
                  {
                    memset (rootca_flags, 0, sizeof *rootca_flags);
                    istrusted_rc = ((flags & VALIDATE_FLAG_STEED)
                                    ? 0 : gpg_error (GPG_ERR_NOT_TRUSTED));
                  }
                else
                  istrusted_rc = gpgsm_agent_istrusted
                    (ctrl, issuer_cert, NULL, rootca_flags);

                if (!istrusted_rc && rootca_flags->relax)
                  {
                    /* Ignore the error due to the relax flag.  */
                    rc = 0;
                    chainlen = -1;
                  }
              }
          }
        if (rc)
          goto leave;
        if (chainlen >= 0 && depth > chainlen)
          {
            do_list (1, listmode, listfp,
                     _("certificate chain longer than allowed by CA (%d)"),
                     chainlen);
            rc = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
            goto leave;
          }
      }

      /* Is the certificate allowed to sign other certificates. */
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

      /* Check for revocations etc.  Note that for a root certificate
         this test is done a second time later. This should eventually
         be fixed. */
      if ((flags & VALIDATE_FLAG_NO_DIRMNGR))
        rc = 0;
      else if ((flags & VALIDATE_FLAG_STEED))
        rc = 0; /* Fixme: XXX */
      else if (is_root && (opt.no_trusted_cert_crl_check
                           || (!istrusted_rc && rootca_flags->relax)))
        rc = 0;
      else
        rc = is_cert_still_valid (ctrl,
                                  (flags & VALIDATE_FLAG_CHAIN_MODEL),
                                  listmode, listfp,
                                  subject_cert, issuer_cert,
                                  &any_revoked, &any_no_crl, &any_crl_too_old);
      if (rc)
        goto leave;


      if (opt.verbose && !listmode)
        log_info (depth == 0 ? _("certificate is good\n") :
                  !is_root   ? _("intermediate certificate is good\n") :
                  /* other */  _("root certificate is good\n"));

      /* Under the chain model the next check time is the creation
         time of the subject certificate.  */
      if ( (flags & VALIDATE_FLAG_CHAIN_MODEL) )
        {
          rc = ksba_cert_get_validity (subject_cert, 0, check_time);
          if (rc)
            {
              /* That will never happen as we have already checked
                 this above.  */
              BUG ();
            }
        }

      /* For the next round the current issuer becomes the new subject.  */
      keydb_search_reset (kh);
      ksba_cert_release (subject_cert);
      subject_cert = issuer_cert;
      issuer_cert = NULL;
      depth++;
    } /* End chain traversal. */

  if (!listmode && !opt.quiet)
    {
      if (opt.no_policy_check)
        log_info ("policies not checked due to %s option\n",
                  "--disable-policy-checks");
      if (ctrl->offline || (opt.no_crl_check && !ctrl->use_ocsp))
        log_info ("CRLs not checked due to %s option\n",
                  ctrl->offline ? "offline" : "--disable-crl-checks");
    }

  if (!rc)
    { /* If we encountered an error somewhere during the checks, set
         the error code to the most critical one */
      if (any_revoked)
        rc = gpg_error (GPG_ERR_CERT_REVOKED);
      else if (any_expired)
        rc = gpg_error (GPG_ERR_CERT_EXPIRED);
      else if (any_no_crl)
        rc = gpg_error (GPG_ERR_NO_CRL_KNOWN);
      else if (any_crl_too_old)
        rc = gpg_error (GPG_ERR_CRL_TOO_OLD);
      else if (any_no_policy_match)
        rc = gpg_error (GPG_ERR_NO_POLICY_MATCH);
    }

 leave:
  /* If we have traversed a complete chain up to the root we will
     reset the ephemeral flag for all these certificates.  This is done
     regardless of any error because those errors may only be
     transient. */
  if (chain && chain->is_root)
    {
      gpg_error_t err;
      chain_item_t ci;

      for (ci = chain; ci; ci = ci->next)
        {
          /* Note that it is possible for the last certificate in the
             chain (i.e. our target certificate) that it has not yet
             been stored in the keybox and thus the flag can't be set.
             We ignore this error because it will later be stored
             anyway.  */
          err = keydb_set_cert_flags (ctrl, ci->cert, 1, KEYBOX_FLAG_BLOB, 0,
                                      KEYBOX_FLAG_BLOB_EPHEMERAL, 0);
          if (!ci->next && gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            ;
          else if (err)
            log_error ("clearing ephemeral flag failed: %s\n",
                       gpg_strerror (err));
        }
    }

  /* If we have figured something about the qualified signature
     capability of the certificate under question, store the result as
     user data in all certificates of the chain.  We do this even if the
     validation itself failed.  */
  if (is_qualified != -1 && !(flags & VALIDATE_FLAG_STEED))
    {
      gpg_error_t err;
      chain_item_t ci;
      char buf[1];

      buf[0] = !!is_qualified;

      for (ci = chain; ci; ci = ci->next)
        {
          err = ksba_cert_set_user_data (ci->cert, "is_qualified", buf, 1);
          if (err)
            {
              log_error ("set_user_data(is_qualified) failed: %s\n",
                         gpg_strerror (err));
              if (!rc)
                rc = err;
            }
        }
    }

  /* If auditing has been enabled, record what is in the chain.  */
  if (ctrl->audit)
    {
      chain_item_t ci;

      audit_log (ctrl->audit, AUDIT_CHAIN_BEGIN);
      for (ci = chain; ci; ci = ci->next)
        {
          audit_log_cert (ctrl->audit,
                          ci->is_root? AUDIT_CHAIN_ROOTCERT : AUDIT_CHAIN_CERT,
                          ci->cert, 0);
        }
      audit_log (ctrl->audit, AUDIT_CHAIN_END);
    }

  if (r_exptime)
    gnupg_copy_time (r_exptime, exptime);
  xfree (issuer);
  xfree (subject);
  keydb_release (kh);
  while (chain)
    {
      chain_item_t ci_next = chain->next;
      ksba_cert_release (chain->cert);
      xfree (chain);
      chain = ci_next;
    }
  ksba_cert_release (issuer_cert);
  ksba_cert_release (subject_cert);
  return rc;
}


/* Validate a certificate chain.  For a description see
   do_validate_chain.  This function is a wrapper to handle a root
   certificate with the chain_model flag set.  If RETFLAGS is not
   NULL, flags indicating now the verification was done are stored
   there.  The only defined bits for RETFLAGS are
   VALIDATE_FLAG_CHAIN_MODEL and VALIDATE_FLAG_STEED.

   If you are verifying a signature you should set CHECKTIME to the
   creation time of the signature.  If your are verifying a
   certificate, set it nil (i.e. the empty string).  If the creation
   date of the signature is not known use the special date
   "19700101T000000" which is treated in a special way here. */
int
gpgsm_validate_chain (ctrl_t ctrl, ksba_cert_t cert, ksba_isotime_t checktime,
                      ksba_isotime_t r_exptime,
                      int listmode, estream_t listfp, unsigned int flags,
                      unsigned int *retflags)
{
  int rc;
  struct rootca_flags_s rootca_flags;
  unsigned int dummy_retflags;

  if (!retflags)
    retflags = &dummy_retflags;

  /* If the session requested a certain validation mode make sure the
     corresponding flags are set.  */
  if (ctrl->validation_model == 1)
    flags |= VALIDATE_FLAG_CHAIN_MODEL;
  else if (ctrl->validation_model == 2)
    flags |= VALIDATE_FLAG_STEED;

  /* If the chain model was forced, set this immediately into
     RETFLAGS.  */
  *retflags = (flags & VALIDATE_FLAG_CHAIN_MODEL);

  memset (&rootca_flags, 0, sizeof rootca_flags);

  if ((flags & VALIDATE_FLAG_BYPASS))
    {
      *retflags |= VALIDATE_FLAG_BYPASS;
      rc = 0;
    }
  else
    rc = do_validate_chain (ctrl, cert, checktime,
                            r_exptime, listmode, listfp, flags,
                            &rootca_flags);
  if (!rc && (flags & VALIDATE_FLAG_STEED))
    {
      *retflags |= VALIDATE_FLAG_STEED;
    }
  else if (!(flags & VALIDATE_FLAG_CHAIN_MODEL)
           && (rootca_flags.valid && rootca_flags.chain_model))
    {
      /* The root CA indicated that the chain model is to be used but
       * we have not yet used it.  Thus do the validation again using
       * the chain model.  */
      if (opt.verbose)
        do_list (0, listmode, listfp, _("switching to chain model"));
      rc = do_validate_chain (ctrl, cert, checktime,
                              r_exptime, listmode, listfp,
                              (flags |= VALIDATE_FLAG_CHAIN_MODEL),
                              &rootca_flags);
      *retflags |= VALIDATE_FLAG_CHAIN_MODEL;
    }

  if (opt.verbose)
    do_list (0, listmode, listfp, _("validation model used: %s"),
             (*retflags & VALIDATE_FLAG_BYPASS)?
             "bypass" :
             (*retflags & VALIDATE_FLAG_STEED)?
             "steed" :
             (*retflags & VALIDATE_FLAG_CHAIN_MODEL)?
             _("chain"):_("shell"));

  return rc;
}


/* Check that the given certificate is valid but DO NOT check any
   constraints.  We assume that the issuers certificate is already in
   the DB and that this one is valid; which it should be because it
   has been checked using this function. */
int
gpgsm_basic_cert_check (ctrl_t ctrl, ksba_cert_t cert)
{
  int rc = 0;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh;
  ksba_cert_t issuer_cert = NULL;

  if (opt.no_chain_validation)
    {
      log_info ("WARNING: bypassing basic certificate checks\n");
      return 0;
    }

  kh = keydb_new (ctrl);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
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

  if (is_root_cert (cert, issuer, subject))
    {
      rc = gpgsm_check_cert_sig (cert, cert);
      if (rc)
        {
          log_error ("self-signed certificate has a BAD signature: %s\n",
                     gpg_strerror (rc));
          if (DBG_X509)
            {
              gpgsm_dump_cert ("self-signing cert", cert);
            }
          rc = gpg_error (GPG_ERR_BAD_CERT);
          goto leave;
        }
    }
  else
    {
      /* Find the next cert up the tree. */
      keydb_search_reset (kh);
      rc = find_up (ctrl, kh, cert, issuer, 0);
      if (rc)
        {
          if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
            {
              if (!opt.quiet)
                {
                  es_fflush (es_stdout);
                  log_info ("issuer certificate (#/");
                  gpgsm_dump_string (issuer);
                  log_printf (") not found\n");
                }
            }
          else
            log_error ("failed to find issuer's certificate: %s <%s>\n",
                       gpg_strerror (rc), gpg_strsource (rc));
          rc = gpg_error (GPG_ERR_MISSING_ISSUER_CERT);
          goto leave;
        }

      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_error ("keydb_get_cert failed in %s: %s <%s>\n",
                     __func__, gpg_strerror (rc), gpg_strsource (rc));
          rc = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

      rc = gpgsm_check_cert_sig (issuer_cert, cert);
      if (rc)
        {
          log_error ("certificate has a BAD signature: %s\n",
                     gpg_strerror (rc));
          if (DBG_X509)
            {
              gpgsm_dump_cert ("signing issuer", issuer_cert);
              gpgsm_dump_cert ("signed subject", cert);
            }
          rc = gpg_error (GPG_ERR_BAD_CERT);
          goto leave;
        }
      if (opt.verbose)
        log_info (_("certificate is good\n"));
    }

 leave:
  xfree (issuer);
  xfree (subject);
  keydb_release (kh);
  ksba_cert_release (issuer_cert);
  return rc;
}



/* Check whether the certificate CERT has been issued by the German
   authority for qualified signature.  They do not set the
   basicConstraints and thus we need this workaround.  It works by
   looking up the root certificate and checking whether that one is
   listed as a qualified certificate for Germany.

   We also try to cache this data but as long as don't keep a
   reference to the certificate this won't be used.

   Returns: True if CERT is a RegTP issued CA cert (i.e. the root
   certificate itself or one of the CAs).  In that case CHAINLEN will
   receive the length of the chain which is either 0 or 1.
*/
static int
get_regtp_ca_info (ctrl_t ctrl, ksba_cert_t cert, int *chainlen)
{
  gpg_error_t err;
  ksba_cert_t next;
  int rc = 0;
  int i, depth;
  char country[3];
  ksba_cert_t array[4];
  char buf[2];
  size_t buflen;
  int dummy_chainlen;

  if (!chainlen)
    chainlen = &dummy_chainlen;

  *chainlen = 0;
  err = ksba_cert_get_user_data (cert, "regtp_ca_chainlen",
                                 &buf, sizeof (buf), &buflen);
  if (!err)
    {
      /* Got info. */
      if (buflen < 2 || !*buf)
        return 0; /* Nothing found. */
      *chainlen = buf[1];
      return 1; /* This is a regtp CA. */
    }
  else if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    {
      log_error ("ksba_cert_get_user_data(%s) failed: %s\n",
                 "regtp_ca_chainlen", gpg_strerror (err));
      return 0; /* Nothing found.  */
    }

  /* Need to gather the info.  This requires to walk up the chain
     until we have found the root.  Because we are only interested in
     German Bundesnetzagentur (former RegTP) derived certificates 3
     levels are enough.  (The German signature law demands a 3 tier
     hierarchy; thus there is only one CA between the EE and the Root
     CA.)  */
  memset (&array, 0, sizeof array);

  depth = 0;
  ksba_cert_ref (cert);
  array[depth++] = cert;
  ksba_cert_ref (cert);
  while (depth < DIM(array) && !(rc=gpgsm_walk_cert_chain (ctrl, cert, &next)))
    {
      ksba_cert_release (cert);
      ksba_cert_ref (next);
      array[depth++] = next;
      cert = next;
    }
  ksba_cert_release (cert);
  if (gpg_err_code (rc) != GPG_ERR_NOT_FOUND || !depth || depth == DIM(array) )
    {
      /* We did not reached the root. */
      goto leave;
    }

  /* If this is a German signature law issued certificate, we store
     additional information. */
  if (!gpgsm_is_in_qualified_list (NULL, array[depth-1], country)
      && !strcmp (country, "de"))
    {
      /* Setting the pathlen for the root CA and the CA flag for the
         next one is all what we need to do. */
      err = ksba_cert_set_user_data (array[depth-1], "regtp_ca_chainlen",
                                     "\x01\x01", 2);
      if (!err && depth > 1)
        err = ksba_cert_set_user_data (array[depth-2], "regtp_ca_chainlen",
                                       "\x01\x00", 2);
      if (err)
        log_error ("ksba_set_user_data(%s) failed: %s\n",
                   "regtp_ca_chainlen", gpg_strerror (err));
      for (i=0; i < depth; i++)
        ksba_cert_release (array[i]);
      *chainlen = (depth>1? 0:1);
      return 1;
    }

 leave:
  /* Nothing special with this certificate. Mark the target
     certificate anyway to avoid duplicate lookups. */
  err = ksba_cert_set_user_data (cert, "regtp_ca_chainlen", "", 1);
  if (err)
    log_error ("ksba_set_user_data(%s) failed: %s\n",
               "regtp_ca_chainlen", gpg_strerror (err));
  for (i=0; i < depth; i++)
    ksba_cert_release (array[i]);
  return 0;
}
