/* certlist.c - build list of certificates
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
 
/* Return 0 if the cert is usable for encryption.  A MODE of 0 checks
   for signing a MODE of 1 checks for encryption, a MODE of 2 checks
   for verification and a MODE of 3 for decryption (just for
   debugging) */
static int
cert_usage_p (KsbaCert cert, int mode)
{
  KsbaError err;
  unsigned int use;

  err = ksba_cert_get_key_usage (cert, &use);
  if (err == KSBA_No_Data)
    {
      if (opt.verbose && mode < 2)
        log_info (mode? 
                  _("no key usage specified - accepted for encryption\n"):
                  _("no key usage specified - accepted for signing\n"));
      return 0;
    }
  if (err)
    { 
      log_error (_("error getting key usage information: %s\n"),
                 ksba_strerror (err));
      return map_ksba_err (err);
    } 

  if (mode == 4)
    {
      if ((use & (KSBA_KEYUSAGE_KEY_CERT_SIGN)))
        return 0;
      log_info ( _("certificate should have not been used certification\n"));
      return GNUPG_Wrong_Key_Usage;
    }

  if ((use & ((mode&1)?
              (KSBA_KEYUSAGE_KEY_ENCIPHERMENT|KSBA_KEYUSAGE_DATA_ENCIPHERMENT):
              (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_NON_REPUDIATION)))
      )
    return 0;
  log_info (mode==3? _("certificate should have not been used for encryption\n"):
            mode==2? _("certificate should have not been used for signing\n"):
            mode==1? _("certificate is not usable for encryption\n"):
                     _("certificate is not usable for signing\n"));
  return GNUPG_Wrong_Key_Usage;
}


/* Return 0 if the cert is usable for signing */
int
gpgsm_cert_use_sign_p (KsbaCert cert)
{
  return cert_usage_p (cert, 0);
}


/* Return 0 if the cert is usable for encryption */
int
gpgsm_cert_use_encrypt_p (KsbaCert cert)
{
  return cert_usage_p (cert, 1);
}

int
gpgsm_cert_use_verify_p (KsbaCert cert)
{
  return cert_usage_p (cert, 2);
}

int
gpgsm_cert_use_decrypt_p (KsbaCert cert)
{
  return cert_usage_p (cert, 3);
}

int
gpgsm_cert_use_cert_p (KsbaCert cert)
{
  return cert_usage_p (cert, 4);
}


static int
same_subject_issuer (const char *subject, const char *issuer, KsbaCert cert)
{
  char *subject2 = ksba_cert_get_subject (cert, 0);
  char *issuer2 = ksba_cert_get_subject (cert, 0);
  int tmp;
  
  tmp = (subject && subject2
         && !strcmp (subject, subject2)
         && issuer && issuer2
         && !strcmp (issuer, issuer2));
  xfree (subject2);
  xfree (issuer2);
  return tmp;
}



/* add a certificate to a list of certificate and make sure that it is
   a valid certificate */
int
gpgsm_add_to_certlist (CTRL ctrl, const char *name, CERTLIST *listaddr)
{
  int rc;
  KEYDB_SEARCH_DESC desc;
  KEYDB_HANDLE kh = NULL;
  KsbaCert cert = NULL;

  rc = keydb_classify_name (name, &desc);
  if (!rc)
    {
      kh = keydb_new (0);
      if (!kh)
        rc = GNUPG_Out_Of_Core;
      else
        {
          int wrong_usage = 0;
          char *subject = NULL;
          char *issuer = NULL;

        get_next:
          rc = keydb_search (kh, &desc, 1);
          if (!rc)
            rc = keydb_get_cert (kh, &cert);
          if (!rc)
            {
              rc = gpgsm_cert_use_encrypt_p (cert);
              if (rc == GNUPG_Wrong_Key_Usage)
                {
                  /* There might be another certificate with the
                     correct usage, so we try again */
                  if (!wrong_usage)
                    { /* save the first match */
                      wrong_usage = rc;
                      subject = ksba_cert_get_subject (cert, 0);
                      issuer = ksba_cert_get_subject (cert, 0);
                      ksba_cert_release (cert);
                      cert = NULL;
                      goto get_next;
                    }
                  else if (same_subject_issuer (subject, issuer, cert))
                    {
                      wrong_usage = rc;
                      ksba_cert_release (cert);
                      cert = NULL;
                      goto get_next;
                    }
                  else
                    wrong_usage = rc;

                }
            }
          /* we want the error code from the first match in this case */
          if (rc && wrong_usage)
            rc = wrong_usage;
          
          if (!rc)
            {
            next_ambigious:
              rc = keydb_search (kh, &desc, 1);
              if (rc == -1)
                rc = 0;
              else if (!rc)
                {
                  KsbaCert cert2 = NULL;

                  /* We have to ignore ambigious names as long as
                     there only fault is a bad key usage */
                  if (!keydb_get_cert (kh, &cert2))
                    {
                      int tmp = (same_subject_issuer (subject, issuer, cert2)
                                 && (gpgsm_cert_use_encrypt_p (cert2)
                                     == GNUPG_Wrong_Key_Usage));
                      ksba_cert_release (cert2);
                      if (tmp)
                        goto next_ambigious;
                    }
                  rc = GNUPG_Ambiguous_Name;
                }
            }
          xfree (subject);
          xfree (issuer);

          if (!rc)
            rc = gpgsm_validate_path (ctrl, cert, NULL);
          if (!rc)
            {
              CERTLIST cl = xtrycalloc (1, sizeof *cl);
              if (!cl)
                rc = GNUPG_Out_Of_Core;
              else 
                {
                  cl->cert = cert; cert = NULL;
                  cl->next = *listaddr;
                  *listaddr = cl;
                }
            }
        }
    }
  
  keydb_release (kh);
  ksba_cert_release (cert);
  return rc == -1? GNUPG_No_Public_Key: rc;
}

void
gpgsm_release_certlist (CERTLIST list)
{
  while (list)
    {
      CERTLIST cl = list->next;
      ksba_cert_release (list->cert);
      xfree (list);
      list = cl;
    }
}


/* Like gpgsm_add_to_certlist, but look only for one certificate.  No
   path validation is done */
int
gpgsm_find_cert (const char *name, KsbaCert *r_cert)
{
  int rc;
  KEYDB_SEARCH_DESC desc;
  KEYDB_HANDLE kh = NULL;

  *r_cert = NULL;
  rc = keydb_classify_name (name, &desc);
  if (!rc)
    {
      kh = keydb_new (0);
      if (!kh)
        rc = GNUPG_Out_Of_Core;
      else
        {
          rc = keydb_search (kh, &desc, 1);
          if (!rc)
            rc = keydb_get_cert (kh, r_cert);
          if (!rc)
            {
              rc = keydb_search (kh, &desc, 1);
              if (rc == -1)
                rc = 0;
              else 
                {
                  if (!rc)
                    rc = GNUPG_Ambiguous_Name;
                  ksba_cert_release (*r_cert);
                  *r_cert = NULL;
                }
            }
        }
    }
  
  keydb_release (kh);
  return rc == -1? GNUPG_No_Public_Key: rc;
}

