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

  if ((use & ((mode&1)? KSBA_KEYUSAGE_DIGITAL_SIGNATURE
              : KSBA_KEYUSAGE_KEY_ENCIPHERMENT)))
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

/* add a certificate to a list of certificate and make sure that it is
   a valid certificate */
int
gpgsm_add_to_certlist (const char *name, CERTLIST *listaddr)
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
                     correct usage, so we better try again */
                  wrong_usage = rc;
                  ksba_cert_release (cert);
                  cert = NULL;
                  goto get_next;
                }
            }
          /* we want the error code from the first match in this case */
          if (wrong_usage)
            rc = wrong_usage;

          if (!rc)
            {
              /* Fixme: If we ever have two certifciates differing
                 only in the key usage, we should only bail out here
                 if the certificate differes just in the key usage.
                 However we need to find some criteria to match the
                 identities */
              rc = keydb_search (kh, &desc, 1);
              if (rc == -1)
                rc = 0;
              else if (!rc)
                rc = GNUPG_Ambiguous_Name;
            }
          if (!rc)
            rc = gpgsm_validate_path (cert);
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

