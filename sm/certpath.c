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

int
gpgsm_validate_path (KsbaCert cert)
{
  int rc = 0, depth = 0;
  char *issuer = NULL;
  char *subject = NULL;
  KEYDB_HANDLE kh = keydb_new (0);
  KsbaCert subject_cert = NULL, issuer_cert = NULL;

  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GPGSM_General_Error;
      goto leave;
    }

  gpgsm_dump_cert ("subject", cert);

  subject_cert = cert;

  for (;;)
    {
      xfree (issuer);
      xfree (subject);
      issuer = ksba_cert_get_issuer (subject_cert);
      subject = ksba_cert_get_subject (subject_cert);

      if (!issuer)
        {
          if (DBG_X509)
            log_debug ("ERROR: issuer missing\n");
          rc = GPGSM_Bad_Certificate;
          goto leave;
        }

      if (subject && !strcmp (issuer, subject))
        {
          if (gpgsm_check_cert_sig (subject_cert, subject_cert) )
            {
              log_debug ("selfsigned certificate has a BAD signatures\n");
              rc = depth? GPGSM_Bad_Certificate_Path : GPGSM_Bad_Certificate;
              goto leave;
            }
          log_debug ("selfsigned certificate is good\n");
          break;  /* okay, a self-signed certicate is an end-point */
        }
      
      depth++;
      /* fixme: check against a maximum path length */

      /* find the next cert up the tree */
      keydb_search_reset (kh);
      rc = keydb_search_subject (kh, issuer);
      if (rc)
        {
          log_debug ("failed to find issuer's certificate: rc=%d\n", rc);
          rc = GPGSM_Missing_Certificate;
          goto leave;
        }

      ksba_cert_release (issuer_cert); issuer_cert = NULL;
      rc = keydb_get_cert (kh, &issuer_cert);
      if (rc)
        {
          log_debug ("failed to get cert: rc=%d\n", rc);
          rc = GPGSM_General_Error;
          goto leave;
        }

      log_debug ("got issuer's certificate:\n");
      gpgsm_dump_cert ("issuer", issuer_cert);

      if (gpgsm_check_cert_sig (issuer_cert, subject_cert) )
        {
          log_debug ("certificate has a BAD signatures\n");
          rc = GPGSM_Bad_Certificate_Path;
          goto leave;
        }
      log_debug ("certificate is good\n");
      
      keydb_search_reset (kh);
      subject_cert = issuer_cert;
      issuer_cert = NULL;
    }
  
 leave:
  xfree (issuer);
  keydb_release (kh); 
  ksba_cert_release (issuer_cert);
  if (subject_cert != cert)
    ksba_cert_release (subject_cert);
  return rc;
}

