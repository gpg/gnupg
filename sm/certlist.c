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

/* add a certificate to a list of certificate and make sure that it is
   a valid certificate */
int
gpgsm_add_to_certlist (const char *name, CERTLIST *listaddr)
{
  int rc;
  KEYDB_SEARCH_DESC desc;
  KEYDB_HANDLE kh = NULL;
  KsbaCert cert = NULL;

  /* fixme: check that we identify excactly one cert with the name */
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
            rc = keydb_get_cert (kh, &cert);
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
  /* fixme: check that we identify excactly one cert with the name */
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
        }
    }
  
  keydb_release (kh);
  return rc == -1? GNUPG_No_Public_Key: rc;
}
