/* import.c - Import certificates
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
gpgsm_import (CTRL ctrl, int in_fd)
{
  int rc;
  Base64Context b64reader = NULL;
  KsbaReader reader;
  KsbaCert cert = NULL;
  FILE *fp = NULL;

  fp = fdopen ( dup (in_fd), "rb");
  if (!fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  cert = ksba_cert_new ();
  if (!cert)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  rc = ksba_cert_read_der (cert, reader);
  if (rc)
    {
      rc = map_ksba_err (rc);
      goto leave;
    }

  if ( !gpgsm_basic_cert_check (cert) )
    {
      if (!keydb_store_cert (cert))
        {
          if (opt.verbose)
            log_info ("certificate imported\n");
        }
    }
      
 leave:
  ksba_cert_release (cert);
  gpgsm_destroy_reader (b64reader);
  if (fp)
    fclose (fp);
  return rc;
}




