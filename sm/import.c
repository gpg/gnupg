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
  KsbaCMS cms = NULL;
  FILE *fp = NULL;
  KsbaContentType ct;

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

  ct = ksba_cms_identify (reader);
  if (ct == KSBA_CT_SIGNED_DATA)
    { /* This is probably a signed-only message - import the certs */
      KsbaStopReason stopreason;
      int i;

      cms = ksba_cms_new ();
      if (!cms)
        {
          rc = seterr (Out_Of_Core);
          goto leave;
        }

      rc = ksba_cms_set_reader_writer (cms, reader, NULL);
      if (rc)
        {
          log_error ("ksba_cms_set_reader_writer failed: %s\n",
                     ksba_strerror (rc));
          rc = map_ksba_err (rc);
          goto leave;
        }


      do 
        {
          rc = ksba_cms_parse (cms, &stopreason);
          if (rc)
            {
              log_error ("ksba_cms_parse failed: %s\n", ksba_strerror (rc));
              rc = map_ksba_err (rc);
              goto leave;
            }

          if (stopreason == KSBA_SR_BEGIN_DATA)
              log_info ("not a certs-only message\n");
        }
      while (stopreason != KSBA_SR_READY);   
      
      for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
        {
          if ( !gpgsm_basic_cert_check (cert) )
            {
              if (!keydb_store_cert (cert))
                {
                  if (opt.verbose)
                    log_info ("certificate imported\n");
                }
              else
                log_error (_("error storing certificate\n"));
            }
          else
            log_error (_("basic certificate checks failed - not imported\n"));
          ksba_cert_release (cert); 
          cert = NULL;
        }
      if (!i)
        log_error ("no certificate found\n");
    }
  else if (ct == KSBA_CT_NONE)
    { /* Failed to identify this message - assume a certificate */

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
          else
            log_error (_("error storing certificate\n"));
        }
      else
        log_error (_("basic certificate checks failed - not imported\n"));
    }
  else
    {
      log_error ("can't extract certificates from input\n");
      rc = GNUPG_No_Data;
    }
   

 leave:
  ksba_cms_release (cms);
  ksba_cert_release (cert);
  gpgsm_destroy_reader (b64reader);
  if (fp)
    fclose (fp);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gnupg_strerror (rc));
  return rc;
}




