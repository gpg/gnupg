/* import.c - Import certificates
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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

struct stats_s {
  unsigned long count;
  unsigned long imported;
  unsigned long unchanged;
  unsigned long not_imported;
};



static void
print_imported_status (CTRL ctrl, KsbaCert cert)
{
  char *fpr;
 
  fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
  gpgsm_status2 (ctrl, STATUS_IMPORTED, fpr, "[X.509]", NULL);
  xfree (fpr);
}


/* Print an IMPORT_PROBLEM status.  REASON is one of:
   0 := "No specific reason given".
   1 := "Invalid Certificate".
   2 := "Issuer Certificate missing".
   3 := "Certificate Chain too long".
   4 := "Error storing certificate".
*/
static void
print_import_problem (CTRL ctrl, KsbaCert cert, int reason)
{
  char *fpr = NULL;
  char buf[25];
  int i;

  sprintf (buf, "%d", reason);
  if (cert)
    {
      fpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
      /* detetect an error (all high) value */
      for (i=0; fpr[i] == 'F'; i++)
        ;
      if (!fpr[i])
        {
          xfree (fpr);
          fpr = NULL;
        }
    }
  gpgsm_status2 (ctrl, STATUS_IMPORT_PROBLEM, buf, fpr, NULL);
  xfree (fpr);
}


void
print_imported_summary (CTRL ctrl, struct stats_s *stats)
{
  char buf[14*25];

  if (!opt.quiet)
    {
      log_info (_("total number processed: %lu\n"), stats->count);
      if (stats->imported) 
        {
          log_info (_("              imported: %lu"), stats->imported );
          log_printf ("\n");
	}
      if (stats->unchanged)
        log_info (_("             unchanged: %lu\n"), stats->unchanged);
      if (stats->not_imported)
        log_info (_("          not imported: %lu\n"), stats->not_imported);
    }

  sprintf (buf, "%lu 0 %lu 0 %lu 0 0 0 0 0 0 0 0 %lu",
           stats->count,
           stats->imported,
           stats->unchanged,
           stats->not_imported
           );
  gpgsm_status (ctrl, STATUS_IMPORT_RES, buf);
}



static void
check_and_store (CTRL ctrl, struct stats_s *stats, KsbaCert cert, int depth)
{
  int rc;

  stats->count++;
  if ( depth >= 50 )
    {
      log_error (_("certificate chain too long\n"));
      stats->not_imported++;
      print_import_problem (ctrl, cert, 3);
      return;
    }

  rc = gpgsm_basic_cert_check (cert);
  if (!rc)
    {
      int existed;

      if (!keydb_store_cert (cert, 0, &existed))
        {
          KsbaCert next = NULL;

          if (!existed)
            {
              print_imported_status (ctrl, cert);
              stats->imported++;
            }
          else
            stats->unchanged++;
            
          if (opt.verbose > 1 && existed)
            {
              if (depth)
                log_info ("issuer certificate already in DB\n");
              else
                log_info ("certificate already in DB\n");
            }
          else if (opt.verbose && !existed)
            {
              if (depth)
                log_info ("issuer certificate imported\n");
              else
                log_info ("certificate imported\n");
            }
          /* Now lets walk up the chain and import all certificates up
             the chain.*/
          else if (!gpgsm_walk_cert_chain (cert, &next))
            {
              check_and_store (ctrl, stats, next, depth+1);
              ksba_cert_release (next);
            }
        }
      else
        {
          log_error (_("error storing certificate\n"));
          stats->not_imported++;
          print_import_problem (ctrl, cert, 4);
        }
    }
  else
    {
      log_error (_("basic certificate checks failed - not imported\n"));
      stats->not_imported++;
      print_import_problem (ctrl, cert,
                            gpg_err_code (rc) == GPG_ERR_MISSING_CERT? 2 :
                            gpg_err_code (rc) == GPG_ERR_BAD_CERT?     1 : 0);
    }
}




static int
import_one (CTRL ctrl, struct stats_s *stats, int in_fd)
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
      rc = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("fdopen() failed: %s\n", strerror (errno));
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
          rc = gpg_error (GPG_ERR_ENOMEM);
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
          check_and_store (ctrl, stats, cert, 0);
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
          rc = gpg_error (GPG_ERR_ENOMEM);
          goto leave;
        }

      rc = ksba_cert_read_der (cert, reader);
      if (rc)
        {
          rc = map_ksba_err (rc);
          goto leave;
        }

      check_and_store (ctrl, stats, cert, 0);
    }
  else
    {
      log_error ("can't extract certificates from input\n");
      rc = gpg_error (GPG_ERR_NO_DATA);
    }
   
 leave:
  ksba_cms_release (cms);
  ksba_cert_release (cert);
  gpgsm_destroy_reader (b64reader);
  if (fp)
    fclose (fp);
  return rc;
}


int
gpgsm_import (CTRL ctrl, int in_fd)
{
  int rc;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);
  rc = import_one (ctrl, &stats, in_fd);
  print_imported_summary (ctrl, &stats);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gnupg_strerror (rc));
  return rc;
}


int
gpgsm_import_files (CTRL ctrl, int nfiles, char **files,
                    int (*of)(const char *fname))
{
  int rc = 0;
  struct stats_s stats;

  memset (&stats, 0, sizeof stats);
  
  if (!nfiles)
    rc = import_one (ctrl, &stats, 0);
  else
    {
      for (; nfiles && !rc ; nfiles--, files++)
        {
          int fd = of (*files);
          rc = import_one (ctrl, &stats, fd);
          close (fd);
          if (rc == -1)
            rc = 0;
        }
    }
  print_imported_summary (ctrl, &stats);
  /* If we never printed an error message do it now so that a command
     line invocation will return with an error (log_error keeps a
     global errorcount) */
  if (rc && !log_get_errorcount (0))
    log_error (_("error importing certificate: %s\n"), gnupg_strerror (rc));
  return rc;
}


