/* encrypt.c - Encrypt a message
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


KsbaCert
get_default_recipient (void)
{
  return NULL;
}



/* Perform an encrypt operation.  

   Encrypt the data received on DATA-FD and write it to OUT_FP.  The
   recipients are hardwired for now. */
int
gpgsm_encrypt (CTRL ctrl, int data_fd, FILE *out_fp)
{
  int i, rc;
  Base64Context b64reader = NULL;
  Base64Context b64writer = NULL;
  KsbaError err;
  KsbaWriter writer;
  KsbaReader reader;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KsbaCert cert;
  KEYDB_HANDLE kh = NULL;
  GCRY_MD_HD data_md = NULL;
  int signer;
  const char *algoid;
  FILE *data_fp = NULL;
  int algo;


  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }

  data_fp = fdopen ( dup (data_fd), "rb");
  if (!data_fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, data_fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  rc = gpgsm_create_writer (&b64writer, ctrl, out_fp, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  cms = ksba_cms_new ();
  if (!cms)
    {
      rc = seterr (Out_Of_Core);
      goto leave;
    }

  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  /* We are going to create signed data with data as encap. content */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_ENVELOPED_DATA);
  if (!err)
    err = ksba_cms_set_content_type (cms, 1, KSBA_CT_ENCRYPTED_DATA);
  if (err)
    {
      log_debug ("ksba_cms_set_content_type failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }


  /* gather certificates of recipients and store them in the CMS object */
  cert = get_default_recipient ();
  if (!cert)
    {
      log_error ("no default recipient found\n");
      rc = seterr (General_Error);
      goto leave;
    }
/*    err = ksba_cms_add_signer (cms, cert); */
/*    if (err) */
/*      { */
/*        log_debug ("ksba_cms_add_signer failed: %s\n",  ksba_strerror (err)); */
/*        rc = map_ksba_err (err); */
/*        goto leave; */
/*      } */
  cert = NULL; /* cms does now own the certificate */

  /* Set the hash algorithm we are going to use */
  err = ksba_cms_add_digest_algo (cms, "1.3.14.3.2.26" /*SHA-1*/);
  if (err)
    {
      log_debug ("ksba_cms_add_digest_algo failed: %s\n", ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  /* Prepare hashing (actually we are figuring out what we have set above)*/
  data_md = gcry_md_open (0, 0);
  if (!data_md)
    {
      rc = map_gcry_err (gcry_errno());
      log_error ("md_open failed: %s\n", gcry_strerror (-1));
      goto leave;
    }
  for (i=0; (algoid=ksba_cms_get_digest_algo_list (cms, i)); i++)
    {
      algo = gcry_md_map_name (algoid);
      if (!algo)
        {
          log_error ("unknown hash algorithm `%s'\n", algoid? algoid:"?");
          rc = GNUPG_Bug;
          goto leave;
        }
      gcry_md_enable (data_md, algo);
    }

  signer = 0;
  do 
    {
      err = ksba_cms_build (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_build failed: %s\n", ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }
      log_debug ("ksba_cms_build - stop reason %d\n", stopreason);

      if (stopreason == KSBA_SR_BEGIN_DATA)
        { 
        }
      else if (stopreason == KSBA_SR_NEED_SIG)
        { /* calculate the signature for all signers */
          GCRY_MD_HD md;

          algo = GCRY_MD_SHA1;
          signer = 0;
          md = gcry_md_open (algo, 0);
          if (!md)
            {
              log_error ("md_open failed: %s\n", gcry_strerror (-1));
              goto leave;
            }
          ksba_cms_set_hash_function (cms, HASH_FNC, md);
          rc = ksba_cms_hash_signed_attrs (cms, signer);
          if (rc)
            {
              log_debug ("hashing signed attrs failed: %s\n",
                         ksba_strerror (rc));
              gcry_md_close (md);
              goto leave;
            }
          
          { /* This is all an temporary hack */
            char *sigval;

            cert = NULL;
            if (!cert)
              {
                log_error ("oops - failed to get cert again\n");
                rc = seterr (General_Error);
                goto leave;
              }

            sigval = NULL;
            rc = gpgsm_create_cms_signature (cert, md, algo, &sigval);
            if (rc)
              {
                ksba_cert_release (cert);
                goto leave;
              }

            err = ksba_cms_set_sig_val (cms, signer, sigval);
            xfree (sigval);
            if (err)
              {
                log_error ("failed to store the signature: %s\n",
                           ksba_strerror (err));
                rc = map_ksba_err (err);
                goto leave;
              }
          }
        }
    }
  while (stopreason != KSBA_SR_READY);   

  log_info ("signature created\n");

 leave:
  ksba_cms_release (cms);
  gpgsm_destroy_writer (b64writer);
  gpgsm_destroy_reader (b64reader);
  keydb_release (kh); 
  gcry_md_close (data_md);
  if (data_fp)
    fclose (data_fp);
  return rc;
}
