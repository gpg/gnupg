/* sign.c - Sign a message
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


static void
hash_data (int fd, GCRY_MD_HD md)
{
  FILE *fp;
  char buffer[4096];
  int nread;

  fp = fdopen ( dup (fd), "rb");
  if (!fp)
    {
      log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
      return;
    }

  do 
    {
      nread = fread (buffer, 1, DIM(buffer), fp);
      gcry_md_write (md, buffer, nread);
    }
  while (nread);
  if (ferror (fp))
      log_error ("read error on fd %d: %s\n", fd, strerror (errno));
  fclose (fp);
}


static KsbaCert
get_default_signer (void)
{
  //  const char key[] = "1.2.840.113549.1.9.1=#7472757374407765622E6465#,CN=WEB.DE TrustCenter,OU=TrustCenter,O=WEB.DE AG,L=D-76227 Karlsruhe,C=DE";
  const char key[] =
    "/CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=Düsseldorf,C=DE";

  KsbaCert cert = NULL;
  KEYDB_HANDLE kh = NULL;
  int rc;

  kh = keydb_new (0);
  if (!kh)
    return NULL;

  rc = keydb_search_subject (kh, key);
  if (rc)
    {
      log_debug ("failed to find default certificate: rc=%d\n", rc);
    }
  else 
    {
      rc = keydb_get_cert (kh, &cert);
      if (rc)
        {
          log_debug ("failed to get cert: rc=%d\n", rc);
        }
    }

  keydb_release (kh);
  return cert;
}



/* Perform a sign operation.  

   Sign the data received on DATA-FD in embedded mode or in deatched
   mode when DETACHED is true.  Write the signature to OUT_FP The key
   used to sign is the default - we will extend the fucntion to take a
   list of fingerprints in the future. */
int
gpgsm_sign (CTRL ctrl, int data_fd, int detached, FILE *out_fp)
{
  int i, rc;
  KsbaError err;
  Base64Context b64writer = NULL;
  KsbaWriter writer;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KsbaCert cert;
  KEYDB_HANDLE kh = NULL;
  GCRY_MD_HD data_md = NULL;
  int signer;
  const char *algoid;
  int algo;

  if (!detached)
    {
       rc = seterr (Not_Implemented);
       goto leave;
    }


  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
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

  err = ksba_cms_set_reader_writer (cms, NULL, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  /* We are going to create signed data with data as encap. content */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_SIGNED_DATA);
  if (!err)
    err = ksba_cms_set_content_type (cms, 1, KSBA_CT_DATA);
  if (err)
    {
      log_debug ("ksba_cms_set_content_type failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }


  /* gather certificates of signers  and store in theCMS object */
  /* fixme: process a list of fingerprints and store the certificate of
     each given fingerprint */
  cert = get_default_signer ();
  if (!cert)
    {
      log_error ("no default signer found\n");
      rc = seterr (General_Error);
      goto leave;
    }
  err = ksba_cms_add_signer (cms, cert);
  if (err)
    {
      log_debug ("ksba_cms_add_signer failed: %s\n",  ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }
  ksba_cert_release (cert); cert = NULL;

  /* fixme: We might want to include a list of certificate which are
     put as info into the signed data object - maybe we should add a
     flag to ksba_cms_add_signer to decider whether this cert should
     be send along with the signature */
  
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
  if (detached)
    { /* we hash the data right now so that we can store the message
         digest.  ksba_cms_build() takes this as an flag that detached
         data is expected. */
      unsigned char *digest;
      size_t digest_len;
      /* Fixme do this for all signers and get the algo to use from
         the signer's certificate - does not make mich sense, bu we
         should do this consistent as we have already done it above */
      algo = GCRY_MD_SHA1; 
      hash_data (data_fd, data_md);
      digest = gcry_md_read (data_md, algo);
      digest_len = gcry_md_get_algo_dlen (algo);
      if ( !digest || !digest_len)
        {
          log_error ("problem getting the hash of the data\n");
          rc = GNUPG_Bug;
          goto leave;
        }
      err = ksba_cms_set_message_digest (cms, signer, digest, digest_len);
      if (err)
        {
          log_error ("ksba_cms_set_message_digest failed: %s\n",
                     ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }
    }
#if 0
  err = ksba_cms_set_signing_time (cms, signer, 0 /*now*/);
  if (err)
    {
      log_error ("ksba_cms_set_signing_time failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }
#endif
  do 
    {
      err = ksba_cms_build (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_build failed: %s\n", ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }

      if (stopreason == KSBA_SR_BEGIN_DATA)
        { /* hash the data and store the message digest */
          assert (!detached);
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

            cert = get_default_signer ();
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

  rc = gpgsm_finish_writer (b64writer);
  if (rc) 
    {
      log_error ("write failed: %s\n", gnupg_strerror (rc));
      goto leave;
    }
  log_info ("signature created\n");

 leave:
  ksba_cms_release (cms);
  gpgsm_destroy_writer (b64writer);
  keydb_release (kh); 
  gcry_md_close (data_md);
  return rc;
}
