/* sign.c - Sign a message
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "i18n.h"


static void
hash_data (int fd, gcry_md_hd_t md)
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

static int
hash_and_copy_data (int fd, gcry_md_hd_t md, KsbaWriter writer)
{
  KsbaError err;
  FILE *fp;
  char buffer[4096];
  int nread;
  int rc = 0;
  int any = 0;

  fp = fdopen ( dup (fd), "rb");
  if (!fp)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
      return tmperr;
    }

  do 
    {
      nread = fread (buffer, 1, DIM(buffer), fp);
      if (nread)
        {
          any = 1;
          gcry_md_write (md, buffer, nread);
          err = ksba_writer_write_octet_string (writer, buffer, nread, 0);
          if (err)
            {
              log_error ("write failed: %s\n", gpg_strerror (err));
              rc = err;
            }
        }
    }
  while (nread && !rc);
  if (ferror (fp))
    {
      rc = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("read error on fd %d: %s\n", fd, strerror (errno));
    }
  fclose (fp);
  if (!any)
    {
      /* We can't allow to sign an empty message because it does not
         make much sense and more seriously, ksba-cms_build has
         already written the tag for data and now expects an octet
         string but an octet string of zeize 0 is illegal. */
      log_error ("cannot sign an empty message\n");
      rc = gpg_error (GPG_ERR_NO_DATA);
    }
  if (!rc)
    {
      err = ksba_writer_write_octet_string (writer, NULL, 0, 1);
      if (err)
        {
          log_error ("write failed: %s\n", gpg_strerror (err));
          rc = err;
        }
    }

  return rc;
}


/* Get the default certificate which is defined as the first one our
   keyDB retruns and has a secret key available */
int
gpgsm_get_default_cert (KsbaCert *r_cert)
{
  KEYDB_HANDLE hd;
  KsbaCert cert = NULL;
  int rc;
  char *p;

  hd = keydb_new (0);
  if (!hd)
    return gpg_error (GPG_ERR_GENERAL);
  rc = keydb_search_first (hd);
  if (rc)
    {
      keydb_release (hd);
      return rc;
    }

  do
    {
      rc = keydb_get_cert (hd, &cert);
      if (rc) 
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          keydb_release (hd);
          return rc;
        }
      
      p = gpgsm_get_keygrip_hexstring (cert);
      if (p)
        {
          if (!gpgsm_agent_havekey (p))
            {
              xfree (p);
              keydb_release (hd);
              *r_cert = cert;
              return 0; /* got it */
            }
          xfree (p);
        }
    
      ksba_cert_release (cert); 
      cert = NULL;
    }
  while (!(rc = keydb_search_next (hd)));
  if (rc && rc != -1)
    log_error ("keydb_search_next failed: %s\n", gpg_strerror (rc));
  
  ksba_cert_release (cert);
  keydb_release (hd);
  return rc;
}


static KsbaCert
get_default_signer (void)
{
  KEYDB_SEARCH_DESC desc;
  KsbaCert cert = NULL;
  KEYDB_HANDLE kh = NULL;
  int rc;

  if (!opt.local_user)
    {
      rc = gpgsm_get_default_cert (&cert);
      if (rc)
        {
          if (rc != -1)
            log_debug ("failed to find default certificate: %s\n",
                       gpg_strerror (rc));
          return NULL;
        }
      return cert;
    }

  rc = keydb_classify_name (opt.local_user, &desc);
  if (rc)
    {
      log_error ("failed to find default signer: %s\n", gpg_strerror (rc));
      return NULL;
    }

  kh = keydb_new (0);
  if (!kh)
    return NULL;

  rc = keydb_search (kh, &desc, 1);
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

/* Depending on the options in CTRL add the certificate CERT as well as
   other certificate up in the chain to the Root-CA to the CMS
   object. */
static int 
add_certificate_list (CTRL ctrl, KsbaCMS cms, KsbaCert cert)
{
  KsbaError err;
  int rc = 0;
  KsbaCert next = NULL;
  int n;
  int not_root = 0;

  ksba_cert_ref (cert);

  n = ctrl->include_certs;
  if (n == -2)
    {
      not_root = 1;
      n = -1;
    }
  if (n < 0 || n > 50)
    n = 50; /* We better apply an upper bound */

  if (n)
    {
      if (not_root && gpgsm_is_root_cert (cert))
        err = 0;
      else
        err = ksba_cms_add_cert (cms, cert);
      if (err)
        goto ksba_failure;
    }
  while ( n-- && !(rc = gpgsm_walk_cert_chain (cert, &next)) )
    {
      if (not_root && gpgsm_is_root_cert (next))
        err = 0;
      else
        err = ksba_cms_add_cert (cms, next);
      ksba_cert_release (cert);
      cert = next; next = NULL;
      if (err)
        goto ksba_failure;
    }
  ksba_cert_release (cert);

  return rc == -1? 0: rc;

 ksba_failure:
  ksba_cert_release (cert);
  log_error ("ksba_cms_add_cert failed: %s\n", gpg_strerror (err));
  return err;
}




/* Perform a sign operation.  

   Sign the data received on DATA-FD in embedded mode or in detached
   mode when DETACHED is true.  Write the signature to OUT_FP.  The
   keys used to sign are taken from SIGNERLIST or the default one will
   be used if the value of this argument is NULL. */
int
gpgsm_sign (CTRL ctrl, CERTLIST signerlist,
            int data_fd, int detached, FILE *out_fp)
{
  int i, rc;
  KsbaError err;
  Base64Context b64writer = NULL;
  KsbaWriter writer;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KEYDB_HANDLE kh = NULL;
  gcry_md_hd_t data_md = NULL;
  int signer;
  const char *algoid;
  int algo;
  ksba_isotime_t signed_at;
  CERTLIST cl;
  int release_signerlist = 0;

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  ctrl->pem_name = "SIGNED MESSAGE";
  rc = gpgsm_create_writer (&b64writer, ctrl, out_fp, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (rc));
      goto leave;
    }

  err = ksba_cms_new (&cms);
  if (err)
    {
      rc = err;
      goto leave;
    }

  err = ksba_cms_set_reader_writer (cms, NULL, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

  /* We are going to create signed data with data as encap. content */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_SIGNED_DATA);
  if (!err)
    err = ksba_cms_set_content_type (cms, 1, KSBA_CT_DATA);
  if (err)
    {
      log_debug ("ksba_cms_set_content_type failed: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

  /* If no list of signers is given, use a default one. */
  if (!signerlist)
    {
      KsbaCert cert = get_default_signer ();
      if (!cert)
        {
          log_error ("no default signer found\n");
          rc = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
      signerlist = xtrycalloc (1, sizeof *signerlist);
      if (!signerlist)
        {
          rc = OUT_OF_CORE (errno);
          ksba_cert_release (cert);
          goto leave;
        }
      signerlist->cert = cert;
      release_signerlist = 1;
    }


  /* Gather certificates of signers and store them in the CMS object. */
  for (cl=signerlist; cl; cl = cl->next)
    {
      rc = gpgsm_cert_use_sign_p (cl->cert);
      if (rc)
        goto leave;
      
      err = ksba_cms_add_signer (cms, cl->cert);
      if (err)
        {
          log_error ("ksba_cms_add_signer failed: %s\n", gpg_strerror (err));
          rc = err;
          goto leave;
        }
      rc = add_certificate_list (ctrl, cms, cl->cert);
      if (rc)
        {
          log_error ("failed to store list of certificates: %s\n",
                     gpg_strerror(rc));
          goto leave;
        }
      /* Set the hash algorithm we are going to use */
      err = ksba_cms_add_digest_algo (cms, "1.3.14.3.2.26" /*SHA-1*/);
      if (err)
        {
          log_debug ("ksba_cms_add_digest_algo failed: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }
  
  /* Prepare hashing (actually we are figuring out what we have set above)*/
  rc = gcry_md_open (&data_md, 0, 0);
  if (rc)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
  if (DBG_HASHING)
    gcry_md_start_debug (data_md, "sign.data");

  for (i=0; (algoid=ksba_cms_get_digest_algo_list (cms, i)); i++)
    {
      algo = gcry_md_map_name (algoid);
      if (!algo)
        {
          log_error ("unknown hash algorithm `%s'\n", algoid? algoid:"?");
          rc = gpg_error (GPG_ERR_BUG);
          goto leave;
        }
      gcry_md_enable (data_md, algo);
    }

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
          rc = gpg_error (GPG_ERR_BUG);
          goto leave;
        }
      for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
        {
          err = ksba_cms_set_message_digest (cms, signer, digest, digest_len);
          if (err)
            {
              log_error ("ksba_cms_set_message_digest failed: %s\n",
                         gpg_strerror (err));
              rc = err;
              goto leave;
            }
        }
    }

  gnupg_get_isotime (signed_at);
  for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
    {
      err = ksba_cms_set_signing_time (cms, signer, signed_at);
      if (err)
        {
          log_error ("ksba_cms_set_signing_time failed: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }

  do 
    {
      err = ksba_cms_build (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_build failed: %s\n", gpg_strerror (err));
          rc = err;
          goto leave;
        }

      if (stopreason == KSBA_SR_BEGIN_DATA)
        { /* hash the data and store the message digest */
          unsigned char *digest;
          size_t digest_len;

          assert (!detached);
          /* Fixme: get the algo to use from the signer's certificate
             - does not make much sense, but we should do this
             consistent as we have already done it above.  Code is
             mostly duplicated above. */

          algo = GCRY_MD_SHA1; 
          rc = hash_and_copy_data (data_fd, data_md, writer);
          if (rc)
            goto leave;
          digest = gcry_md_read (data_md, algo);
          digest_len = gcry_md_get_algo_dlen (algo);
          if ( !digest || !digest_len)
            {
              log_error ("problem getting the hash of the data\n");
              rc = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
            {
              err = ksba_cms_set_message_digest (cms, signer,
                                                 digest, digest_len);
              if (err)
                {
                  log_error ("ksba_cms_set_message_digest failed: %s\n",
                             gpg_strerror (err));
                  rc = err;
                  goto leave;
                }
            }
        }
      else if (stopreason == KSBA_SR_NEED_SIG)
        { /* calculate the signature for all signers */
          gcry_md_hd_t md;

          algo = GCRY_MD_SHA1;
          rc = gcry_md_open (&md, algo, 0);
          if (rc)
            {
              log_error ("md_open failed: %s\n", gpg_strerror (rc));
              goto leave;
            }
          if (DBG_HASHING)
            gcry_md_start_debug (md, "sign.attr");
          ksba_cms_set_hash_function (cms, HASH_FNC, md);
          for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
            {
              char *sigval = NULL;
              char *buf, *fpr;

              if (signer)
                gcry_md_reset (md);
              rc = ksba_cms_hash_signed_attrs (cms, signer);
              if (rc)
                {
                  log_debug ("hashing signed attrs failed: %s\n",
                             gpg_strerror (rc));
                  gcry_md_close (md);
                  goto leave;
                }
            
              rc = gpgsm_create_cms_signature (cl->cert, md, algo, &sigval);
              if (rc)
                {
                  gcry_md_close (md);
                  goto leave;
                }

              err = ksba_cms_set_sig_val (cms, signer, sigval);
              xfree (sigval);
              if (err)
                {
                  log_error ("failed to store the signature: %s\n",
                             gpg_strerror (err));
                  rc = err;
                  gcry_md_close (md);
                  goto leave;
                }

              /* write a status message */
              fpr = gpgsm_get_fingerprint_hexstring (cl->cert, GCRY_MD_SHA1);
              if (!fpr)
                {
                  rc = gpg_error (GPG_ERR_ENOMEM);
                  gcry_md_close (md);
                  goto leave;
                }
              rc = asprintf (&buf, "%c %d %d 00 %s %s",
                             detached? 'D':'S',
                             GCRY_PK_RSA,  /* FIXME: get pk algo from cert */
                             algo, 
                             signed_at,
                             fpr);
              xfree (fpr);
              if (rc < 0)
                {
                  rc = gpg_error (GPG_ERR_ENOMEM);
                  gcry_md_close (md);
                  goto leave;
                }
              rc = 0;
              gpgsm_status (ctrl, STATUS_SIG_CREATED, buf);
              free (buf); /* yes, we must use the regular free() here */
            }
          gcry_md_close (md);

        }
    }
  while (stopreason != KSBA_SR_READY);   

  rc = gpgsm_finish_writer (b64writer);
  if (rc) 
    {
      log_error ("write failed: %s\n", gpg_strerror (rc));
      goto leave;
    }

  log_info ("signature created\n");


 leave:
  if (release_signerlist)
    gpgsm_release_certlist (signerlist);
  ksba_cms_release (cms);
  gpgsm_destroy_writer (b64writer);
  keydb_release (kh); 
  gcry_md_close (data_md);
  return rc;
}
