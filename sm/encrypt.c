/* encrypt.c - Encrypt a message
 * Copyright (C) 2001, 2003, 2004, 2007, 2008 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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


struct dek_s {
  const char *algoid;
  int algo;
  gcry_cipher_hd_t chd;
  char key[32];
  int keylen;
  char iv[32];
  int ivlen;
};
typedef struct dek_s *DEK;

struct encrypt_cb_parm_s {
  FILE *fp;
  DEK dek;
  int eof_seen;
  int ready;
  int readerror;
  int bufsize;
  unsigned char *buffer;
  int buflen;
};





/* Initialize the data encryption key (session key). */
static int
init_dek (DEK dek)
{
  int rc=0, mode, i;

  dek->algo = gcry_cipher_map_name (dek->algoid);
  mode = gcry_cipher_mode_from_oid (dek->algoid);
  if (!dek->algo || !mode)
    {
      log_error ("unsupported algorithm `%s'\n", dek->algoid);
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }
  
  /* Extra check for algorithms we consider to be too weak for
     encryption, although we support them for decryption.  Note that
     there is another check below discriminating on the key length. */
  switch (dek->algo)
    {
    case GCRY_CIPHER_DES:
    case GCRY_CIPHER_RFC2268_40:
      log_error ("cipher algorithm `%s' not allowed: too weak\n",
                 gcry_cipher_algo_name (dek->algo));
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    default:
      break;
    }

  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);
  if (!dek->keylen || dek->keylen > sizeof (dek->key))
    return gpg_error (GPG_ERR_BUG);

  dek->ivlen = gcry_cipher_get_algo_blklen (dek->algo);
  if (!dek->ivlen || dek->ivlen > sizeof (dek->iv))
    return gpg_error (GPG_ERR_BUG);

  /* Make sure we don't use weak keys. */
  if (dek->keylen < 100/8)
    { 
      log_error ("key length of `%s' too small\n", dek->algoid);
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }
  
  rc = gcry_cipher_open (&dek->chd, dek->algo, mode, GCRY_CIPHER_SECURE);
  if (rc)
    {
      log_error ("failed to create cipher context: %s\n", gpg_strerror (rc));
      return rc;
    }
  
  for (i=0; i < 8; i++)
    {
      gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM );
      rc = gcry_cipher_setkey (dek->chd, dek->key, dek->keylen);
      if (gpg_err_code (rc) != GPG_ERR_WEAK_KEY)
        break;
      log_info(_("weak key created - retrying\n") );
    }
  if (rc)
    {
      log_error ("failed to set the key: %s\n", gpg_strerror (rc));
      gcry_cipher_close (dek->chd);
      dek->chd = NULL;
      return rc;
    }

  gcry_create_nonce (dek->iv, dek->ivlen);
  rc = gcry_cipher_setiv (dek->chd, dek->iv, dek->ivlen);
  if (rc)
    {
      log_error ("failed to set the IV: %s\n", gpg_strerror (rc));
      gcry_cipher_close (dek->chd);
      dek->chd = NULL;
      return rc;
    }
  
  return 0;
}


static int
encode_session_key (DEK dek, gcry_sexp_t * r_data)
{
  gcry_sexp_t data;
  char *p;
  int rc;

  p = xtrymalloc (64 + 2 * dek->keylen);
  if (!p)
    return gpg_error_from_syserror ();
  strcpy (p, "(data\n (flags pkcs1)\n (value #");
  bin2hex (dek->key, dek->keylen, p + strlen (p));
  strcat (p, "#))\n");
  rc = gcry_sexp_sscan (&data, NULL, p, strlen (p));
  xfree (p);
  *r_data = data;
  return rc;    
}


/* Encrypt the DEK under the key contained in CERT and return it as a
   canonical S-Exp in encval. */
static int
encrypt_dek (const DEK dek, ksba_cert_t cert, unsigned char **encval)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc;
  ksba_sexp_t buf;
  size_t len;

  *encval = NULL;

  /* get the key from the cert */
  buf = ksba_cert_get_public_key (cert);
  if (!buf)
    {
      log_error ("no public key for recipient\n");
      return gpg_error (GPG_ERR_NO_PUBKEY);
    }
  len = gcry_sexp_canon_len (buf, 0, NULL, NULL);
  if (!len)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      return gpg_error (GPG_ERR_BUG);
    }
  rc = gcry_sexp_sscan (&s_pkey, NULL, (char*)buf, len);
  xfree (buf); buf = NULL;
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  /* Put the encoded cleartext into a simple list. */
  s_data = NULL; /* (avoid compiler warning) */
  rc = encode_session_key (dek, &s_data);
  if (rc)
    {
      log_error ("encode_session_key failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);
  
  /* Reformat it. */
  rc = make_canon_sexp (s_ciph, encval, NULL);
  gcry_sexp_release (s_ciph);
  return rc;
}



/* do the actual encryption */
static int
encrypt_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  struct encrypt_cb_parm_s *parm = cb_value;
  int blklen = parm->dek->ivlen;
  unsigned char *p;
  size_t n;

  *nread = 0;
  if (!buffer)
    return -1; /* not supported */

  if (parm->ready)
    return -1;

  if (count < blklen)
    BUG ();
     
  if (!parm->eof_seen)
    { /* fillup the buffer */
      p = parm->buffer;
      for (n=parm->buflen; n < parm->bufsize; n++)
        {
          int c = getc (parm->fp);
          if (c == EOF)
            {
              if (ferror (parm->fp))
                {
                  parm->readerror = errno;
                  return -1;
                }
              parm->eof_seen = 1;
              break; 
            }
          p[n] = c;
        }
      parm->buflen = n;
    }
  
  n = parm->buflen < count? parm->buflen : count;
  n = n/blklen * blklen;
  if (n)
    { /* encrypt the stuff */
      gcry_cipher_encrypt (parm->dek->chd, buffer, n, parm->buffer, n);
      *nread = n;
      /* Who cares about cycles, take the easy way and shift the buffer */
      parm->buflen -= n;
      memmove (parm->buffer, parm->buffer+n, parm->buflen);
    }
  else if (parm->eof_seen)
    { /* no complete block but eof: add padding */
      /* fixme: we should try to do this also in the above code path */
      int i, npad = blklen - (parm->buflen % blklen);
      p = parm->buffer;
      for (n=parm->buflen, i=0; n < parm->bufsize && i < npad; n++, i++)
        p[n] = npad;
      gcry_cipher_encrypt (parm->dek->chd, buffer, n, parm->buffer, n);
      *nread = n;
      parm->ready = 1;
    }

  return 0;
}




/* Perform an encrypt operation.  

   Encrypt the data received on DATA-FD and write it to OUT_FP.  The
   recipients are take from the certificate given in recplist; if this
   is NULL it will be encrypted for a default recipient */
int
gpgsm_encrypt (ctrl_t ctrl, certlist_t recplist, int data_fd, FILE *out_fp)
{
  int rc = 0;
  Base64Context b64writer = NULL;
  gpg_error_t err;
  ksba_writer_t writer;
  ksba_reader_t reader = NULL;
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  KEYDB_HANDLE kh = NULL;
  struct encrypt_cb_parm_s encparm;
  DEK dek = NULL;
  int recpno;
  FILE *data_fp = NULL;
  certlist_t cl;
  int count;

  memset (&encparm, 0, sizeof encparm);

  audit_set_type (ctrl->audit, AUDIT_TYPE_ENCRYPT);

  /* Check that the certificate list is not empty and that at least
     one certificate is not flagged as encrypt_to; i.e. is a real
     recipient. */
  for (cl = recplist; cl; cl = cl->next)
    if (!cl->is_encrypt_to)
      break;
  if (!cl)
    {
      log_error(_("no valid recipients given\n"));
      gpgsm_status (ctrl, STATUS_NO_RECP, "0");
      audit_log_i (ctrl->audit, AUDIT_GOT_RECIPIENTS, 0);
      rc = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  for (count = 0, cl = recplist; cl; cl = cl->next)
    count++;
  audit_log_i (ctrl->audit, AUDIT_GOT_RECIPIENTS, count);

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  data_fp = fdopen ( dup (data_fd), "rb");
  if (!data_fp)
    {
      rc = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("fdopen() failed: %s\n", strerror (errno));
      goto leave;
    }

  err = ksba_reader_new (&reader);
  if (err)
      rc = err;
  if (!rc)
    rc = ksba_reader_set_cb (reader, encrypt_cb, &encparm);
  if (rc)
      goto leave;

  encparm.fp = data_fp;

  ctrl->pem_name = "ENCRYPTED MESSAGE";
  rc = gpgsm_create_writer (&b64writer, ctrl, out_fp, NULL, &writer);
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

  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

  audit_log (ctrl->audit, AUDIT_GOT_DATA);

  /* We are going to create enveloped data with uninterpreted data as
     inner content */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_ENVELOPED_DATA);
  if (!err)
    err = ksba_cms_set_content_type (cms, 1, KSBA_CT_DATA);
  if (err)
    {
      log_debug ("ksba_cms_set_content_type failed: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

  /* Create a session key */
  dek = xtrycalloc_secure (1, sizeof *dek); 
  if (!dek)
    rc = out_of_core ();
  else
  {
    dek->algoid = opt.def_cipher_algoid;
    rc = init_dek (dek);
  }
  if (rc)
    {
      log_error ("failed to create the session key: %s\n",
                 gpg_strerror (rc));
      goto leave;
    }

  err = ksba_cms_set_content_enc_algo (cms, dek->algoid, dek->iv, dek->ivlen);
  if (err)
    {
      log_error ("ksba_cms_set_content_enc_algo failed: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

  encparm.dek = dek;
  /* Use a ~8k (AES) or ~4k (3DES) buffer */
  encparm.bufsize = 500 * dek->ivlen;
  encparm.buffer = xtrymalloc (encparm.bufsize);
  if (!encparm.buffer)
    {
      rc = out_of_core ();
      goto leave;
    }
  
  audit_log_s (ctrl->audit, AUDIT_SESSION_KEY, dek->algoid);

  /* Gather certificates of recipients, encrypt the session key for
     each and store them in the CMS object */
  for (recpno = 0, cl = recplist; cl; recpno++, cl = cl->next)
    {
      unsigned char *encval;
      
      rc = encrypt_dek (dek, cl->cert, &encval);
      if (rc)
        {
          audit_log_cert (ctrl->audit, AUDIT_ENCRYPTED_TO, cl->cert, rc);
          log_error ("encryption failed for recipient no. %d: %s\n",
                     recpno, gpg_strerror (rc));
          goto leave;
        }
      
      err = ksba_cms_add_recipient (cms, cl->cert);
      if (err)
        {
          audit_log_cert (ctrl->audit, AUDIT_ENCRYPTED_TO, cl->cert, err);
          log_error ("ksba_cms_add_recipient failed: %s\n",
                     gpg_strerror (err));
          rc = err;
          xfree (encval);
          goto leave;
        }
      
      err = ksba_cms_set_enc_val (cms, recpno, encval);
      xfree (encval);
      audit_log_cert (ctrl->audit, AUDIT_ENCRYPTED_TO, cl->cert, err);
      if (err)
        {
          log_error ("ksba_cms_set_enc_val failed: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }

  /* Main control loop for encryption. */
  recpno = 0;
  do 
    {
      err = ksba_cms_build (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_build failed: %s\n", gpg_strerror (err));
          rc = err;
          goto leave;
        }
    }
  while (stopreason != KSBA_SR_READY);   

  if (encparm.readerror)
    {
      log_error ("error reading input: %s\n", strerror (encparm.readerror));
      rc = gpg_error (gpg_err_code_from_errno (encparm.readerror));
      goto leave;
    }


  rc = gpgsm_finish_writer (b64writer);
  if (rc) 
    {
      log_error ("write failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
  audit_log (ctrl->audit, AUDIT_ENCRYPTION_DONE);
  log_info ("encrypted data created\n");

 leave:
  ksba_cms_release (cms);
  gpgsm_destroy_writer (b64writer);
  ksba_reader_release (reader);
  keydb_release (kh); 
  xfree (dek);
  if (data_fp)
    fclose (data_fp);
  xfree (encparm.buffer);
  return rc;
}
