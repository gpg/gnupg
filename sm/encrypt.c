/* encrypt.c - Encrypt a message
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





/* initialize the data encryptionkey (session key) */
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

  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);
  if (!dek->keylen || dek->keylen > sizeof (dek->key))
    return gpg_error (GPG_ERR_BUG);

  dek->ivlen = gcry_cipher_get_algo_blklen (dek->algo);
  if (!dek->ivlen || dek->ivlen > sizeof (dek->iv))
    return gpg_error (GPG_ERR_BUG);

  if (dek->keylen < 100/8)
    { /* make sure we don't use weak keys */
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

  gcry_randomize (dek->iv, dek->ivlen, GCRY_STRONG_RANDOM);
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
  char * p, tmp[3];
  int i;
  int rc;

  p = xmalloc (64 + 2 * dek->keylen);
  strcpy (p, "(data\n (flags pkcs1)\n (value #");
  for (i=0; i < dek->keylen; i++)
    {
      sprintf (tmp, "%02x", (unsigned char) dek->key[i]);
      strcat (p, tmp);   
    }
  strcat (p, "#))\n");
  rc = gcry_sexp_sscan (&data, NULL, p, strlen (p));
  xfree (p);
  *r_data = data;
  return rc;    
}


/* encrypt the DEK under the key contained in CERT and return it as a
   canonical S-Exp in encval */
static int
encrypt_dek (const DEK dek, KsbaCert cert, char **encval)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc;
  KsbaSexp buf;
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
  rc = gcry_sexp_sscan (&s_pkey, NULL, buf, len);
  xfree (buf); buf = NULL;
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  /* put the encoded cleartext into a simple list */
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
  
  /* reformat it */
  len = gcry_sexp_sprint (s_ciph, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len); 
  buf = xtrymalloc (len);
  if (!buf)
    {
      gpg_error_t tmperr = OUT_OF_CORE (errno);
      gcry_sexp_release (s_ciph);
      return tmperr;
    }
  len = gcry_sexp_sprint (s_ciph, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  *encval = buf;
  return 0;
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
gpgsm_encrypt (CTRL ctrl, CERTLIST recplist, int data_fd, FILE *out_fp)
{
  int rc = 0;
  Base64Context b64writer = NULL;
  KsbaError err;
  KsbaWriter writer;
  KsbaReader reader = NULL;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KEYDB_HANDLE kh = NULL;
  struct encrypt_cb_parm_s encparm;
  DEK dek = NULL;
  int recpno;
  FILE *data_fp = NULL;
  CERTLIST cl;

  memset (&encparm, 0, sizeof encparm);

  if (!recplist)
    {
      log_error(_("no valid recipients given\n"));
      gpgsm_status (ctrl, STATUS_NO_RECP, "0");
      rc = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
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

  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (err));
      rc = err;
      goto leave;
    }

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

  /* create a session key */
  dek = xtrycalloc (1, sizeof *dek); /* hmmm: should we put it into secmem?*/
  if (!dek)
    rc = OUT_OF_CORE (errno);
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
      rc = OUT_OF_CORE (errno);
      goto leave;
    }

  /* gather certificates of recipients, encrypt the session key for
     each and store them in the CMS object */
  for (recpno = 0, cl = recplist; cl; recpno++, cl = cl->next)
    {
      char *encval;
      
      rc = encrypt_dek (dek, cl->cert, &encval);
      if (rc)
        {
          log_error ("encryption failed for recipient no. %d: %s\n",
                     recpno, gpg_strerror (rc));
          goto leave;
        }
      
      err = ksba_cms_add_recipient (cms, cl->cert);
      if (err)
        {
          log_error ("ksba_cms_add_recipient failed: %s\n",
                     gpg_strerror (err));
          rc = err;
          xfree (encval);
          goto leave;
        }
      
      err = ksba_cms_set_enc_val (cms, recpno, encval);
      xfree (encval);
      if (err)
        {
          log_error ("ksba_cms_set_enc_val failed: %s\n",
                     gpg_strerror (err));
          rc = err;
          goto leave;
        }
  }

  /* main control loop for encryption */
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
