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


struct dek_s {
  const char *algoid;
  int algo;
  GCRY_CIPHER_HD chd;
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


static KsbaCert
get_default_recipient (void)
{
  const char key[] =
    "/CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=Düsseldorf,C=DE";

  KEYDB_SEARCH_DESC desc;
  KsbaCert cert = NULL;
  KEYDB_HANDLE kh = NULL;
  int rc;

  rc = keydb_classify_name (key, &desc);
  if (rc)
    {
      log_error ("failed to find recipient: %s\n", gnupg_strerror (rc));
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
      return GNUPG_Unsupported_Algorithm;
    }

  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);
  if (!dek->keylen || dek->keylen > sizeof (dek->key))
    return GNUPG_Bug;

  dek->ivlen = gcry_cipher_get_algo_blklen (dek->algo);
  if (!dek->ivlen || dek->ivlen > sizeof (dek->iv))
    return GNUPG_Bug;

  if (dek->keylen < 100/8)
    { /* make sure we don't use weak keys */
      log_error ("key length of `%s' too small\n", dek->algoid);
      return GNUPG_Unsupported_Algorithm;
    }
  
  dek->chd = gcry_cipher_open (dek->algo, mode, GCRY_CIPHER_SECURE);
  if (!dek->chd)
    {
      log_error ("failed to create cipher context: %s\n", gcry_strerror (-1));
      return GNUPG_General_Error;
    }
  
  for (i=0; i < 8; i++)
    {
      gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM );
      rc = gcry_cipher_setkey (dek->chd, dek->key, dek->keylen);
      if (rc != GCRYERR_WEAK_KEY)
        break;
      log_info(_("weak key created - retrying\n") );
    }
  if (rc)
    {
      log_error ("failed to set the key: %s\n", gcry_strerror (rc));
      gcry_cipher_close (dek->chd);
      dek->chd = NULL;
      return map_gcry_err (rc);
    }

  gcry_randomize (dek->iv, dek->ivlen, GCRY_STRONG_RANDOM);
  rc = gcry_cipher_setiv (dek->chd, dek->iv, dek->ivlen);
  if (rc)
    {
      log_error ("failed to set the IV: %s\n", gcry_strerror (rc));
      gcry_cipher_close (dek->chd);
      dek->chd = NULL;
      return map_gcry_err (rc);
    }
  
  return 0;
}


/* Encode the session key. NBITS is the number of bits which should be
   used for packing the session key.  returns: An mpi with the session
   key (caller must free) */
static GCRY_MPI
encode_session_key (DEK dek, unsigned int nbits)
{
  int nframe = (nbits+7) / 8;
  byte *p;
  byte *frame;
  int i,n;
  MPI a;

  if (dek->keylen + 7 > nframe || !nframe)
    log_bug ("can't encode a %d bit key in a %d bits frame\n",
             dek->keylen*8, nbits );

  /* We encode the session key in this way:
   *
   *	   0  2  RND(n bytes)  0  KEY(k bytes)
   *
   * (But how can we store the leading 0 - the external representaion
   *	of MPIs doesn't allow leading zeroes =:-)
   *
   * RND are non-zero random bytes.
   * KEY is the encryption key (session key) 
   */

  frame = gcry_xmalloc_secure (nframe);
  n = 0;
  frame[n++] = 0;
  frame[n++] = 2;
  i = nframe - 3 - dek->keylen;
  assert (i > 0);
  p = gcry_random_bytes_secure (i, GCRY_STRONG_RANDOM);
  /* replace zero bytes by new values */
  for (;;)
    {
      int j, k;
      byte *pp;

      /* count the zero bytes */
      for(j=k=0; j < i; j++ )
        {
          if( !p[j] )
            k++;
        }
      if( !k )
        break; /* okay: no zero bytes */

      k += k/128; /* better get some more */
      pp = gcry_random_bytes_secure (k, GCRY_STRONG_RANDOM);
      for (j=0; j < i && k; j++)
        {
          if( !p[j] )
            p[j] = pp[--k];
        }
      xfree (pp);
    }
  memcpy (frame+n, p, i);
  xfree (p);

  n += i;
  frame[n++] = 0;
  memcpy (frame+n, dek->key, dek->keylen);
  n += dek->keylen;
  assert (n == nframe);
  if (gcry_mpi_scan (&a, GCRYMPI_FMT_USG, frame, &nframe) )
    BUG ();
  gcry_free(frame);

  return a;
}



/* encrypt the DEK under the key contained in CERT and return it as a
   canonical S-Exp in encval */
static int
encrypt_dek (const DEK dek, KsbaCert cert, char **encval)
{
  GCRY_SEXP s_ciph, s_data, s_pkey;
  int rc;
  char *buf;
  size_t len;

  *encval = NULL;

  /* get the key from the cert */
  buf = ksba_cert_get_public_key (cert);
  if (!buf)
    {
      log_error ("no public key for recipient\n");
      return GNUPG_No_Public_Key;
    }
  rc = gcry_sexp_sscan (&s_pkey, NULL, buf, strlen(buf));
  xfree (buf); buf = NULL;
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gcry_strerror (rc));
      return map_gcry_err (rc);
    }

  /* put the encoded cleartext into a simple list */
  {
    /* fixme: actually the pkcs-1 encoding should go into libgcrypt */
    GCRY_MPI data = encode_session_key (dek, gcry_pk_get_nbits (s_pkey));
    if (!data)
      {
        gcry_mpi_release (data);
        return GNUPG_General_Error;
      }
    if (gcry_sexp_build (&s_data, NULL, "%m", data))
      BUG ();
    gcry_mpi_release (data);
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
      gcry_sexp_release (s_ciph);
      return GNUPG_Out_Of_Core;
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
  struct certlist_s help_recplist;
  CERTLIST cl;

  memset (&encparm, 0, sizeof encparm);
  help_recplist.next = NULL;
  help_recplist.cert = NULL;
  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }

  /* If no recipient list is given, use a default one */
  /* FIXME: we shoudl not do this but return an error and a
     STATUS_NO_RECP */
  if (!recplist)
    {
      help_recplist.cert = get_default_recipient ();
      if (!help_recplist.cert)
        {
          log_error ("no default recipient found\n");
          rc = seterr (General_Error);
          goto leave;
        }
      recplist = &help_recplist;
    }

  data_fp = fdopen ( dup (data_fd), "rb");
  if (!data_fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  reader = ksba_reader_new ();
  if (!reader)
      rc = KSBA_Out_Of_Core;
  if (!rc)
    rc = ksba_reader_set_cb (reader, encrypt_cb, &encparm);
  if (rc)
    {
      rc = map_ksba_err (rc);
      goto leave;
    }
  encparm.fp = data_fp;

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

  /* We are going to create enveloped data with uninterpreted data as
     inner content */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_ENVELOPED_DATA);
  if (!err)
    err = ksba_cms_set_content_type (cms, 1, KSBA_CT_DATA);
  if (err)
    {
      log_debug ("ksba_cms_set_content_type failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  /* create a session key */
  dek = xtrycalloc (1, sizeof *dek); /* hmmm: should we put it into secmem?*/
  if (!dek)
    rc = GNUPG_Out_Of_Core;
  else
  {
    dek->algoid = opt.def_cipher_algoid;
    rc = init_dek (dek);
  }
  if (rc)
    {
      log_error ("failed to create the session key: %s\n",
                 gnupg_strerror (rc));
      goto leave;
    }

  err = ksba_cms_set_content_enc_algo (cms, dek->algoid, dek->iv, dek->ivlen);
  if (err)
    {
      log_error ("ksba_cms_set_content_enc_algo failed: %s\n",
                 ksba_strerror (err));
      rc = map_ksba_err (err);
      goto leave;
    }

  encparm.dek = dek;
  /* fixme: we should use a larger buffer - the small one is better
     for testing */
  encparm.bufsize = 10 * dek->ivlen;
  encparm.buffer = xtrymalloc (encparm.bufsize);
  if (!encparm.buffer)
    {
      rc = seterr (Out_Of_Core);
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
                     recpno, gnupg_strerror (rc));
          goto leave;
        }
      
      err = ksba_cms_add_recipient (cms, cl->cert);
      if (err)
        {
          log_error ("ksba_cms_add_recipient failed: %s\n",
                     ksba_strerror (err));
          rc = map_ksba_err (err);
          xfree (encval);
          goto leave;
        }
      
      err = ksba_cms_set_enc_val (cms, recpno, encval);
      xfree (encval);
      if (err)
        {
          log_error ("ksba_cms_set_enc_val failed: %s\n",
                     ksba_strerror (err));
          rc = map_ksba_err (err);
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
          log_debug ("ksba_cms_build failed: %s\n", ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }
    }
  while (stopreason != KSBA_SR_READY);   

  if (encparm.readerror)
    {
      log_error ("error reading input: %s\n", strerror (encparm.readerror));
      rc = seterr (Read_Error);
      goto leave;
    }


  rc = gpgsm_finish_writer (b64writer);
  if (rc) 
    {
      log_error ("write failed: %s\n", gnupg_strerror (rc));
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
  if (help_recplist.cert)
    ksba_cert_release (help_recplist.cert);
  return rc;
}
