/* decrypt.c - Decrypt a message
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

struct decrypt_filter_parm_s {
  int algo;
  int mode;
  int blklen;
  GCRY_CIPHER_HD hd;
  char iv[16];
  size_t ivlen;
  int any_data;  /* dod we push anything through the filter at all? */
  unsigned char lastblock[16];  /* to strip the padding we have to
                                   keep this one */
  char helpblock[16];  /* needed because there is no block buffering in
                          libgcrypt (yet) */
  int  helpblocklen;
};



/* decrypt the session key and fill in the parm structure.  The
   algo and the IV is expected to be already in PARM. */
static int 
prepare_decryption (const char *hexkeygrip, KsbaConstSexp enc_val,
                    struct decrypt_filter_parm_s *parm)
{
  char *seskey = NULL;
  size_t n, seskeylen;
  int rc;

  rc = gpgsm_agent_pkdecrypt (hexkeygrip, enc_val,
                              &seskey, &seskeylen);
  if (rc)
    {
      log_error ("error decrypting session key: %s\n", gnupg_strerror (rc));
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex ("pkcs1 encoded session key:", seskey, seskeylen);

  n=0;
  if (n + 7 > seskeylen )
    {
      rc = seterr (Invalid_Session_Key);
      goto leave; 
    }

  /* FIXME: Actually the leading zero is required but due to the way
     we encode the output in libgcrypt as an MPI we are not able to
     encode that leading zero.  However, when using a Smartcard we are
     doing it the rightway and therefore we have to skip the zero.  This
     should be fixed in gpg-agent of course. */
  if (!seskey[n])
    n++;

  if (seskey[n] != 2 )  /* wrong block type version */
    { 
      rc = seterr (Invalid_Session_Key);
      goto leave; 
    }

  for (n++; n < seskeylen && seskey[n]; n++) /* skip the random bytes */
    ;
  n++; /* and the zero byte */
  if (n >= seskeylen )
    { 
      rc = seterr (Invalid_Session_Key);
      goto leave; 
    }
  
  if (DBG_CRYPTO)
    log_printhex ("session key:", seskey+n, seskeylen-n);

  parm->hd = gcry_cipher_open (parm->algo, parm->mode, 0);
  if (!parm->hd)
    {
      rc = gcry_errno ();
      log_error ("error creating decryptor: %s\n", gcry_strerror (rc));
      rc = map_gcry_err (rc);
      goto leave;
    }
                        
  rc = gcry_cipher_setkey (parm->hd, seskey+n, seskeylen-n);
  if (rc == GCRYERR_WEAK_KEY)
    {
      log_info (_("WARNING: message was encrypted with "
                  "a weak key in the symmetric cipher.\n"));
      rc = 0;
    }
  if (rc)
    {
      log_error("key setup failed: %s\n", gcry_strerror(rc) );
      rc = map_gcry_err (rc);
      goto leave;
    }

  gcry_cipher_setiv (parm->hd, parm->iv, parm->ivlen);

 leave:
  xfree (seskey);
  return rc;
}


/* This function is called by the KSBA writer just before the actual
   write is done.  The function must take INLEN bytes from INBUF,
   decrypt it and store it inoutbuf which has a maximum size of
   maxoutlen.  The valid bytes in outbuf should be return in outlen.
   Due to different buffer sizes or different length of input and
   output, it may happen that fewer bytes are process or fewer bytes
   are written. */
static KsbaError  
decrypt_filter (void *arg,
                const void *inbuf, size_t inlen, size_t *inused,
                void *outbuf, size_t maxoutlen, size_t *outlen)
{
  struct decrypt_filter_parm_s *parm = arg;
  int blklen = parm->blklen;
  size_t orig_inlen = inlen;

  /* fixme: Should we issue an error when we have not seen one full block? */
  if (!inlen)
    return KSBA_Bug;

  if (maxoutlen < 2*parm->blklen)
    return KSBA_Bug;
  /* make some space becuase we will later need an extra block at the end */
  maxoutlen -= blklen;

  if (parm->helpblocklen)
    {
      int i, j;

      for (i=parm->helpblocklen,j=0; i < blklen && j < inlen; i++, j++)
        parm->helpblock[i] = ((const char*)inbuf)[j];
      inlen -= j;
      if (blklen > maxoutlen)
        return KSBA_Bug;
      if (i < blklen)
        {
          parm->helpblocklen = i;
          *outlen = 0;
        }
      else
        {
          parm->helpblocklen = 0;
          if (parm->any_data)
            {
              memcpy (outbuf, parm->lastblock, blklen);
              *outlen =blklen;
            }
          else
            *outlen = 0;
          gcry_cipher_decrypt (parm->hd, parm->lastblock, blklen,
                               parm->helpblock, blklen);
          parm->any_data = 1;
        }
      *inused = orig_inlen - inlen;
      return 0;
    }


  if (inlen > maxoutlen)
    inlen = maxoutlen;
  if (inlen % blklen)
    { /* store the remainder away */
      parm->helpblocklen = inlen%blklen;
      inlen = inlen/blklen*blklen;
      memcpy (parm->helpblock, (const char*)inbuf+inlen, parm->helpblocklen);
    }

  *inused = inlen + parm->helpblocklen;
  if (inlen)
    {
      assert (inlen >= blklen);
      if (parm->any_data)
        {
          gcry_cipher_decrypt (parm->hd, (char*)outbuf+blklen, inlen,
                               inbuf, inlen);
          memcpy (outbuf, parm->lastblock, blklen);
          memcpy (parm->lastblock,(char*)outbuf+inlen, blklen);
          *outlen = inlen;
        }
      else
        {
          gcry_cipher_decrypt (parm->hd, outbuf, inlen, inbuf, inlen);
          memcpy (parm->lastblock, (char*)outbuf+inlen-blklen, blklen);
          *outlen = inlen - blklen;
          parm->any_data = 1;
        }
    }
  else
    *outlen = 0;
  return 0;
}



/* Perform a decrypt operation.  */
int
gpgsm_decrypt (CTRL ctrl, int in_fd, FILE *out_fp)
{
  int rc;
  KsbaError err;
  Base64Context b64reader = NULL;
  Base64Context b64writer = NULL;
  KsbaReader reader;
  KsbaWriter writer;
  KsbaCMS cms = NULL;
  KsbaStopReason stopreason;
  KEYDB_HANDLE kh;
  int recp;
  FILE *in_fp = NULL;
  struct decrypt_filter_parm_s dfparm;

  memset (&dfparm, 0, sizeof dfparm);

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocated keyDB handle\n"));
      rc = GNUPG_General_Error;
      goto leave;
    }


  in_fp = fdopen ( dup (in_fd), "rb");
  if (!in_fp)
    {
      log_error ("fdopen() failed: %s\n", strerror (errno));
      rc = seterr (IO_Error);
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, in_fp, &reader);
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

  /* parser loop */
  do 
    {
      err = ksba_cms_parse (cms, &stopreason);
      if (err)
        {
          log_debug ("ksba_cms_parse failed: %s\n", ksba_strerror (err));
          rc = map_ksba_err (err);
          goto leave;
        }

      if (stopreason == KSBA_SR_BEGIN_DATA
          || stopreason == KSBA_SR_DETACHED_DATA)
        {
          int algo, mode;
          const char *algoid;
          int any_key = 0;
          
          algoid = ksba_cms_get_content_oid (cms, 2/* encryption algo*/);
          algo = gcry_cipher_map_name (algoid);
          mode = gcry_cipher_mode_from_oid (algoid);
          if (!algo || !mode)
            {
              log_error ("unsupported algorithm `%s'\n", algoid? algoid:"?");
              rc = GNUPG_Unsupported_Algorithm;
              goto leave;
            }
          dfparm.algo = algo;
          dfparm.mode = mode;
          dfparm.blklen = gcry_cipher_get_algo_blklen (algo);
          if (dfparm.blklen > sizeof (dfparm.helpblock))
            return GNUPG_Bug;

          rc = ksba_cms_get_content_enc_iv (cms,
                                            dfparm.iv,
                                            sizeof (dfparm.iv),
                                            &dfparm.ivlen);
          if (rc)
            {
              log_error ("error getting IV: %s\n", ksba_strerror (err));
              rc = map_ksba_err (err);
              goto leave;
            }
          
          for (recp=0; !any_key; recp++)
            {
              char *issuer;
              KsbaSexp serial;
              KsbaSexp enc_val;
              char *hexkeygrip = NULL;

              err = ksba_cms_get_issuer_serial (cms, recp, &issuer, &serial);
              if (err == -1 && recp)
                break; /* no more recipients */
              if (err)
                log_error ("recp %d - error getting info: %s\n",
                           recp, ksba_strerror (err));
              else
                {
                  KsbaCert cert = NULL;

                  log_debug ("recp %d - issuer: `%s'\n",
                             recp, issuer? issuer:"[NONE]");
                  log_debug ("recp %d - serial: ", recp);
                  gpgsm_dump_serial (serial);
                  log_printf ("\n");

                  keydb_search_reset (kh);
                  rc = keydb_search_issuer_sn (kh, issuer, serial);
                  if (rc)
                    {
                      log_error ("failed to find the certificate: %s\n",
                                 gnupg_strerror(rc));
                      goto oops;
                    }

                  rc = keydb_get_cert (kh, &cert);
                  if (rc)
                    {
                      log_error ("failed to get cert: %s\n", gnupg_strerror (rc));
                      goto oops;     
                    }
                  /* Just in case there is a problem with the own
                     certificate we print this message - should never
                     happen of course */
                  rc = gpgsm_cert_use_decrypt_p (cert);
                  if (rc)
                    {
                      gpgsm_status2 (ctrl, STATUS_ERROR, "decrypt.keyusage",
                                     gnupg_error_token (rc), NULL);
                      rc = 0;
                    }

                  hexkeygrip = gpgsm_get_keygrip_hexstring (cert);

                oops:
                  xfree (issuer);
                  xfree (serial);
                  ksba_cert_release (cert);
                }

              if (!hexkeygrip)
                ;
              else if (!(enc_val = ksba_cms_get_enc_val (cms, recp)))
                log_error ("recp %d - error getting encrypted session key\n",
                           recp);
              else
                {
                  rc = prepare_decryption (hexkeygrip, enc_val, &dfparm);
                  xfree (enc_val);
                  if (rc)
                    {
                      log_debug ("decrypting session key failed: %s\n",
                                 gnupg_strerror (rc));
                    }
                  else
                    { /* setup the bulk decrypter */
                      any_key = 1;
                      ksba_writer_set_filter (writer,
                                              decrypt_filter,
                                              &dfparm);
                    }
                }
            }
          if (!any_key)
            {
              rc = GNUPG_No_Secret_Key;
              goto leave;
            }
        }
      else if (stopreason == KSBA_SR_END_DATA)
        {
          ksba_writer_set_filter (writer, NULL, NULL);
          if (dfparm.any_data)
            { /* write the last block with padding removed */
              int i, npadding = dfparm.lastblock[dfparm.blklen-1];
              if (!npadding || npadding > dfparm.blklen)
                {
                  log_error ("invalid padding with value %d\n", npadding);
                  rc = seterr (Invalid_Data);
                  goto leave;
                }
              rc = ksba_writer_write (writer,
                                      dfparm.lastblock, 
                                      dfparm.blklen - npadding);
              if (rc)
                {
                  rc = map_ksba_err (rc);
                  goto leave;
                }
              for (i=dfparm.blklen - npadding; i < dfparm.blklen; i++)
                {
                  if (dfparm.lastblock[i] != npadding)
                    {
                      log_error ("inconsistent padding\n");
                      rc = seterr (Invalid_Data);
                      goto leave;
                    }
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
  gpgsm_status (ctrl, STATUS_DECRYPTION_OKAY, NULL);


 leave:
  if (rc)
    gpgsm_status (ctrl, STATUS_DECRYPTION_FAILED, NULL);
  ksba_cms_release (cms);
  gpgsm_destroy_reader (b64reader);
  gpgsm_destroy_writer (b64writer);
  keydb_release (kh); 
  if (in_fp)
    fclose (in_fp);
  if (dfparm.hd)
    gcry_cipher_close (dfparm.hd); 
  return rc;
}


