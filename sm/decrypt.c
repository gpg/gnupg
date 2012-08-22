/* decrypt.c - Decrypt a message
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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

struct decrypt_filter_parm_s {
  int algo;
  int mode;
  int blklen;
  gcry_cipher_hd_t hd;
  char iv[16];
  size_t ivlen;
  int any_data;  /* dod we push anything through the filter at all? */
  unsigned char lastblock[16];  /* to strip the padding we have to
                                   keep this one */
  char helpblock[16];  /* needed because there is no block buffering in
                          libgcrypt (yet) */
  int  helpblocklen;
};



/* Decrypt the session key and fill in the parm structure.  The
   algo and the IV is expected to be already in PARM. */
static int 
prepare_decryption (ctrl_t ctrl, const char *hexkeygrip, const char *desc,
                    ksba_const_sexp_t enc_val,
                    struct decrypt_filter_parm_s *parm)
{
  char *seskey = NULL;
  size_t n, seskeylen;
  int rc;

  rc = gpgsm_agent_pkdecrypt (ctrl, hexkeygrip, desc, enc_val,
                              &seskey, &seskeylen);
  if (rc)
    {
      log_error ("error decrypting session key: %s\n", gpg_strerror (rc));
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex ("pkcs1 encoded session key:", seskey, seskeylen);

  n=0;
  if (seskeylen == 24)
    {
      /* Smells like a 3-des key.  This might happen because a SC has
         already done the unpacking. */
    }
  else
    {
      if (n + 7 > seskeylen )
        {
          rc = gpg_error (GPG_ERR_INV_SESSION_KEY);
          goto leave; 
        }
      
      /* FIXME: Actually the leading zero is required but due to the way
         we encode the output in libgcrypt as an MPI we are not able to
         encode that leading zero.  However, when using a Smartcard we are
         doing it the right way and therefore we have to skip the zero.  This
         should be fixed in gpg-agent of course. */
      if (!seskey[n])
        n++;
      
      if (seskey[n] != 2 )  /* Wrong block type version. */
        { 
          rc = gpg_error (GPG_ERR_INV_SESSION_KEY);
          goto leave; 
        }
      
      for (n++; n < seskeylen && seskey[n]; n++) /* Skip the random bytes. */
        ;
      n++; /* and the zero byte */
      if (n >= seskeylen )
        { 
          rc = gpg_error (GPG_ERR_INV_SESSION_KEY);
          goto leave; 
        }
    }

  if (DBG_CRYPTO)
    log_printhex ("session key:", seskey+n, seskeylen-n);

  rc = gcry_cipher_open (&parm->hd, parm->algo, parm->mode, 0);
  if (rc)
    {
      log_error ("error creating decryptor: %s\n", gpg_strerror (rc));
      goto leave;
    }
                        
  rc = gcry_cipher_setkey (parm->hd, seskey+n, seskeylen-n);
  if (gpg_err_code (rc) == GPG_ERR_WEAK_KEY)
    {
      log_info (_("WARNING: message was encrypted with "
                  "a weak key in the symmetric cipher.\n"));
      rc = 0;
    }
  if (rc)
    {
      log_error("key setup failed: %s\n", gpg_strerror(rc) );
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
   output, it may happen that fewer bytes are processed or fewer bytes
   are written. */
static gpg_error_t
decrypt_filter (void *arg,
                const void *inbuf, size_t inlen, size_t *inused,
                void *outbuf, size_t maxoutlen, size_t *outlen)
{
  struct decrypt_filter_parm_s *parm = arg;
  int blklen = parm->blklen;
  size_t orig_inlen = inlen;

  /* fixme: Should we issue an error when we have not seen one full block? */
  if (!inlen)
    return gpg_error (GPG_ERR_BUG);

  if (maxoutlen < 2*parm->blklen)
    return gpg_error (GPG_ERR_BUG);
  /* Make some space because we will later need an extra block at the end.  */
  maxoutlen -= blklen;

  if (parm->helpblocklen)
    {
      int i, j;

      for (i=parm->helpblocklen,j=0; i < blklen && j < inlen; i++, j++)
        parm->helpblock[i] = ((const char*)inbuf)[j];
      inlen -= j;
      if (blklen > maxoutlen)
        return gpg_error (GPG_ERR_BUG);
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
gpgsm_decrypt (ctrl_t ctrl, int in_fd, FILE *out_fp)
{
  int rc;
  Base64Context b64reader = NULL;
  Base64Context b64writer = NULL;
  ksba_reader_t reader;
  ksba_writer_t writer;
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  KEYDB_HANDLE kh;
  int recp;
  FILE *in_fp = NULL;
  struct decrypt_filter_parm_s dfparm;

  memset (&dfparm, 0, sizeof dfparm);

  audit_set_type (ctrl->audit, AUDIT_TYPE_DECRYPT);

  kh = keydb_new (0);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }


  in_fp = fdopen ( dup (in_fd), "rb");
  if (!in_fp)
    {
      rc = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("fdopen() failed: %s\n", strerror (errno));
      goto leave;
    }

  rc = gpgsm_create_reader (&b64reader, ctrl, in_fp, 0, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = gpgsm_create_writer (&b64writer, ctrl, out_fp, NULL, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = ksba_cms_new (&cms);
  if (rc)
    goto leave;

  rc = ksba_cms_set_reader_writer (cms, reader, writer);
  if (rc)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (rc));
      goto leave;
    }

  audit_log (ctrl->audit, AUDIT_SETUP_READY);

  /* Parser loop. */
  do 
    {
      rc = ksba_cms_parse (cms, &stopreason);
      if (rc)
        {
          log_debug ("ksba_cms_parse failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (stopreason == KSBA_SR_BEGIN_DATA
          || stopreason == KSBA_SR_DETACHED_DATA)
        {
          int algo, mode;
          const char *algoid;
          int any_key = 0;
          
          audit_log (ctrl->audit, AUDIT_GOT_DATA);

          algoid = ksba_cms_get_content_oid (cms, 2/* encryption algo*/);
          algo = gcry_cipher_map_name (algoid);
          mode = gcry_cipher_mode_from_oid (algoid);
          if (!algo || !mode)
            {
              rc = gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
              log_error ("unsupported algorithm `%s'\n", algoid? algoid:"?");
              if (algoid && !strcmp (algoid, "1.2.840.113549.3.2"))
                log_info (_("(this is the RC2 algorithm)\n"));
              else if (!algoid)
                log_info (_("(this does not seem to be an encrypted"
                            " message)\n"));
              {
                char numbuf[50];
                sprintf (numbuf, "%d", rc);
                gpgsm_status2 (ctrl, STATUS_ERROR, "decrypt.algorithm",
                               numbuf, algoid?algoid:"?", NULL);
                audit_log_s (ctrl->audit, AUDIT_BAD_DATA_CIPHER_ALGO, algoid);
              }

              /* If it seems that this is not an encrypted message we
                 return a more sensible error code. */
              if (!algoid)
                rc = gpg_error (GPG_ERR_NO_DATA);

              goto leave;
            }

          audit_log_i (ctrl->audit, AUDIT_DATA_CIPHER_ALGO, algo);
          dfparm.algo = algo;
          dfparm.mode = mode;
          dfparm.blklen = gcry_cipher_get_algo_blklen (algo);
          if (dfparm.blklen > sizeof (dfparm.helpblock))
            return gpg_error (GPG_ERR_BUG);

          rc = ksba_cms_get_content_enc_iv (cms,
                                            dfparm.iv,
                                            sizeof (dfparm.iv),
                                            &dfparm.ivlen);
          if (rc)
            {
              log_error ("error getting IV: %s\n", gpg_strerror (rc));
              goto leave;
            }
          
          for (recp=0; !any_key; recp++)
            {
              char *issuer;
              ksba_sexp_t serial;
              ksba_sexp_t enc_val;
              char *hexkeygrip = NULL;
              char *desc = NULL;
              char kidbuf[16+1];

              *kidbuf = 0;

              rc = ksba_cms_get_issuer_serial (cms, recp, &issuer, &serial);
              if (rc == -1 && recp)
                break; /* no more recipients */
              audit_log_i (ctrl->audit, AUDIT_NEW_RECP, recp);
              if (rc)
                log_error ("recp %d - error getting info: %s\n",
                           recp, gpg_strerror (rc));
              else
                {
                  ksba_cert_t cert = NULL;

                  log_debug ("recp %d - issuer: `%s'\n",
                             recp, issuer? issuer:"[NONE]");
                  log_debug ("recp %d - serial: ", recp);
                  gpgsm_dump_serial (serial);
                  log_printf ("\n");

                  if (ctrl->audit)
                    {
                      char *tmpstr = gpgsm_format_sn_issuer (serial, issuer);
                      audit_log_s (ctrl->audit, AUDIT_RECP_NAME, tmpstr);
                      xfree (tmpstr);
                    }

                  keydb_search_reset (kh);
                  rc = keydb_search_issuer_sn (kh, issuer, serial);
                  if (rc)
                    {
                      log_error ("failed to find the certificate: %s\n",
                                 gpg_strerror(rc));
                      goto oops;
                    }

                  rc = keydb_get_cert (kh, &cert);
                  if (rc)
                    {
                      log_error ("failed to get cert: %s\n", gpg_strerror (rc));
                      goto oops;     
                    }

                  /* Print the ENC_TO status line.  Note that we can
                     do so only if we have the certificate.  This is
                     in contrast to gpg where the keyID is commonly
                     included in the encrypted messages. It is too
                     cumbersome to retrieve the used algorithm, thus
                     we don't print it for now.  We also record the
                     keyid for later use.  */
                  {
                    unsigned long kid[2];
                    
                    kid[0] = gpgsm_get_short_fingerprint (cert, kid+1);
                    snprintf (kidbuf, sizeof kidbuf, "%08lX%08lX",
                              kid[1], kid[0]);
                    gpgsm_status2 (ctrl, STATUS_ENC_TO, 
                                   kidbuf, "0", "0", NULL);
                  }

                  /* Put the certificate into the audit log.  */
                  audit_log_cert (ctrl->audit, AUDIT_SAVE_CERT, cert, 0);

                  /* Just in case there is a problem with the own
                     certificate we print this message - should never
                     happen of course */
                  rc = gpgsm_cert_use_decrypt_p (cert);
                  if (rc)
                    {
                      char numbuf[50];
                      sprintf (numbuf, "%d", rc);
                      gpgsm_status2 (ctrl, STATUS_ERROR, "decrypt.keyusage",
                                     numbuf, NULL);
                      rc = 0;
                    }

                  hexkeygrip = gpgsm_get_keygrip_hexstring (cert);
                  desc = gpgsm_format_keydesc (cert);

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
                  rc = prepare_decryption (ctrl,
                                           hexkeygrip, desc, enc_val, &dfparm);
                  xfree (enc_val);
                  if (rc)
                    {
                      log_info ("decrypting session key failed: %s\n",
                                gpg_strerror (rc));
                      if (gpg_err_code (rc) == GPG_ERR_NO_SECKEY && *kidbuf)
                        gpgsm_status2 (ctrl, STATUS_NO_SECKEY, kidbuf, NULL);
                    }
                  else
                    { /* setup the bulk decrypter */
                      any_key = 1;
                      ksba_writer_set_filter (writer,
                                              decrypt_filter,
                                              &dfparm);
                    }
                  audit_log_ok (ctrl->audit, AUDIT_RECP_RESULT, rc);
                }
              xfree (hexkeygrip);
              xfree (desc);
            }

          /* If we write an audit log add the unused recipients to the
             log as well.  */
          if (ctrl->audit && any_key)
            {
              for (;; recp++)
                {
                  char *issuer;
                  ksba_sexp_t serial;
                  int tmp_rc;

                  tmp_rc = ksba_cms_get_issuer_serial (cms, recp,
                                                       &issuer, &serial);
                  if (tmp_rc == -1)
                    break; /* no more recipients */
                  audit_log_i (ctrl->audit, AUDIT_NEW_RECP, recp);
                  if (tmp_rc)
                    log_error ("recp %d - error getting info: %s\n",
                               recp, gpg_strerror (rc));
                  else
                    {
                      char *tmpstr = gpgsm_format_sn_issuer (serial, issuer);
                      audit_log_s (ctrl->audit, AUDIT_RECP_NAME, tmpstr);
                      xfree (tmpstr);
                      xfree (issuer);
                      xfree (serial);
                    }
                }
            }

          if (!any_key)
            {
              rc = gpg_error (GPG_ERR_NO_SECKEY);
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
                  rc = gpg_error (GPG_ERR_INV_DATA);
                  goto leave;
                }
              rc = ksba_writer_write (writer,
                                      dfparm.lastblock, 
                                      dfparm.blklen - npadding);
              if (rc)
                goto leave;

              for (i=dfparm.blklen - npadding; i < dfparm.blklen; i++)
                {
                  if (dfparm.lastblock[i] != npadding)
                    {
                      log_error ("inconsistent padding\n");
                      rc = gpg_error (GPG_ERR_INV_DATA);
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
      log_error ("write failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
  gpgsm_status (ctrl, STATUS_DECRYPTION_OKAY, NULL);


 leave:
  audit_log_ok (ctrl->audit, AUDIT_DECRYPTION_RESULT, rc);
  if (rc)
    {
      gpgsm_status (ctrl, STATUS_DECRYPTION_FAILED, NULL);
      log_error ("message decryption failed: %s <%s>\n",
                 gpg_strerror (rc), gpg_strsource (rc));
    }
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


