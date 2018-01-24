/* decrypt-data.c - Decrypt an encrypted data packet
 * Copyright (C) 1998-2001, 2005-2006, 2009 Free Software Foundation, Inc.
 * Copyright (C) 1998-2001, 2005-2006, 2009, 2018 Werner Koch
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "options.h"
#include "../common/i18n.h"
#include "../common/status.h"
#include "../common/compliance.h"


static int aead_decode_filter (void *opaque, int control, iobuf_t a,
                               byte *buf, size_t *ret_len);
static int mdc_decode_filter ( void *opaque, int control, IOBUF a,
                               byte *buf, size_t *ret_len);
static int decode_filter ( void *opaque, int control, IOBUF a,
					byte *buf, size_t *ret_len);

/* Our context object.  */
struct decode_filter_context_s
{
  /* Recounter (max value is 2).  We need it becuase we do not know
   * whether the iobuf or the outer control code frees this object
   * first.  */
  int  refcount;

  /* The cipher handle.  */
  gcry_cipher_hd_t cipher_hd;

  /* The hash handle for use in MDC mode.  */
  gcry_md_hd_t mdc_hash;

  /* The start IV for AEAD encryption.   */
  byte startiv[16];

  /* The holdback buffer and its used length.  For AEAD we need at
   * least 32+1 byte for MDC 22 bytes are required.  */
  char holdback[48];
  unsigned int holdbacklen;

  /* Working on a partial length packet.  */
  unsigned int partial : 1;

  /* EOF indicator with these true values:
   *   1 = normal EOF
   *   2 = premature EOF (tag incomplete)
   *   3 = premature EOF (general)       */
  unsigned int eof_seen : 2;

  /* The actually used cipher algo for AEAD.  */
  byte cipher_algo;

  /* The AEAD algo.  */
  byte aead_algo;

  /* The encoded chunk byte for AEAD.  */
  byte chunkbyte;

  /* The decoded CHUNKBYTE.  */
  uint64_t chunksize;

  /* The chunk index for AEAD.  */
  uint64_t chunkindex;

  /* The number of bytes in the current chunk.  */
  uint64_t chunklen;

  /* The total count of decrypted plaintext octets.  */
  uint64_t total;

  /* Remaining bytes in the packet according to the packet header.
   * Not used if PARTIAL is true.  */
  size_t length;
};
typedef struct decode_filter_context_s *decode_filter_ctx_t;


/* Helper to release the decode context.  */
static void
release_dfx_context (decode_filter_ctx_t dfx)
{
  if (!dfx)
    return;

  log_assert (dfx->refcount);
  if ( !--dfx->refcount )
    {
      gcry_cipher_close (dfx->cipher_hd);
      dfx->cipher_hd = NULL;
      gcry_md_close (dfx->mdc_hash);
      dfx->mdc_hash = NULL;
      xfree (dfx);
    }
}


/* Set the nonce for AEAD.  This also reset the decryption machinery
 * so that the handle can be used for a new chunk.  */
static gpg_error_t
aead_set_nonce (decode_filter_ctx_t dfx)
{
  unsigned char nonce[16];
  int i;

  switch (dfx->aead_algo)
    {
    case AEAD_ALGO_OCB:
      memcpy (nonce, dfx->startiv, 15);
      i = 7;
      break;

    case AEAD_ALGO_EAX:
      memcpy (nonce, dfx->startiv, 16);
      i = 8;
      break;

    default:
      BUG ();
    }
  nonce[i++] ^= dfx->chunkindex >> 56;
  nonce[i++] ^= dfx->chunkindex >> 48;
  nonce[i++] ^= dfx->chunkindex >> 40;
  nonce[i++] ^= dfx->chunkindex >> 32;
  nonce[i++] ^= dfx->chunkindex >> 24;
  nonce[i++] ^= dfx->chunkindex >> 16;
  nonce[i++] ^= dfx->chunkindex >>  8;
  nonce[i++] ^= dfx->chunkindex;

  if (DBG_CRYPTO)
    log_printhex (nonce, i, "nonce:");
  return gcry_cipher_setiv (dfx->cipher_hd, nonce, i);
}


/* Set the additional data for the current chunk.  If FINAL is set the
 * final AEAD chunk is processed.  */
static gpg_error_t
aead_set_ad (decode_filter_ctx_t dfx, int final)
{
  unsigned char ad[21];

  ad[0] = (0xc0 | PKT_ENCRYPTED_AEAD);
  ad[1] = 1;
  ad[2] = dfx->cipher_algo;
  ad[3] = dfx->aead_algo;
  ad[4] = dfx->chunkbyte;
  ad[5] = dfx->chunkindex >> 56;
  ad[6] = dfx->chunkindex >> 48;
  ad[7] = dfx->chunkindex >> 40;
  ad[8] = dfx->chunkindex >> 32;
  ad[9] = dfx->chunkindex >> 24;
  ad[10]= dfx->chunkindex >> 16;
  ad[11]= dfx->chunkindex >>  8;
  ad[12]= dfx->chunkindex;
  if (final)
    {
      ad[13] = dfx->total >> 56;
      ad[14] = dfx->total >> 48;
      ad[15] = dfx->total >> 40;
      ad[16] = dfx->total >> 32;
      ad[17] = dfx->total >> 24;
      ad[18] = dfx->total >> 16;
      ad[19] = dfx->total >>  8;
      ad[20] = dfx->total;
    }
  if (DBG_CRYPTO)
    log_printhex (ad, final? 21 : 13, "authdata:");
  return gcry_cipher_authenticate (dfx->cipher_hd, ad, final? 21 : 13);
}


/****************
 * Decrypt the data, specified by ED with the key DEK.
 */
int
decrypt_data (ctrl_t ctrl, void *procctx, PKT_encrypted *ed, DEK *dek)
{
  decode_filter_ctx_t dfx;
  byte *p;
  int rc=0, c, i;
  byte temp[32];
  unsigned int blocksize;
  unsigned int nprefix;

  dfx = xtrycalloc (1, sizeof *dfx);
  if (!dfx)
    return gpg_error_from_syserror ();
  dfx->refcount = 1;

  if ( opt.verbose && !dek->algo_info_printed )
    {
      if (!openpgp_cipher_test_algo (dek->algo))
        log_info (_("%s.%s encrypted data\n"),
                  openpgp_cipher_algo_name (dek->algo),
                  ed->aead_algo? openpgp_aead_algo_name (ed->aead_algo)
                  /**/         : "CFB");
      else
        log_info (_("encrypted with unknown algorithm %d\n"), dek->algo );
      dek->algo_info_printed = 1;
    }

  /* Check compliance.  */
  if (! gnupg_cipher_is_allowed (opt.compliance, 0, dek->algo,
                                 GCRY_CIPHER_MODE_CFB))
    {
      log_error (_("cipher algorithm '%s' may not be used in %s mode\n"),
		 openpgp_cipher_algo_name (dek->algo),
		 gnupg_compliance_option_string (opt.compliance));
      rc = gpg_error (GPG_ERR_CIPHER_ALGO);
      goto leave;
    }

  write_status_printf (STATUS_DECRYPTION_INFO, "%d %d %d",
                       ed->mdc_method, dek->algo, ed->aead_algo);

  if (opt.show_session_key)
    {
      char numbuf[30];
      char *hexbuf;

      if (ed->aead_algo)
        snprintf (numbuf, sizeof numbuf, "%d.%u:", dek->algo, ed->aead_algo);
      else
        snprintf (numbuf, sizeof numbuf, "%d:", dek->algo);
      hexbuf = bin2hex (dek->key, dek->keylen, NULL);
      if (!hexbuf)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
      log_info ("session key: '%s%s'\n", numbuf, hexbuf);
      write_status_strings (STATUS_SESSION_KEY, numbuf, hexbuf, NULL);
      xfree (hexbuf);
    }

  rc = openpgp_cipher_test_algo (dek->algo);
  if (rc)
    goto leave;
  blocksize = openpgp_cipher_get_algo_blklen (dek->algo);
  if ( !blocksize || blocksize > 16 )
    log_fatal ("unsupported blocksize %u\n", blocksize );
  if (ed->aead_algo)
    {
      enum gcry_cipher_modes ciphermode;
      unsigned int startivlen;

      if (blocksize != 16)
        {
          rc = gpg_error (GPG_ERR_CIPHER_ALGO);
          goto leave;
        }

      rc = openpgp_aead_algo_info (ed->aead_algo, &ciphermode, &startivlen);
      if (rc)
        goto leave;
      log_assert (startivlen <= sizeof dfx->startiv);

      if (ed->chunkbyte > 56)
        {
          log_error ("invalid AEAD chunkbyte %u\n", ed->chunkbyte);
          rc = gpg_error (GPG_ERR_INV_PACKET);
          goto leave;
        }

      /* Read the Start-IV. */
      if (ed->len)
        {
          for (i=0; i < startivlen && ed->len; i++, ed->len--)
            {
              if ((c=iobuf_get (ed->buf)) == -1)
                break;
              dfx->startiv[i] = c;
            }
        }
      else
        {
          for (i=0; i < startivlen; i++ )
            if ( (c=iobuf_get (ed->buf)) == -1 )
              break;
            else
              dfx->startiv[i] = c;
        }
      if (i != startivlen)
        {
          log_error ("Start-IV in AEAD packet too short (%d/%u)\n",
                     i, startivlen);
          rc = gpg_error (GPG_ERR_TOO_SHORT);
          goto leave;
        }

      dfx->cipher_algo = ed->cipher_algo;
      dfx->aead_algo = ed->aead_algo;
      dfx->chunkbyte = ed->chunkbyte;
      dfx->chunksize = (uint64_t)1 << (dfx->chunkbyte + 6);

      if (dek->algo != dfx->cipher_algo)
        log_info ("Note: different cipher algorithms used (%s/%s)\n",
                  openpgp_cipher_algo_name (dek->algo),
                  openpgp_cipher_algo_name (dfx->cipher_algo));

      rc = openpgp_cipher_open (&dfx->cipher_hd,
                                dfx->cipher_algo,
                                ciphermode,
                                GCRY_CIPHER_SECURE);
      if (rc)
        goto leave; /* Should never happen.  */

      if (DBG_CRYPTO)
        log_printhex (dek->key, dek->keylen, "thekey:");
      rc = gcry_cipher_setkey (dfx->cipher_hd, dek->key, dek->keylen);
      if (gpg_err_code (rc) == GPG_ERR_WEAK_KEY)
        {
          log_info (_("WARNING: message was encrypted with"
                      " a weak key in the symmetric cipher.\n"));
          rc = 0;
        }
      else if (rc)
        {
          log_error("key setup failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (!ed->buf)
        {
          log_error(_("problem handling encrypted packet\n"));
          goto leave;
        }

      rc = aead_set_nonce (dfx);
      if (rc)
        goto leave;

      rc = aead_set_ad (dfx, 0);
      if (rc)
        goto leave;

    }
  else /* CFB encryption.  */
    {
      nprefix = blocksize;
      if ( ed->len && ed->len < (nprefix+2) )
        {
          /* An invalid message.  We can't check that during parsing
             because we may not know the used cipher then.  */
          rc = gpg_error (GPG_ERR_INV_PACKET);
          goto leave;
        }

      if ( ed->mdc_method )
        {
          if (gcry_md_open (&dfx->mdc_hash, ed->mdc_method, 0 ))
            BUG ();
          if ( DBG_HASHING )
            gcry_md_debug (dfx->mdc_hash, "checkmdc");
        }

      rc = openpgp_cipher_open (&dfx->cipher_hd, dek->algo,
                                GCRY_CIPHER_MODE_CFB,
                                (GCRY_CIPHER_SECURE
                                 | ((ed->mdc_method || dek->algo >= 100)?
                                    0 : GCRY_CIPHER_ENABLE_SYNC)));
      if (rc)
        {
          /* We should never get an error here cause we already checked
           * that the algorithm is available.  */
          BUG();
        }


      /* log_hexdump( "thekey", dek->key, dek->keylen );*/
      rc = gcry_cipher_setkey (dfx->cipher_hd, dek->key, dek->keylen);
      if ( gpg_err_code (rc) == GPG_ERR_WEAK_KEY )
        {
          log_info(_("WARNING: message was encrypted with"
                     " a weak key in the symmetric cipher.\n"));
          rc=0;
        }
      else if( rc )
        {
          log_error("key setup failed: %s\n", gpg_strerror (rc) );
          goto leave;
        }

      if (!ed->buf)
        {
          log_error(_("problem handling encrypted packet\n"));
          goto leave;
        }

      gcry_cipher_setiv (dfx->cipher_hd, NULL, 0);

      if ( ed->len )
        {
          for (i=0; i < (nprefix+2) && ed->len; i++, ed->len-- )
            {
              if ( (c=iobuf_get(ed->buf)) == -1 )
                break;
              else
                temp[i] = c;
            }
        }
      else
        {
          for (i=0; i < (nprefix+2); i++ )
            if ( (c=iobuf_get(ed->buf)) == -1 )
              break;
            else
              temp[i] = c;
        }

      gcry_cipher_decrypt (dfx->cipher_hd, temp, nprefix+2, NULL, 0);
      gcry_cipher_sync (dfx->cipher_hd);
      p = temp;
      /* log_hexdump( "prefix", temp, nprefix+2 ); */
      if (dek->symmetric
          && (p[nprefix-2] != p[nprefix] || p[nprefix-1] != p[nprefix+1]) )
        {
          rc = gpg_error (GPG_ERR_BAD_KEY);
          goto leave;
        }

      if ( dfx->mdc_hash )
        gcry_md_write (dfx->mdc_hash, temp, nprefix+2);
    }

  dfx->refcount++;
  dfx->partial = !!ed->is_partial;
  dfx->length = ed->len;
  if (ed->aead_algo)
    iobuf_push_filter ( ed->buf, aead_decode_filter, dfx );
  else if (ed->mdc_method)
    iobuf_push_filter ( ed->buf, mdc_decode_filter, dfx );
  else
    iobuf_push_filter ( ed->buf, decode_filter, dfx );

  if (opt.unwrap_encryption)
    {
      char *filename = NULL;
      estream_t fp;
      rc = get_output_file ("", 0, ed->buf, &filename, &fp);
      if (! rc)
        {
          iobuf_t output = iobuf_esopen (fp, "w", 0);
          armor_filter_context_t *afx = NULL;

          if (opt.armor)
            {
              afx = new_armor_context ();
              push_armor_filter (afx, output);
            }

          iobuf_copy (output, ed->buf);
          if ((rc = iobuf_error (ed->buf)))
            log_error (_("error reading '%s': %s\n"),
                       filename, gpg_strerror (rc));
          else if ((rc = iobuf_error (output)))
            log_error (_("error writing '%s': %s\n"),
                       filename, gpg_strerror (rc));

          iobuf_close (output);
          if (afx)
            release_armor_context (afx);
        }
      xfree (filename);
    }
  else
    proc_packets (ctrl, procctx, ed->buf );

  ed->buf = NULL;
  if (dfx->eof_seen > 1 )
    rc = gpg_error (GPG_ERR_INV_PACKET);
  else if ( ed->mdc_method )
    {
      /* We used to let parse-packet.c handle the MDC packet but this
         turned out to be a problem with compressed packets: With old
         style packets there is no length information available and
         the decompressor uses an implicit end.  However we can't know
         this implicit end beforehand (:-) and thus may feed the
         decompressor with more bytes than actually needed.  It would
         be possible to unread the extra bytes but due to our weird
         iobuf system any unread is non reliable due to filters
         already popped off.  The easy and sane solution is to care
         about the MDC packet only here and never pass it to the
         packet parser.  Fortunatley the OpenPGP spec requires a
         strict format for the MDC packet so that we know that 22
         bytes are appended.  */
      int datalen = gcry_md_get_algo_dlen (ed->mdc_method);

      log_assert (dfx->cipher_hd);
      log_assert (dfx->mdc_hash);
      gcry_cipher_decrypt (dfx->cipher_hd, dfx->holdback, 22, NULL, 0);
      gcry_md_write (dfx->mdc_hash, dfx->holdback, 2);
      gcry_md_final (dfx->mdc_hash);

      if (   dfx->holdback[0] != '\xd3'
          || dfx->holdback[1] != '\x14'
          || datalen != 20
          || memcmp (gcry_md_read (dfx->mdc_hash, 0), dfx->holdback+2, datalen))
        rc = gpg_error (GPG_ERR_BAD_SIGNATURE);
      /* log_printhex("MDC message:", dfx->holdback, 22); */
      /* log_printhex("MDC calc:", gcry_md_read (dfx->mdc_hash,0), datalen); */
    }


 leave:
  release_dfx_context (dfx);
  return rc;
}


/* The core of the AEAD decryption.  This is the underflow function of
 * the aead_decode_filter.  */
static gpg_error_t
aead_underflow (decode_filter_ctx_t dfx, iobuf_t a, byte *buf, size_t *ret_len)
{
  const size_t size = *ret_len; /* The initial length of BUF.  */
  gpg_error_t err;
  size_t n; /* Finally the number of decrypted bytes in BUF.  */
  int c;

  log_assert (size > 64); /* Our code requires at least this size.  */

  /* Get at least 32 bytes and put it ahead in the buffer.  */
  if (dfx->partial)
    {
      for (n=32; n < 64; n++)
        {
          if ((c = iobuf_get (a)) == -1)
            break;
          buf[n] = c;
        }
    }
  else
    {
      for (n=32; n < 64 && dfx->length; n++, dfx->length--)
        {
          if ((c = iobuf_get (a)) == -1)
            break; /* Premature EOF.  */
          buf[n] = c;
        }
    }

  if (n == 64)
    {
      /* We got 32 bytes from A which are good for the last chunk's
       * auth tag and the final chunk's auth tag.  On the first time
       * we don't have anything in the holdback buffer and thus we move
       * those 32 bytes to the start of the buffer.  All further calls
       * will copy the 32 bytes from the holdback buffer to the start of the
       * buffer.  */
      if (!dfx->holdbacklen)
        {
          memcpy (buf, buf+32, 32);
          n = 32;  /* Continue at this position.  */
        }
      else
        {
          memcpy (buf, dfx->holdback, 32);
        }

      /* Now fill up the provided buffer.  */
      if (dfx->partial)
        {
          for (; n < size; n++ )
            {
              if ((c = iobuf_get (a)) == -1)
                {
                  dfx->eof_seen = 1; /* Normal EOF. */
                  break;
                }
              buf[n] = c;
            }
        }
      else
        {
          for (; n < size && dfx->length; n++, dfx->length--)
            {
              c = iobuf_get (a);
              if (c == -1)
                {
                  dfx->eof_seen = 3; /* Premature EOF. */
                  break;
                }
              buf[n] = c;
            }
          if (!dfx->length)
            dfx->eof_seen = 1; /* Normal EOF.  */
        }

      /* Move the trailing 32 bytes back to the holdback buffer.  We
       * got at least 64 bytes and thus a memmove is not needed.  */
      n -= 32;
      memcpy (dfx->holdback, buf+n, 32);
      dfx->holdbacklen = 32;
    }
  else if (!dfx->holdbacklen)
    {
      /* EOF seen but empty holdback buffer.  This means that we did
       * not read enough for the two auth tags.  */
      n -= 32;
      memcpy (buf, buf+32, n );
      dfx->eof_seen = 2; /* EOF with incomplete tag.  */
    }
  else
    {
      /* EOF seen (i.e. read less than 32 bytes). */
      memcpy (buf, dfx->holdback, 32);
      n -= 32;
      memcpy (dfx->holdback, buf+n, 32);
      dfx->eof_seen = 1; /* Normal EOF. */
    }

  if (DBG_FILTER)
    log_debug ("decrypt: chunklen=%ju total=%ju size=%zu n=%zu%s\n",
               (uintmax_t)dfx->chunklen, (uintmax_t)dfx->total, size, n,
               dfx->eof_seen? " eof":"");

  /* Now decrypt the buffer.  */
  if (n && dfx->eof_seen > 1)
    {
      err = gpg_error (GPG_ERR_TRUNCATED);
    }
  else if (!n)
    {
      log_assert (dfx->eof_seen);
      err = gpg_error (GPG_ERR_EOF);
    }
  else
    {
      size_t off = 0;

      if (dfx->chunklen + n >= dfx->chunksize)
        {
          size_t n0 = dfx->chunksize - dfx->chunklen;

          if (DBG_FILTER)
            log_debug ("chunksize will be reached: n0=%zu\n", n0);
          gcry_cipher_final (dfx->cipher_hd);
          err = gcry_cipher_decrypt (dfx->cipher_hd, buf, n0, NULL, 0);
          if (err)
            {
              log_error ("gcry_cipher_decrypt failed (1): %s\n",
                         gpg_strerror (err));
              goto leave;
            }
          /*log_printhex (buf, n, "buf:");*/
          dfx->chunklen += n0;
          dfx->total += n0;
          off = n0;
          n -= n0;

          if (DBG_FILTER)
            log_debug ("bytes left: %zu  off=%zu\n", n, off);
          log_assert (n >= 16);
          log_assert (dfx->holdbacklen);
          if (DBG_CRYPTO)
            log_printhex (buf+off, 16, "tag:");
          err = gcry_cipher_checktag (dfx->cipher_hd, buf + off, 16);
          if (err)
            {
              if (DBG_FILTER)
                log_debug ("gcry_cipher_checktag failed (1): %s\n",
                           gpg_strerror (err));
              /* Return Bad Signature like we do with MDC encryption. */
              if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
                err = gpg_error (GPG_ERR_BAD_SIGNATURE);
              goto leave;
            }
          /* Remove that tag from the output.  */
          memmove (buf + off, buf + off + 16, n - 16);
          n -= 16;

          /* Prepare a new chunk.  */
          dfx->chunklen = 0;
          dfx->chunkindex++;
          err = aead_set_nonce (dfx);
          if (err)
            goto leave;
          err = aead_set_ad (dfx, 0);
          if (err)
            goto leave;
        }

      if (dfx->eof_seen)
        {
          /* This is the last block of the last chunk.  Its length may
           * not be a multiple of the block length.  We expect that it
           * is followed by two authtags.  The first being the one
           * from the current chunk and the second form the final
           * chunk encrypting the empty string.  Note that for the
           * other blocks we assume a multiple of the block length
           * which is only true because the filter is called with
           * large 2^n sized buffers.  There is no assert because
           * gcry_cipher_decrypt would detect such an error.  */
          gcry_cipher_final (dfx->cipher_hd);
          /* log_printhex (buf+off, n, "buf+off:"); */
        }
      err = gcry_cipher_decrypt (dfx->cipher_hd, buf + off, n, NULL, 0);
      if (err)
        {
          log_error ("gcry_cipher_decrypt failed (2): %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      dfx->chunklen += n;
      dfx->total += n;

      if (dfx->eof_seen)
        {
          log_printhex (buf+off, n, "buf+off:");
          if (DBG_FILTER)
            log_debug ("eof seen: chunklen=%ju total=%ju off=%zu n=%zu\n",
                       (uintmax_t)dfx->chunklen, (uintmax_t)dfx->total, off, n);

          log_assert (dfx->holdbacklen);
          err = gcry_cipher_checktag (dfx->cipher_hd, dfx->holdback, 16);
          if (err)
            {
              log_printhex (dfx->holdback, 16, "tag:");
              log_error ("gcry_cipher_checktag failed (2): %s\n",
                         gpg_strerror (err));
              /* Return Bad Signature like we do with MDC encryption. */
              if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
                err = gpg_error (GPG_ERR_BAD_SIGNATURE);
              goto leave;
            }

          /* Check the final chunk.  */
          dfx->chunkindex++;
          err = aead_set_nonce (dfx);
          if (err)
            goto leave;
          err = aead_set_ad (dfx, 1);
          if (err)
            goto leave;
          gcry_cipher_final (dfx->cipher_hd);
          /* decrypt an empty string.  */
          err = gcry_cipher_decrypt (dfx->cipher_hd, buf, 0, NULL, 0);
          if (err)
            {
              log_error ("gcry_cipher_decrypt failed (final): %s\n",
                         gpg_strerror (err));
              goto leave;
            }
          err = gcry_cipher_checktag (dfx->cipher_hd, dfx->holdback+16, 16);
          if (err)
            {
              if (DBG_FILTER)
                log_debug ("gcry_cipher_checktag failed (final): %s\n",
                           gpg_strerror (err));
              /* Return Bad Signature like we do with MDC encryption. */
              if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
                err = gpg_error (GPG_ERR_BAD_SIGNATURE);
              goto leave;
            }

          n += off;
          if (DBG_FILTER)
            log_debug ("eof seen: returning %zu\n", n);
          /* log_printhex (buf, n, "buf:"); */
        }
      else
        n += off;
    }

 leave:
  /* In case of a real error we better wipe out the buffer than to
   * keep partly encrypted data.  */
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    memset (buf, 0, size);
  *ret_len = n;

  return err;
}


/* The IOBUF filter used to decrypt AEAD encrypted data.  */
static int
aead_decode_filter (void *opaque, int control, IOBUF a,
                    byte *buf, size_t *ret_len)
{
  decode_filter_ctx_t dfx = opaque;
  int rc = 0;

  if ( control == IOBUFCTRL_UNDERFLOW && dfx->eof_seen )
    {
      *ret_len = 0;
      rc = -1;
    }
  else if ( control == IOBUFCTRL_UNDERFLOW )
    {
      log_assert (a);

      rc = aead_underflow (dfx, a, buf, ret_len);
      if (gpg_err_code (rc) == GPG_ERR_EOF)
        rc = -1; /* We need to use the old convention in the filter.  */

    }
  else if ( control == IOBUFCTRL_FREE )
    {
      release_dfx_context (dfx);
    }
  else if ( control == IOBUFCTRL_DESC )
    {
      mem2str (buf, "aead_decode_filter", *ret_len);
    }

  return rc;
}


static int
mdc_decode_filter (void *opaque, int control, IOBUF a,
                   byte *buf, size_t *ret_len)
{
  decode_filter_ctx_t dfx = opaque;
  size_t n, size = *ret_len;
  int rc = 0;
  int c;

  /* Note: We need to distinguish between a partial and a fixed length
     packet.  The first is the usual case as created by GPG.  However
     for short messages the format degrades to a fixed length packet
     and other implementations might use fixed length as well.  Only
     looking for the EOF on fixed data works only if the encrypted
     packet is not followed by other data.  This used to be a long
     standing bug which was fixed on 2009-10-02.  */

  if ( control == IOBUFCTRL_UNDERFLOW && dfx->eof_seen )
    {
      *ret_len = 0;
      rc = -1;
    }
  else if( control == IOBUFCTRL_UNDERFLOW )
    {
      log_assert (a);
      log_assert (size > 44); /* Our code requires at least this size.  */

      /* Get at least 22 bytes and put it ahead in the buffer.  */
      if (dfx->partial)
        {
          for (n=22; n < 44; n++)
            {
              if ( (c = iobuf_get(a)) == -1 )
                break;
              buf[n] = c;
            }
        }
      else
        {
          for (n=22; n < 44 && dfx->length; n++, dfx->length--)
            {
              c = iobuf_get (a);
              if (c == -1)
                break; /* Premature EOF.  */
              buf[n] = c;
            }
        }
      if (n == 44)
        {
          /* We have enough stuff - flush the holdback buffer.  */
          if ( !dfx->holdbacklen )  /* First time. */
            {
              memcpy (buf, buf+22, 22);
              n = 22;
	    }
          else
            {

              memcpy (buf, dfx->holdback, 22);
	    }
          /* Fill up the buffer. */
          if (dfx->partial)
            {
              for (; n < size; n++ )
                {
                  if ( (c = iobuf_get(a)) == -1 )
                    {
                      dfx->eof_seen = 1; /* Normal EOF. */
                      break;
                    }
                  buf[n] = c;
                }
            }
          else
            {
              for (; n < size && dfx->length; n++, dfx->length--)
                {
                  c = iobuf_get(a);
                  if (c == -1)
                    {
                      dfx->eof_seen = 3; /* Premature EOF. */
                      break;
                    }
                  buf[n] = c;
                }
              if (!dfx->length)
                dfx->eof_seen = 1; /* Normal EOF.  */
            }

          /* Move the trailing 22 bytes back to the holdback buffer.  We
             have at least 44 bytes thus a memmove is not needed.  */
          n -= 22;
          memcpy (dfx->holdback, buf+n, 22 );
          dfx->holdbacklen = 22;
	}
      else if ( !dfx->holdbacklen ) /* EOF seen but empty holdback. */
        {
          /* This is bad because it means an incomplete hash. */
          n -= 22;
          memcpy (buf, buf+22, n );
          dfx->eof_seen = 2; /* EOF with incomplete hash.  */
	}
      else  /* EOF seen (i.e. read less than 22 bytes). */
        {
          memcpy (buf, dfx->holdback, 22 );
          n -= 22;
          memcpy (dfx->holdback, buf+n, 22 );
          dfx->eof_seen = 1; /* Normal EOF. */
	}

      if ( n )
        {
          if ( dfx->cipher_hd )
            gcry_cipher_decrypt (dfx->cipher_hd, buf, n, NULL, 0);
          if ( dfx->mdc_hash )
            gcry_md_write (dfx->mdc_hash, buf, n);
	}
      else
        {
          log_assert ( dfx->eof_seen );
          rc = -1; /* Return EOF.  */
	}
      *ret_len = n;
    }
  else if ( control == IOBUFCTRL_FREE )
    {
      release_dfx_context (dfx);
    }
  else if ( control == IOBUFCTRL_DESC )
    {
      mem2str (buf, "mdc_decode_filter", *ret_len);
    }
  return rc;
}


static int
decode_filter( void *opaque, int control, IOBUF a, byte *buf, size_t *ret_len)
{
  decode_filter_ctx_t fc = opaque;
  size_t size = *ret_len;
  size_t n;
  int c, rc = 0;


  if ( control == IOBUFCTRL_UNDERFLOW && fc->eof_seen )
    {
      *ret_len = 0;
      rc = -1;
    }
  else if ( control == IOBUFCTRL_UNDERFLOW )
    {
      log_assert (a);

      if (fc->partial)
        {
          for (n=0; n < size; n++ )
            {
              c = iobuf_get(a);
              if (c == -1)
                {
                  fc->eof_seen = 1; /* Normal EOF. */
                  break;
                }
              buf[n] = c;
            }
        }
      else
        {
          for (n=0; n < size && fc->length; n++, fc->length--)
            {
              c = iobuf_get(a);
              if (c == -1)
                {
                  fc->eof_seen = 3; /* Premature EOF. */
                  break;
                }
              buf[n] = c;
            }
          if (!fc->length)
            fc->eof_seen = 1; /* Normal EOF.  */
        }
      if (n)
        {
          if (fc->cipher_hd)
            gcry_cipher_decrypt (fc->cipher_hd, buf, n, NULL, 0);
        }
      else
        {
          if (!fc->eof_seen)
            fc->eof_seen = 1;
          rc = -1; /* Return EOF. */
        }
      *ret_len = n;
    }
  else if ( control == IOBUFCTRL_FREE )
    {
      release_dfx_context (fc);
    }
  else if ( control == IOBUFCTRL_DESC )
    {
      mem2str (buf, "decode_filter", *ret_len);
    }
  return rc;
}
