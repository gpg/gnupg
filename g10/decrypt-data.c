/* decrypt-data.c - Decrypt an encrypted data packet
 * Copyright (C) 1998-2001, 2005-2006, 2009 Free Software Foundation, Inc.
 * Copyright (C) 1998-2001, 2005-2006, 2009, 2018 Werner Koch
 * Copyright (C) 2020 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
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
  /* Recounter (max value is 2).  We need it because we do not know
   * whether the iobuf or the outer control code frees this object
   * first.  */
  int  refcount;

  /* The cipher handle.  */
  gcry_cipher_hd_t cipher_hd;

  /* The hash handle for use in MDC mode.  */
  gcry_md_hd_t mdc_hash;

  /* The start IV for AEAD encryption.   */
  byte startiv[16];

  /* The holdback buffer and its used length.  For AEAD we need 32+1
   * bytes but we use 48 byte.  For MDC we need 22 bytes; here
   * holdbacklen will either 0 or 22.  */
  char holdback[48];
  unsigned int holdbacklen;

  /* Working on a partial length packet.  */
  unsigned int partial : 1;

  /* EOF indicator with these true values:
   *   1 = normal EOF
   *   2 = premature EOF (tag or hash incomplete)
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


/* Set the nonce and the additional data for the current chunk.  This
 * also reset the decryption machinery so that the handle can be
 * used for a new chunk.  If FINAL is set the final AEAD chunk is
 * processed.  */
static gpg_error_t
aead_set_nonce_and_ad (decode_filter_ctx_t dfx, int final)
{
  gpg_error_t err;
  unsigned char ad[21];
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
  err = gcry_cipher_setiv (dfx->cipher_hd, nonce, i);
  if (err)
    return err;

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


/* Helper to check the 16 byte tag in TAGBUF.  The FINAL flag is only
 * for debug messages.  */
static gpg_error_t
aead_checktag (decode_filter_ctx_t dfx, int final, const void *tagbuf)
{
  gpg_error_t err;

  if (DBG_FILTER)
    log_printhex (tagbuf, 16, "tag:");
  err = gcry_cipher_checktag (dfx->cipher_hd, tagbuf, 16);
  if (err)
    {
      log_error ("gcry_cipher_checktag%s failed: %s\n",
                 final? " (final)":"", gpg_strerror (err));
      return err;
    }
  if (DBG_FILTER)
    log_debug ("%stag is valid\n", final?"final ":"");
  return 0;
}


/****************
 * Decrypt the data, specified by ED with the key DEK.  On return
 * COMPLIANCE_ERROR is set to true iff the decryption can claim that
 * it was compliant in the current mode; otherwise this flag is set to
 * false.
 */
int
decrypt_data (ctrl_t ctrl, void *procctx, PKT_encrypted *ed, DEK *dek,
              int *compliance_error)
{
  decode_filter_ctx_t dfx;
  enum gcry_cipher_modes ciphermode;
  unsigned int startivlen;
  byte *p;
  int rc=0, c, i;
  byte temp[32];
  unsigned blocksize;
  unsigned nprefix;

  *compliance_error = 0;

  dfx = xtrycalloc (1, sizeof *dfx);
  if (!dfx)
    return gpg_error_from_syserror ();
  dfx->refcount = 1;

  if ( opt.verbose && !dek->algo_info_printed )
    {
      if (!openpgp_cipher_test_algo (dek->algo))
        log_info (_("%s encrypted data\n"),
                  openpgp_cipher_algo_mode_name (dek->algo, ed->aead_algo));
      else
        log_info (_("encrypted with unknown algorithm %d\n"), dek->algo );
      dek->algo_info_printed = 1;
    }

  if (ed->aead_algo)
    {
      rc = openpgp_aead_algo_info (ed->aead_algo, &ciphermode, &startivlen);
      if (rc)
        goto leave;
      log_assert (startivlen <= sizeof dfx->startiv);
    }
  else
    ciphermode = GCRY_CIPHER_MODE_CFB;

  /* Check compliance.  */
  if (!gnupg_cipher_is_allowed (opt.compliance, 0, dek->algo, ciphermode))
    {
      log_error (_("cipher algorithm '%s' may not be used in %s mode\n"),
		 openpgp_cipher_algo_mode_name (dek->algo,ed->aead_algo),
		 gnupg_compliance_option_string (opt.compliance));
      *compliance_error = 1;
      if (opt.flags.require_compliance)
        {
          /* We fail early in this case because it does not make sense
           * to first decrypt everything.  */
          rc = gpg_error (GPG_ERR_CIPHER_ALGO);
          goto leave;
        }
    }

  write_status_printf (STATUS_DECRYPTION_INFO, "%d %d %d",
                       ed->mdc_method, dek->algo, 0);

  if (opt.show_session_key)
    {
      char numbuf[25];
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
      if (blocksize != 16)
        {
          rc = gpg_error (GPG_ERR_CIPHER_ALGO);
          goto leave;
        }

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

    }
  else /* CFB encryption.  */
    {
      nprefix = blocksize;
      if ( ed->len && ed->len < (nprefix+2) )
        {
          /* An invalid message.  We can't check that during parsing
           * because we may not know the used cipher then.  */
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
          log_info (_("WARNING: message was encrypted with"
                      " a weak key in the symmetric cipher.\n"));
          rc = 0;
        }
      else if (rc)
        {
          log_error("key setup failed: %s\n", gpg_strerror (rc) );
          goto leave;
        }

      if (!ed->buf)
        {
          log_error (_("problem handling encrypted packet\n"));
          rc = gpg_error (GPG_ERR_INV_PACKET);
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

	  es_setbuf (fp, NULL);

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
      /* log_printhex(dfx->holdback, 22, "MDC message:"); */
      /* log_printhex(gcry_md_read (dfx->mdc_hash,0), datalen, "MDC calc:"); */
    }

 leave:
  release_dfx_context (dfx);
  return rc;
}


/* Fill BUFFER with up to NBYTES-OFFSET from STREAM utilizing
 * information from the context DFX.  Returns the new offset which is
 * the number of bytes read plus the original offset.  On EOF the
 * respective flag in DFX is set. */
static size_t
fill_buffer (decode_filter_ctx_t dfx, iobuf_t stream,
             byte *buffer, size_t nbytes, size_t offset)
{
  size_t nread = offset;
  size_t curr;
  int ret;

  if (dfx->partial)
    {
      while (nread < nbytes)
        {
          curr = nbytes - nread;

          ret = iobuf_read (stream, &buffer[nread], curr);
          if (ret == -1)
            {
              dfx->eof_seen = 1; /* Normal EOF. */
              break;
            }

          nread += ret;
        }
    }
  else
    {
      while (nread < nbytes && dfx->length)
        {
          curr = nbytes - nread;
          if (curr > dfx->length)
            curr = dfx->length;

          ret = iobuf_read (stream, &buffer[nread], curr);
          if (ret == -1)
            {
              dfx->eof_seen = 3; /* Premature EOF. */
              break;
            }

          nread += ret;
          dfx->length -= ret;
        }
      if (!dfx->length)
        dfx->eof_seen = 1; /* Normal EOF.  */
    }

  return nread;
}


/* The core of the AEAD decryption.  This is the underflow function of
 * the aead_decode_filter.  */
static gpg_error_t
aead_underflow (decode_filter_ctx_t dfx, iobuf_t a, byte *buf, size_t *ret_len)
{
  const size_t size = *ret_len; /* The allocated size of BUF.  */
  gpg_error_t err;
  size_t totallen = 0; /* The number of bytes to return on success or EOF.  */
  size_t off = 0;      /* The offset into the buffer.  */
  size_t len;          /* The current number of bytes in BUF+OFF.  */

  log_assert (size > 48); /* Our code requires at least this size.  */

  /* Copy the rest from the last call of this function into BUF.  */
  len = dfx->holdbacklen;
  dfx->holdbacklen = 0;
  memcpy (buf, dfx->holdback, len);

  if (DBG_FILTER)
    log_debug ("aead_underflow: size=%zu len=%zu%s%s\n", size, len,
               dfx->partial? " partial":"", dfx->eof_seen? " eof":"");

  /* Read and fill up BUF.  We need to watch out for an EOF so that we
   * can detect the last chunk which is commonly shorter than the
   * chunksize.  After the last data byte from the last chunk 32 more
   * bytes are expected for the last chunk's tag and the following
   * final chunk's tag.  To detect the EOF we need to try reading at least
   * one further byte; however we try to read 16 extra bytes to avoid
   * single byte reads in some lower layers.  The outcome is that we
   * have up to 48 extra extra octets which we will later put into the
   * holdback buffer for the next invocation (which handles the EOF
   * case).  */
  len = fill_buffer (dfx, a, buf, size, len);
  if (len < 32)
    {
      /* Not enough data for the last two tags.  */
      err = gpg_error (GPG_ERR_TRUNCATED);
      goto leave;
    }
  if (dfx->eof_seen)
    {
      /* If have seen an EOF we copy only the last two auth tags into
       * the holdback buffer.  */
      dfx->holdbacklen = 32;
      memcpy (dfx->holdback, buf+len-32, 32);
      len -= 32;
    }
  else
    {
      /* If have not seen an EOF we copy the entire extra 48 bytes
       * into the holdback buffer for processing at the next call of
       * this function.  */
      dfx->holdbacklen = len > 48? 48 : len;
      memcpy (dfx->holdback, buf+len-dfx->holdbacklen, dfx->holdbacklen);
      len -= dfx->holdbacklen;
    }
  /* log_printhex (dfx->holdback, dfx->holdbacklen, "holdback:"); */

  /* Decrypt the buffer.  This first requires a loop to handle the
   * case when a chunk ends within the buffer.  */
  if (DBG_FILTER)
    log_debug ("decrypt: chunklen=%ju total=%ju size=%zu len=%zu%s\n",
               dfx->chunklen, dfx->total, size, len,
               dfx->eof_seen? " eof":"");

  while (len && dfx->chunklen + len >= dfx->chunksize)
    {
      size_t n = dfx->chunksize - dfx->chunklen;
      byte tagbuf[16];

      if (DBG_FILTER)
        log_debug ("chunksize will be reached: n=%zu\n", n);

      if (!dfx->chunklen)
        {
          /* First data for this chunk - prepare.  */
          err = aead_set_nonce_and_ad (dfx, 0);
          if (err)
            goto leave;
        }

      /* log_printhex (buf, n, "ciph:"); */
      gcry_cipher_final (dfx->cipher_hd);
      err = gcry_cipher_decrypt (dfx->cipher_hd, buf+off, n, NULL, 0);
      if (err)
        {
          log_error ("gcry_cipher_decrypt failed (1): %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      /* log_printhex (buf, n, "plai:"); */
      totallen += n;
      dfx->chunklen += n;
      dfx->total += n;
      off += n;
      len -= n;

      if (DBG_FILTER)
        log_debug ("ndecrypted: %zu (nchunk=%ju) bytes left: %zu at off=%zu\n",
                   totallen, dfx->chunklen, len, off);

      /* Check the tag.  */
      if (len < 16)
        {
          /* The tag is not entirely in the buffer.  Read the rest of
           * the tag from the holdback buffer.  Then shift the holdback
           * buffer and fill it up again.  */
          memcpy (tagbuf, buf+off, len);
          memcpy (tagbuf + len, dfx->holdback, 16 - len);
          dfx->holdbacklen -= 16-len;
          memmove (dfx->holdback, dfx->holdback + (16-len), dfx->holdbacklen);

          if (dfx->eof_seen)
            {
              /* We should have the last chunk's tag in TAGBUF and the
               * final tag in HOLDBACKBUF.  */
              if (len || dfx->holdbacklen != 16)
                {
                  /* Not enough data for the last two tags.  */
                  err = gpg_error (GPG_ERR_TRUNCATED);
                  goto leave;
                }
            }
          else
            {
              len = 0;
              dfx->holdbacklen = fill_buffer (dfx, a, dfx->holdback, 48,
                                              dfx->holdbacklen);
              if (dfx->holdbacklen < 32)
                {
                  /* Not enough data for the last two tags.  */
                  err = gpg_error (GPG_ERR_TRUNCATED);
                  goto leave;
                }
            }
        }
      else /* We already have the full tag.  */
        {
          memcpy (tagbuf, buf+off, 16);
          /* Remove that tag from the output.  */
          memmove (buf + off, buf + off + 16, len - 16);
          len -= 16;
        }
      err = aead_checktag (dfx, 0, tagbuf);
      if (err)
        goto leave;
      dfx->chunklen = 0;
      dfx->chunkindex++;

      continue;
    }

  /* The bulk decryption of our buffer.  */
  if (len)
    {
      if (!dfx->chunklen)
        {
          /* First data for this chunk - prepare.  */
          err = aead_set_nonce_and_ad (dfx, 0);
          if (err)
            goto leave;
        }

      if (dfx->eof_seen)
        {
          /* This is the last block of the last chunk.  Its length may
           * not be a multiple of the block length.  */
          gcry_cipher_final (dfx->cipher_hd);
        }
      err = gcry_cipher_decrypt (dfx->cipher_hd, buf + off, len, NULL, 0);
      if (err)
        {
          log_error ("gcry_cipher_decrypt failed (2): %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      totallen += len;
      dfx->chunklen += len;
      dfx->total += len;
      if (DBG_FILTER)
        log_debug ("ndecrypted: %zu (nchunk=%ju)\n", totallen, dfx->chunklen);
    }

  if (dfx->eof_seen)
    {

      if (dfx->chunklen)
        {
          if (DBG_FILTER)
            log_debug ("eof seen: holdback has the last and final tag\n");
          log_assert (dfx->holdbacklen >= 32);
          err = aead_checktag (dfx, 0, dfx->holdback);
          if (err)
            goto leave;
          dfx->chunklen = 0;
          dfx->chunkindex++;
          off = 16;
        }
      else
        {
          if (DBG_FILTER)
            log_debug ("eof seen: holdback has the final tag\n");
          log_assert (dfx->holdbacklen >= 16);
          off = 0;
        }

      /* Check the final chunk.  */
      err = aead_set_nonce_and_ad (dfx, 1);
      if (err)
        goto leave;
      gcry_cipher_final (dfx->cipher_hd);
      /* Decrypt an empty string (using HOLDBACK as a dummy).  */
      err = gcry_cipher_decrypt (dfx->cipher_hd, dfx->holdback, 0, NULL, 0);
      if (err)
        {
          log_error ("gcry_cipher_decrypt failed (final): %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      err = aead_checktag (dfx, 1, dfx->holdback+off);
      if (err)
        goto leave;
      err = gpg_error (GPG_ERR_EOF);
    }

 leave:
  if (DBG_FILTER)
    log_debug ("aead_underflow: returning %zu (%s)\n",
               totallen, gpg_strerror (err));

  /* In case of an auth error we map the error code to the same as
   * used by the MDC decryption.  */
  if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
    err = gpg_error (GPG_ERR_BAD_SIGNATURE);

  /* In case of an error we better wipe out the buffer than to convey
   * partly decrypted data.  */
  if (err && gpg_err_code (err) != GPG_ERR_EOF)
    memset (buf, 0, size);

  *ret_len = totallen;

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
      n = fill_buffer (dfx, a, buf, 44, 22);
      if (n == 44)
        {
          /* We have enough stuff - flush the deferred stuff.  */
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
          n = fill_buffer (dfx, a, buf, size, n);

          /* Move the trailing 22 bytes back to the holdback buffer.  We
             have at least 44 bytes thus a memmove is not needed.  */
          n -= 22;
          memcpy (dfx->holdback, buf+n, 22 );
          dfx->holdbacklen = 22;
	}
      else if ( !dfx->holdbacklen )  /* EOF seen but empty holdback buffer. */
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
  int rc = 0;


  if ( control == IOBUFCTRL_UNDERFLOW && fc->eof_seen )
    {
      *ret_len = 0;
      rc = -1;
    }
  else if ( control == IOBUFCTRL_UNDERFLOW )
    {
      log_assert (a);

      n = fill_buffer (fc, a, buf, size, 0);
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
