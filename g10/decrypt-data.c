/* decrypt-data.c - Decrypt an encrypted data packet
 * Copyright (C) 1998, 1999, 2000, 2001, 2005,
 *               2006, 2009 Free Software Foundation, Inc.
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


static int mdc_decode_filter ( void *opaque, int control, IOBUF a,
                               byte *buf, size_t *ret_len);
static int decode_filter ( void *opaque, int control, IOBUF a,
					byte *buf, size_t *ret_len);

typedef struct decode_filter_context_s
{
  gcry_cipher_hd_t cipher_hd;
  gcry_md_hd_t mdc_hash;
  char defer[22];
  int  defer_filled;
  int  eof_seen;
  int  refcount;
  int  partial;   /* Working on a partial length packet.  */
  size_t length;  /* If !partial: Remaining bytes in the packet.  */
} *decode_filter_ctx_t;


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
  unsigned blocksize;
  unsigned nprefix;

  dfx = xtrycalloc (1, sizeof *dfx);
  if (!dfx)
    return gpg_error_from_syserror ();
  dfx->refcount = 1;

  if ( opt.verbose && !dek->algo_info_printed )
    {
      if (!openpgp_cipher_test_algo (dek->algo))
        log_info (_("%s encrypted data\n"),
                  openpgp_cipher_algo_name (dek->algo));
      else
        log_info (_("encrypted with unknown algorithm %d\n"), dek->algo );
      dek->algo_info_printed = 1;
    }

  {
    char buf[20];

    snprintf (buf, sizeof buf, "%d %d", ed->mdc_method, dek->algo);
    write_status_text (STATUS_DECRYPTION_INFO, buf);
  }

  if (opt.show_session_key)
    {
      char numbuf[25];
      char *hexbuf;

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

  dfx->refcount++;
  dfx->partial = ed->is_partial;
  dfx->length = ed->len;
  if ( ed->mdc_method )
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
      gcry_cipher_decrypt (dfx->cipher_hd, dfx->defer, 22, NULL, 0);
      gcry_md_write (dfx->mdc_hash, dfx->defer, 2);
      gcry_md_final (dfx->mdc_hash);

      if (   dfx->defer[0] != '\xd3'
          || dfx->defer[1] != '\x14'
          || datalen != 20
          || memcmp (gcry_md_read (dfx->mdc_hash, 0), dfx->defer+2, datalen))
        rc = gpg_error (GPG_ERR_BAD_SIGNATURE);
      /* log_printhex("MDC message:", dfx->defer, 22); */
      /* log_printhex("MDC calc:", gcry_md_read (dfx->mdc_hash,0), datalen); */
    }


 leave:
  release_dfx_context (dfx);
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
          /* We have enough stuff - flush the deferred stuff.  */
          if ( !dfx->defer_filled )  /* First time. */
            {
              memcpy (buf, buf+22, 22);
              n = 22;
	    }
          else
            {
              memcpy (buf, dfx->defer, 22);
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

          /* Move the trailing 22 bytes back to the defer buffer.  We
             have at least 44 bytes thus a memmove is not needed.  */
          n -= 22;
          memcpy (dfx->defer, buf+n, 22 );
          dfx->defer_filled = 1;
	}
      else if ( !dfx->defer_filled )  /* EOF seen but empty defer buffer. */
        {
          /* This is bad because it means an incomplete hash. */
          n -= 22;
          memcpy (buf, buf+22, n );
          dfx->eof_seen = 2; /* EOF with incomplete hash.  */
	}
      else  /* EOF seen (i.e. read less than 22 bytes). */
        {
          memcpy (buf, dfx->defer, 22 );
          n -= 22;
          memcpy (dfx->defer, buf+n, 22 );
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
