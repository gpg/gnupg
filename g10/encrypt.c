/* encrypt.c - Main encryption driver
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2009 Free Software Foundation, Inc.
 * Copyright (C) 2016 g10 Code GmbH
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
#include <errno.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "keydb.h"
#include "../common/util.h"
#include "main.h"
#include "filter.h"
#include "trustdb.h"
#include "../common/i18n.h"
#include "../common/status.h"
#include "pkglue.h"


static int encrypt_simple( const char *filename, int mode, int use_seskey );
static int write_pubkey_enc_from_list (ctrl_t ctrl,
                                       PK_LIST pk_list, DEK *dek, iobuf_t out);

/****************
 * Encrypt FILENAME with only the symmetric cipher.  Take input from
 * stdin if FILENAME is NULL.
 */
int
encrypt_symmetric (const char *filename)
{
  return encrypt_simple( filename, 1, 0 );
}


/****************
 * Encrypt FILENAME as a literal data packet only. Take input from
 * stdin if FILENAME is NULL.
 */
int
encrypt_store (const char *filename)
{
  return encrypt_simple( filename, 0, 0 );
}


/* *SESKEY contains the unencrypted session key ((*SESKEY)->KEY) and
   the algorithm that will be used to encrypt the contents of the SED
   packet ((*SESKEY)->ALGO).  If *SESKEY is NULL, then a random
   session key that is appropriate for DEK->ALGO is generated and
   stored there.

   Encrypt that session key using DEK and store the result in ENCKEY,
   which must be large enough to hold (*SESKEY)->KEYLEN + 1 bytes.  */
void
encrypt_seskey (DEK *dek, DEK **seskey, byte *enckey)
{
  gcry_cipher_hd_t hd;
  byte buf[33];

  log_assert ( dek->keylen <= 32 );
  if (!*seskey)
    {
      *seskey=xmalloc_clear(sizeof(DEK));
      (*seskey)->algo=dek->algo;
      make_session_key(*seskey);
      /*log_hexdump( "thekey", c->key, c->keylen );*/
    }

  /* The encrypted session key is prefixed with a one-octet algorithm id.  */
  buf[0] = (*seskey)->algo;
  memcpy( buf + 1, (*seskey)->key, (*seskey)->keylen );

  /* We only pass already checked values to the following function,
     thus we consider any failure as fatal.  */
  if (openpgp_cipher_open (&hd, dek->algo, GCRY_CIPHER_MODE_CFB, 1))
    BUG ();
  if (gcry_cipher_setkey (hd, dek->key, dek->keylen))
    BUG ();
  gcry_cipher_setiv (hd, NULL, 0);
  gcry_cipher_encrypt (hd, buf, (*seskey)->keylen + 1, NULL, 0);
  gcry_cipher_close (hd);

  memcpy( enckey, buf, (*seskey)->keylen + 1 );
  wipememory( buf, sizeof buf ); /* burn key */
}


/* We try very hard to use a MDC */
int
use_mdc (pk_list_t pk_list,int algo)
{
  /* RFC-2440 don't has MDC */
  if (RFC2440)
    return 0;

  /* --force-mdc overrides --disable-mdc */
  if(opt.force_mdc)
    return 1;

  if(opt.disable_mdc)
    return 0;

  /* Do the keys really support MDC? */

  if(select_mdc_from_pklist(pk_list))
    return 1;

  /* The keys don't support MDC, so now we do a bit of a hack - if any
     of the AESes or TWOFISH are in the prefs, we assume that the user
     can handle a MDC.  This is valid for PGP 7, which can handle MDCs
     though it will not generate them.  2440bis allows this, by the
     way. */

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_AES,NULL)==CIPHER_ALGO_AES)
    return 1;

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_AES192,NULL)==CIPHER_ALGO_AES192)
    return 1;

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_AES256,NULL)==CIPHER_ALGO_AES256)
    return 1;

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_TWOFISH,NULL)==CIPHER_ALGO_TWOFISH)
    return 1;

  /* Last try.  Use MDC for the modern ciphers. */

  if (openpgp_cipher_get_algo_blklen (algo) != 8)
    return 1;

  if (opt.verbose)
    warn_missing_mdc_from_pklist (pk_list);

  return 0; /* No MDC */
}


/* We don't want to use use_seskey yet because older gnupg versions
   can't handle it, and there isn't really any point unless we're
   making a message that can be decrypted by a public key or
   passphrase. */
static int
encrypt_simple (const char *filename, int mode, int use_seskey)
{
  iobuf_t inp, out;
  PACKET pkt;
  PKT_plaintext *pt = NULL;
  STRING2KEY *s2k = NULL;
  byte enckey[33];
  int rc = 0;
  int seskeylen = 0;
  u32 filesize;
  cipher_filter_context_t cfx;
  armor_filter_context_t  *afx = NULL;
  compress_filter_context_t zfx;
  text_filter_context_t tfx;
  progress_filter_context_t *pfx;
  int do_compress = !!default_compress_algo();

  pfx = new_progress_context ();
  memset( &cfx, 0, sizeof cfx);
  memset( &zfx, 0, sizeof zfx);
  memset( &tfx, 0, sizeof tfx);
  init_packet(&pkt);

  /* Prepare iobufs. */
  inp = iobuf_open(filename);
  if (inp)
    iobuf_ioctl (inp, IOBUF_IOCTL_NO_CACHE, 1, NULL);
  if (inp && is_secured_file (iobuf_get_fd (inp)))
    {
      iobuf_close (inp);
      inp = NULL;
      gpg_err_set_errno (EPERM);
    }
  if (!inp)
    {
      rc = gpg_error_from_syserror ();
      log_error(_("can't open '%s': %s\n"), filename? filename: "[stdin]",
                strerror(errno) );
      release_progress_context (pfx);
      return rc;
    }

  handle_progress (pfx, inp, filename);

  if (opt.textmode)
    iobuf_push_filter( inp, text_filter, &tfx );

  cfx.dek = NULL;
  if ( mode )
    {
      int canceled;

      s2k = xmalloc_clear( sizeof *s2k );
      s2k->mode = opt.s2k_mode;
      s2k->hash_algo = S2K_DIGEST_ALGO;
      cfx.dek = passphrase_to_dek (default_cipher_algo (), s2k, 1, 0,
                                   NULL, &canceled);
      if ( !cfx.dek || !cfx.dek->keylen )
        {
          rc = gpg_error (canceled? GPG_ERR_CANCELED:GPG_ERR_INV_PASSPHRASE);
          xfree (cfx.dek);
          xfree (s2k);
          iobuf_close (inp);
          log_error (_("error creating passphrase: %s\n"), gpg_strerror (rc));
          release_progress_context (pfx);
          return rc;
        }
      if (use_seskey && s2k->mode != 1 && s2k->mode != 3)
        {
          use_seskey = 0;
          log_info (_("can't use a symmetric ESK packet "
                      "due to the S2K mode\n"));
        }

      if ( use_seskey )
        {
          DEK *dek = NULL;

          seskeylen = openpgp_cipher_get_algo_keylen (default_cipher_algo ());
          encrypt_seskey( cfx.dek, &dek, enckey );
          xfree( cfx.dek ); cfx.dek = dek;
        }

      if (opt.verbose)
        log_info(_("using cipher %s\n"),
                 openpgp_cipher_algo_name (cfx.dek->algo));

      cfx.dek->use_mdc=use_mdc(NULL,cfx.dek->algo);
    }

  if (do_compress && cfx.dek && cfx.dek->use_mdc
      && is_file_compressed(filename, &rc))
    {
      if (opt.verbose)
        log_info(_("'%s' already compressed\n"), filename);
      do_compress = 0;
    }

  if ( rc || (rc = open_outfile (-1, filename, opt.armor? 1:0, 0, &out )))
    {
      iobuf_cancel (inp);
      xfree (cfx.dek);
      xfree (s2k);
      release_progress_context (pfx);
      return rc;
    }

  if ( opt.armor )
    {
      afx = new_armor_context ();
      push_armor_filter (afx, out);
    }

  if ( s2k )
    {
      PKT_symkey_enc *enc = xmalloc_clear( sizeof *enc + seskeylen + 1 );
      enc->version = 4;
      enc->cipher_algo = cfx.dek->algo;
      enc->s2k = *s2k;
      if ( use_seskey && seskeylen )
        {
          enc->seskeylen = seskeylen + 1; /* algo id */
          memcpy (enc->seskey, enckey, seskeylen + 1 );
        }
      pkt.pkttype = PKT_SYMKEY_ENC;
      pkt.pkt.symkey_enc = enc;
      if ((rc = build_packet( out, &pkt )))
        log_error("build symkey packet failed: %s\n", gpg_strerror (rc) );
      xfree (enc);
    }

  if (!opt.no_literal)
    pt = setup_plaintext_name (filename, inp);

  /* Note that PGP 5 has problems decrypting symmetrically encrypted
     data if the file length is in the inner packet. It works when
     only partial length headers are use.  In the past, we always used
     partial body length here, but since PGP 2, PGP 6, and PGP 7 need
     the file length, and nobody should be using PGP 5 nowadays
     anyway, this is now set to the file length.  Note also that this
     only applies to the RFC-1991 style symmetric messages, and not
     the RFC-2440 style.  PGP 6 and 7 work with either partial length
     or fixed length with the new style messages. */

  if ( !iobuf_is_pipe_filename (filename) && *filename && !opt.textmode )
    {
      off_t tmpsize;
      int overflow;

      if ( !(tmpsize = iobuf_get_filelength(inp, &overflow))
           && !overflow && opt.verbose)
        log_info(_("WARNING: '%s' is an empty file\n"), filename );
      /* We can't encode the length of very large files because
         OpenPGP uses only 32 bit for file sizes.  So if the
         size of a file is larger than 2^32 minus some bytes for
         packet headers, we switch to partial length encoding. */
      if ( tmpsize < (IOBUF_FILELENGTH_LIMIT - 65536) )
        filesize = tmpsize;
      else
        filesize = 0;
    }
  else
    filesize = opt.set_filesize ? opt.set_filesize : 0; /* stdin */

  if (!opt.no_literal)
    {
      /* Note that PT has been initialized above in !no_literal mode.  */
      pt->timestamp = make_timestamp();
      pt->mode = opt.mimemode? 'm' : opt.textmode? 't' : 'b';
      pt->len = filesize;
      pt->new_ctb = !pt->len;
      pt->buf = inp;
      pkt.pkttype = PKT_PLAINTEXT;
      pkt.pkt.plaintext = pt;
      cfx.datalen = filesize && !do_compress ? calc_packet_length( &pkt ) : 0;
    }
  else
    {
      cfx.datalen = filesize && !do_compress ? filesize : 0;
      pkt.pkttype = 0;
      pkt.pkt.generic = NULL;
    }

  /* Register the cipher filter. */
  if (mode)
    iobuf_push_filter ( out, cipher_filter, &cfx );

  /* Register the compress filter. */
  if ( do_compress )
    {
      if (cfx.dek && cfx.dek->use_mdc)
        zfx.new_ctb = 1;
      push_compress_filter (out, &zfx, default_compress_algo());
    }

  /* Do the work. */
  if (!opt.no_literal)
    {
      if ( (rc = build_packet( out, &pkt )) )
        log_error("build_packet failed: %s\n", gpg_strerror (rc) );
    }
  else
    {
      /* User requested not to create a literal packet, so we copy the
         plain data.  */
    byte copy_buffer[4096];
    int  bytes_copied;
    while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
      if ( (rc=iobuf_write(out, copy_buffer, bytes_copied)) ) {
        log_error ("copying input to output failed: %s\n",
                   gpg_strerror (rc) );
        break;
      }
    wipememory (copy_buffer, 4096); /* burn buffer */
    }

  /* Finish the stuff.  */
  iobuf_close (inp);
  if (rc)
    iobuf_cancel(out);
  else
    {
      iobuf_close (out); /* fixme: check returncode */
      if (mode)
        write_status ( STATUS_END_ENCRYPTION );
    }
  if (pt)
    pt->buf = NULL;
  free_packet (&pkt, NULL);
  xfree (cfx.dek);
  xfree (s2k);
  release_armor_context (afx);
  release_progress_context (pfx);
  return rc;
}


int
setup_symkey (STRING2KEY **symkey_s2k,DEK **symkey_dek)
{
  int canceled;

  *symkey_s2k=xmalloc_clear(sizeof(STRING2KEY));
  (*symkey_s2k)->mode = opt.s2k_mode;
  (*symkey_s2k)->hash_algo = S2K_DIGEST_ALGO;

  *symkey_dek = passphrase_to_dek (opt.s2k_cipher_algo,
                                   *symkey_s2k, 1, 0, NULL, &canceled);
  if(!*symkey_dek || !(*symkey_dek)->keylen)
    {
      xfree(*symkey_dek);
      xfree(*symkey_s2k);
      return gpg_error (canceled?GPG_ERR_CANCELED:GPG_ERR_BAD_PASSPHRASE);
    }

  return 0;
}


static int
write_symkey_enc (STRING2KEY *symkey_s2k, DEK *symkey_dek, DEK *dek,
                  iobuf_t out)
{
  int rc, seskeylen = openpgp_cipher_get_algo_keylen (dek->algo);

  PKT_symkey_enc *enc;
  byte enckey[33];
  PACKET pkt;

  enc=xmalloc_clear(sizeof(PKT_symkey_enc)+seskeylen+1);
  encrypt_seskey(symkey_dek,&dek,enckey);

  enc->version = 4;
  enc->cipher_algo = opt.s2k_cipher_algo;
  enc->s2k = *symkey_s2k;
  enc->seskeylen = seskeylen + 1; /* algo id */
  memcpy( enc->seskey, enckey, seskeylen + 1 );

  pkt.pkttype = PKT_SYMKEY_ENC;
  pkt.pkt.symkey_enc = enc;

  if ((rc=build_packet(out,&pkt)))
    log_error("build symkey_enc packet failed: %s\n",gpg_strerror (rc));

  xfree(enc);
  return rc;
}


/*
 * Encrypt the file with the given userids (or ask if none is
 * supplied).  Either FILENAME or FILEFD must be given, but not both.
 * The caller may provide a checked list of public keys in
 * PROVIDED_PKS; if not the function builds a list of keys on its own.
 *
 * Note that FILEFD is currently only used by cmd_encrypt in the
 * not yet finished server.c.
 */
int
encrypt_crypt (ctrl_t ctrl, int filefd, const char *filename,
               strlist_t remusr, int use_symkey, pk_list_t provided_keys,
               int outputfd)
{
  iobuf_t inp = NULL;
  iobuf_t out = NULL;
  PACKET pkt;
  PKT_plaintext *pt = NULL;
  DEK *symkey_dek = NULL;
  STRING2KEY *symkey_s2k = NULL;
  int rc = 0, rc2 = 0;
  u32 filesize;
  cipher_filter_context_t cfx;
  armor_filter_context_t *afx = NULL;
  compress_filter_context_t zfx;
  text_filter_context_t tfx;
  progress_filter_context_t *pfx;
  PK_LIST pk_list;
  int do_compress;

  if (filefd != -1 && filename)
    return gpg_error (GPG_ERR_INV_ARG);  /* Both given.  */

  do_compress = !!opt.compress_algo;

  pfx = new_progress_context ();
  memset( &cfx, 0, sizeof cfx);
  memset( &zfx, 0, sizeof zfx);
  memset( &tfx, 0, sizeof tfx);
  init_packet(&pkt);

  if (use_symkey
      && (rc=setup_symkey(&symkey_s2k,&symkey_dek)))
    {
      release_progress_context (pfx);
      return rc;
    }

  if (provided_keys)
    pk_list = provided_keys;
  else
    {
      if ((rc = build_pk_list (ctrl, remusr, &pk_list)))
        {
          release_progress_context (pfx);
          return rc;
        }
    }

  /* Prepare iobufs. */
#ifdef HAVE_W32_SYSTEM
  if (filefd == -1)
    inp = iobuf_open (filename);
  else
    {
      inp = NULL;
      gpg_err_set_errno (ENOSYS);
    }
#else
  if (filefd == GNUPG_INVALID_FD)
    inp = iobuf_open (filename);
  else
    inp = iobuf_fdopen_nc (FD2INT(filefd), "rb");
#endif
  if (inp)
    iobuf_ioctl (inp, IOBUF_IOCTL_NO_CACHE, 1, NULL);
  if (inp && is_secured_file (iobuf_get_fd (inp)))
    {
      iobuf_close (inp);
      inp = NULL;
      gpg_err_set_errno (EPERM);
    }
  if (!inp)
    {
      char xname[64];

      rc = gpg_error_from_syserror ();
      if (filefd != -1)
        snprintf (xname, sizeof xname, "[fd %d]", filefd);
      else if (!filename)
        strcpy (xname, "[stdin]");
      else
        *xname = 0;
      log_error (_("can't open '%s': %s\n"),
                 *xname? xname : filename, gpg_strerror (rc) );
      goto leave;
    }

  if (opt.verbose)
    log_info (_("reading from '%s'\n"), iobuf_get_fname_nonnull (inp));

  handle_progress (pfx, inp, filename);

  if (opt.textmode)
    iobuf_push_filter (inp, text_filter, &tfx);

  rc = open_outfile (outputfd, filename, opt.armor? 1:0, 0, &out);
  if (rc)
    goto leave;

  if (opt.armor)
    {
      afx = new_armor_context ();
      push_armor_filter (afx, out);
    }

  /* Create a session key. */
  cfx.dek = xmalloc_secure_clear (sizeof *cfx.dek);
  if (!opt.def_cipher_algo)
    {
      /* Try to get it from the prefs.  */
      cfx.dek->algo = select_algo_from_prefs (pk_list, PREFTYPE_SYM, -1, NULL);
      /* The only way select_algo_from_prefs can fail here is when
         mixing v3 and v4 keys, as v4 keys have an implicit preference
         entry for 3DES, and the pk_list cannot be empty.  In this
         case, use 3DES anyway as it's the safest choice - perhaps the
         v3 key is being used in an OpenPGP implementation and we know
         that the implementation behind any v4 key can handle 3DES. */
      if (cfx.dek->algo == -1)
        {
          cfx.dek->algo = CIPHER_ALGO_3DES;
        }

      /* In case 3DES has been selected, print a warning if any key
         does not have a preference for AES.  This should help to
         indentify why encrypting to several recipients falls back to
         3DES. */
      if (opt.verbose && cfx.dek->algo == CIPHER_ALGO_3DES)
        warn_missing_aes_from_pklist (pk_list);
    }
  else
    {
      if (!opt.expert
          && (select_algo_from_prefs (pk_list, PREFTYPE_SYM,
                                      opt.def_cipher_algo, NULL)
              != opt.def_cipher_algo))
        {
          log_info(_("WARNING: forcing symmetric cipher %s (%d)"
                     " violates recipient preferences\n"),
                   openpgp_cipher_algo_name (opt.def_cipher_algo),
                   opt.def_cipher_algo);
        }

      cfx.dek->algo = opt.def_cipher_algo;
    }

  cfx.dek->use_mdc = use_mdc (pk_list,cfx.dek->algo);

  /* Only do the is-file-already-compressed check if we are using a
     MDC.  This forces compressed files to be re-compressed if we do
     not have a MDC to give some protection against chosen ciphertext
     attacks. */

  if (do_compress && cfx.dek->use_mdc && is_file_compressed(filename, &rc2))
    {
      if (opt.verbose)
        log_info(_("'%s' already compressed\n"), filename);
      do_compress = 0;
    }
  if (rc2)
    {
      rc = rc2;
      goto leave;
    }

  make_session_key (cfx.dek);
  if (DBG_CRYPTO)
    log_printhex ("DEK is: ", cfx.dek->key, cfx.dek->keylen );

  rc = write_pubkey_enc_from_list (ctrl, pk_list, cfx.dek, out);
  if (rc)
    goto leave;

  /* We put the passphrase (if any) after any public keys as this
     seems to be the most useful on the recipient side - there is no
     point in prompting a user for a passphrase if they have the
     secret key needed to decrypt.  */
  if(use_symkey && (rc = write_symkey_enc(symkey_s2k,symkey_dek,cfx.dek,out)))
    goto leave;

  if (!opt.no_literal)
    pt = setup_plaintext_name (filename, inp);

  /* Get the size of the file if possible, i.e., if it is a real file.  */
  if (filename && *filename
      && !iobuf_is_pipe_filename (filename) && !opt.textmode )
    {
      off_t tmpsize;
      int overflow;

      if ( !(tmpsize = iobuf_get_filelength(inp, &overflow))
           && !overflow && opt.verbose)
        log_info(_("WARNING: '%s' is an empty file\n"), filename );
      /* We can't encode the length of very large files because
         OpenPGP uses only 32 bit for file sizes.  So if the size
         of a file is larger than 2^32 minus some bytes for packet
         headers, we switch to partial length encoding. */
      if (tmpsize < (IOBUF_FILELENGTH_LIMIT - 65536) )
        filesize = tmpsize;
      else
        filesize = 0;
    }
  else
    filesize = opt.set_filesize ? opt.set_filesize : 0; /* stdin */

  if (!opt.no_literal)
    {
      pt->timestamp = make_timestamp();
      pt->mode = opt.mimemode? 'm' : opt.textmode ? 't' : 'b';
      pt->len = filesize;
      pt->new_ctb = !pt->len;
      pt->buf = inp;
      pkt.pkttype = PKT_PLAINTEXT;
      pkt.pkt.plaintext = pt;
      cfx.datalen = filesize && !do_compress? calc_packet_length( &pkt ) : 0;
    }
  else
    cfx.datalen = filesize && !do_compress ? filesize : 0;

  /* Register the cipher filter. */
  iobuf_push_filter (out, cipher_filter, &cfx);

  /* Register the compress filter. */
  if (do_compress)
    {
      int compr_algo = opt.compress_algo;

      if (compr_algo == -1)
        {
          compr_algo = select_algo_from_prefs (pk_list, PREFTYPE_ZIP, -1, NULL);
          if (compr_algo == -1)
            compr_algo = DEFAULT_COMPRESS_ALGO;
          /* Theoretically impossible to get here since uncompressed
             is implicit.  */
        }
      else if (!opt.expert
               && select_algo_from_prefs(pk_list, PREFTYPE_ZIP,
                                         compr_algo, NULL) != compr_algo)
        {
          log_info (_("WARNING: forcing compression algorithm %s (%d)"
                      " violates recipient preferences\n"),
                    compress_algo_to_string(compr_algo), compr_algo);
        }

      /* Algo 0 means no compression. */
      if (compr_algo)
        {
          if (cfx.dek && cfx.dek->use_mdc)
            zfx.new_ctb = 1;
          push_compress_filter (out,&zfx,compr_algo);
        }
    }

  /* Do the work. */
  if (!opt.no_literal)
    {
      if ((rc = build_packet( out, &pkt )))
        log_error ("build_packet failed: %s\n", gpg_strerror (rc));
    }
  else
    {
      /* User requested not to create a literal packet, so we copy the
         plain data. */
      byte copy_buffer[4096];
      int  bytes_copied;
      while ((bytes_copied = iobuf_read (inp, copy_buffer, 4096)) != -1)
        {
          rc = iobuf_write (out, copy_buffer, bytes_copied);
          if (rc)
            {
              log_error ("copying input to output failed: %s\n",
                         gpg_strerror (rc));
              break;
            }
        }
      wipememory (copy_buffer, 4096); /* Burn the buffer. */
    }

  /* Finish the stuff. */
 leave:
  iobuf_close (inp);
  if (rc)
    iobuf_cancel (out);
  else
    {
      iobuf_close (out); /* fixme: check returncode */
      write_status (STATUS_END_ENCRYPTION);
    }
  if (pt)
    pt->buf = NULL;
  free_packet (&pkt, NULL);
  xfree (cfx.dek);
  xfree (symkey_dek);
  xfree (symkey_s2k);
  if (!provided_keys)
    release_pk_list (pk_list);
  release_armor_context (afx);
  release_progress_context (pfx);
  return rc;
}


/*
 * Filter to do a complete public key encryption.
 */
int
encrypt_filter (void *opaque, int control,
                iobuf_t a, byte *buf, size_t *ret_len)
{
  size_t size = *ret_len;
  encrypt_filter_context_t *efx = opaque;
  int rc = 0;

  if (control == IOBUFCTRL_UNDERFLOW) /* decrypt */
    {
      BUG(); /* not used */
    }
  else if ( control == IOBUFCTRL_FLUSH ) /* encrypt */
    {
      if ( !efx->header_okay )
        {
          efx->cfx.dek = xmalloc_secure_clear ( sizeof *efx->cfx.dek );
          if ( !opt.def_cipher_algo  )
            {
              /* Try to get it from the prefs. */
              efx->cfx.dek->algo =
                select_algo_from_prefs (efx->pk_list, PREFTYPE_SYM, -1, NULL);
              if (efx->cfx.dek->algo == -1 )
                {
                  /* Because 3DES is implicitly in the prefs, this can
                     only happen if we do not have any public keys in
                     the list.  */
                  efx->cfx.dek->algo = DEFAULT_CIPHER_ALGO;
                }

              /* In case 3DES has been selected, print a warning if
                 any key does not have a preference for AES.  This
                 should help to indentify why encrypting to several
                 recipients falls back to 3DES. */
              if (opt.verbose
                  && efx->cfx.dek->algo == CIPHER_ALGO_3DES)
                warn_missing_aes_from_pklist (efx->pk_list);
	    }
          else
            {
	      if (!opt.expert
                  && select_algo_from_prefs (efx->pk_list,PREFTYPE_SYM,
                                             opt.def_cipher_algo,
                                             NULL) != opt.def_cipher_algo)
		log_info(_("forcing symmetric cipher %s (%d) "
			   "violates recipient preferences\n"),
			 openpgp_cipher_algo_name (opt.def_cipher_algo),
			 opt.def_cipher_algo);

	      efx->cfx.dek->algo = opt.def_cipher_algo;
	    }

          efx->cfx.dek->use_mdc = use_mdc (efx->pk_list,efx->cfx.dek->algo);

          make_session_key ( efx->cfx.dek );
          if (DBG_CRYPTO)
            log_printhex ("DEK is: ", efx->cfx.dek->key, efx->cfx.dek->keylen);

          rc = write_pubkey_enc_from_list (efx->ctrl,
                                           efx->pk_list, efx->cfx.dek, a);
          if (rc)
            return rc;

          if(efx->symkey_s2k && efx->symkey_dek)
            {
              rc=write_symkey_enc(efx->symkey_s2k,efx->symkey_dek,
                                  efx->cfx.dek,a);
              if(rc)
                return rc;
            }

          iobuf_push_filter (a, cipher_filter, &efx->cfx);

          efx->header_okay = 1;
        }
      rc = iobuf_write (a, buf, size);

    }
  else if (control == IOBUFCTRL_FREE)
    {
      xfree (efx->symkey_dek);
      xfree (efx->symkey_s2k);
    }
  else if ( control == IOBUFCTRL_DESC )
    {
      mem2str (buf, "encrypt_filter", *ret_len);
    }
  return rc;
}


/*
 * Write a pubkey-enc packet for the public key PK to OUT.
 */
int
write_pubkey_enc (ctrl_t ctrl,
                  PKT_public_key *pk, int throw_keyid, DEK *dek, iobuf_t out)
{
  PACKET pkt;
  PKT_pubkey_enc *enc;
  int rc;
  gcry_mpi_t frame;

  print_pubkey_algo_note ( pk->pubkey_algo );
  enc = xmalloc_clear ( sizeof *enc );
  enc->pubkey_algo = pk->pubkey_algo;
  keyid_from_pk( pk, enc->keyid );
  enc->throw_keyid = throw_keyid;

  /* Okay, what's going on: We have the session key somewhere in
   * the structure DEK and want to encode this session key in an
   * integer value of n bits. pubkey_nbits gives us the number of
   * bits we have to use.  We then encode the session key in some
   * way and we get it back in the big intger value FRAME.  Then
   * we use FRAME, the public key PK->PKEY and the algorithm
   * number PK->PUBKEY_ALGO and pass it to pubkey_encrypt which
   * returns the encrypted value in the array ENC->DATA.  This
   * array has a size which depends on the used algorithm (e.g. 2
   * for Elgamal).  We don't need frame anymore because we have
   * everything now in enc->data which is the passed to
   * build_packet().  */
  frame = encode_session_key (pk->pubkey_algo, dek,
                              pubkey_nbits (pk->pubkey_algo, pk->pkey));
  rc = pk_encrypt (pk->pubkey_algo, enc->data, frame, pk, pk->pkey);
  gcry_mpi_release (frame);
  if (rc)
    log_error ("pubkey_encrypt failed: %s\n", gpg_strerror (rc) );
  else
    {
      if ( opt.verbose )
        {
          char *ustr = get_user_id_string_native (ctrl, enc->keyid);
          log_info (_("%s/%s encrypted for: \"%s\"\n"),
                    openpgp_pk_algo_name (enc->pubkey_algo),
                    openpgp_cipher_algo_name (dek->algo),
                    ustr );
          xfree (ustr);
        }
      /* And write it. */
      init_packet (&pkt);
      pkt.pkttype = PKT_PUBKEY_ENC;
      pkt.pkt.pubkey_enc = enc;
      rc = build_packet (out, &pkt);
      if (rc)
        log_error ("build_packet(pubkey_enc) failed: %s\n",
                   gpg_strerror (rc));
    }
  free_pubkey_enc(enc);
  return rc;
}


/*
 * Write pubkey-enc packets from the list of PKs to OUT.
 */
static int
write_pubkey_enc_from_list (ctrl_t ctrl, PK_LIST pk_list, DEK *dek, iobuf_t out)
{
  if (opt.throw_keyids && (PGP6 || PGP7 || PGP8))
    {
      log_info(_("you may not use %s while in %s mode\n"),
               "--throw-keyids",compliance_option_string());
      compliance_failure();
    }

  for ( ; pk_list; pk_list = pk_list->next )
    {
      PKT_public_key *pk = pk_list->pk;
      int throw_keyid = (opt.throw_keyids || (pk_list->flags&1));
      int rc = write_pubkey_enc (ctrl, pk, throw_keyid, dek, out);
      if (rc)
        return rc;
    }

  return 0;
}

void
encrypt_crypt_files (ctrl_t ctrl, int nfiles, char **files, strlist_t remusr)
{
  int rc = 0;

  if (opt.outfile)
    {
      log_error(_("--output doesn't work for this command\n"));
      return;
    }

  if (!nfiles)
    {
      char line[2048];
      unsigned int lno = 0;
      while ( fgets(line, DIM(line), stdin) )
        {
          lno++;
          if (!*line || line[strlen(line)-1] != '\n')
            {
              log_error("input line %u too long or missing LF\n", lno);
              return;
            }
          line[strlen(line)-1] = '\0';
          print_file_status(STATUS_FILE_START, line, 2);
          rc = encrypt_crypt (ctrl, -1, line, remusr, 0, NULL, -1);
          if (rc)
            log_error ("encryption of '%s' failed: %s\n",
                       print_fname_stdin(line), gpg_strerror (rc) );
          write_status( STATUS_FILE_DONE );
        }
    }
  else
    {
      while (nfiles--)
        {
          print_file_status(STATUS_FILE_START, *files, 2);
          if ( (rc = encrypt_crypt (ctrl, -1, *files, remusr, 0, NULL, -1)) )
            log_error("encryption of '%s' failed: %s\n",
                      print_fname_stdin(*files), gpg_strerror (rc) );
          write_status( STATUS_FILE_DONE );
          files++;
        }
    }
}
