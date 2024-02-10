/* mainproc.c - handle packets
 * Copyright (C) 1998-2009 Free Software Foundation, Inc.
 * Copyright (C) 2013-2014 Werner Koch
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/iobuf.h"
#include "options.h"
#include "keydb.h"
#include "filter.h"
#include "main.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "trustdb.h"
#include "keyserver-internal.h"
#include "photoid.h"
#include "../common/mbox-util.h"
#include "call-dirmngr.h"
#include "../common/compliance.h"

/* Put an upper limit on nested packets.  The 32 is an arbitrary
   value, a much lower should actually be sufficient.  */
#define MAX_NESTING_DEPTH 32


/* An object to build a list of symkey packet info.  */
struct symlist_item
{
  struct symlist_item *next;
  int cipher_algo;
  int cfb_mode;
  int other_error;
};


/*
 * Object to hold the processing context.
 */
typedef struct mainproc_context *CTX;
struct mainproc_context
{
  ctrl_t ctrl;
  struct mainproc_context *anchor;  /* May be useful in the future. */
  PKT_public_key *last_pubkey;
  PKT_user_id     *last_user_id;
  md_filter_context_t mfx;
  int sigs_only;    /* Process only signatures and reject all other stuff. */
  int encrypt_only; /* Process only encryption messages. */

  /* Name of the file with the complete signature or the file with the
     detached signature.  This is currently only used to deduce the
     file name of the data file if that has not been given. */
  const char *sigfilename;

  /* A structure to describe the signed data in case of a detached
     signature. */
  struct
  {
    /* A file descriptor of the signed data.  Only used if not -1. */
    int data_fd;
    /* A list of filenames with the data files or NULL. This is only
       used if DATA_FD is -1. */
    strlist_t data_names;
    /* Flag to indicated that either one of the next previous fields
       is used.  This is only needed for better readability. */
    int used;
  } signed_data;

  DEK *dek;
  int last_was_session_key;
  kbnode_t list;    /* The current list of packets. */
  iobuf_t iobuf;    /* Used to get the filename etc. */
  int trustletter;  /* Temporary usage in list_node. */
  ulong symkeys;    /* Number of symmetrically encrypted session keys.  */
  struct pubkey_enc_list *pkenc_list; /* List of encryption packets. */
  struct symlist_item *symenc_list;   /* List of sym. encryption packets. */
  int seen_pkt_encrypted_aead; /* PKT_ENCRYPTED_AEAD packet seen. */
  int seen_pkt_encrypted_mdc;  /* PKT_ENCRYPTED_MDC packet seen. */
  struct {
    unsigned int sig_seen:1;      /* Set to true if a signature packet
                                     has been seen. */
    unsigned int data:1;          /* Any data packet seen */
    unsigned int uncompress_failed:1;
  } any;
};


/* Counter with the number of literal data packets seen.  Note that
 * this is also bumped at the end of an encryption.  This counter is
 * used for a basic consistency check of a received PGP message.  */
static int literals_seen;


/*** Local prototypes.  ***/
static int do_proc_packets (CTX c, iobuf_t a);
static void list_node (CTX c, kbnode_t node);
static void proc_tree (CTX c, kbnode_t node);


/*** Functions.  ***/

/* Reset the literal data counter.  This is required to setup a new
 * decryption or verification context.  */
void
reset_literals_seen(void)
{
  literals_seen = 0;
}


static void
release_list( CTX c )
{
  proc_tree (c, c->list);
  release_kbnode (c->list);
  while (c->pkenc_list)
    {
      struct pubkey_enc_list *tmp = c->pkenc_list->next;

      mpi_release (c->pkenc_list->data[0]);
      mpi_release (c->pkenc_list->data[1]);
      xfree (c->pkenc_list);
      c->pkenc_list = tmp;
    }
  c->pkenc_list = NULL;
  while (c->symenc_list)
    {
      struct symlist_item *tmp = c->symenc_list->next;
      xfree (c->symenc_list);
      c->symenc_list = tmp;
    }
  c->symenc_list = NULL;
  c->list = NULL;
  c->any.data = 0;
  c->any.uncompress_failed = 0;
  c->last_was_session_key = 0;
  c->seen_pkt_encrypted_aead = 0;
  c->seen_pkt_encrypted_mdc = 0;
  xfree (c->dek);
  c->dek = NULL;
}


static int
add_onepass_sig (CTX c, PACKET *pkt)
{
  kbnode_t node;

  if (c->list) /* Add another packet. */
    add_kbnode (c->list, new_kbnode (pkt));
  else /* Insert the first one.  */
    c->list = node = new_kbnode (pkt);

  return 1;
}


static int
add_gpg_control (CTX c, PACKET *pkt)
{
  if ( pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START )
    {
      /* New clear text signature.
       * Process the last one and reset everything */
      release_list(c);
    }

  if (c->list)  /* Add another packet.  */
    add_kbnode (c->list, new_kbnode (pkt));
  else /* Insert the first one. */
    c->list = new_kbnode (pkt);

  return 1;
}


static int
add_user_id (CTX c, PACKET *pkt)
{
  if (!c->list)
    {
      log_error ("orphaned user ID\n");
      return 0;
    }
  add_kbnode (c->list, new_kbnode (pkt));
  return 1;
}


static int
add_subkey (CTX c, PACKET *pkt)
{
  if (!c->list)
    {
      log_error ("subkey w/o mainkey\n");
      return 0;
    }
  add_kbnode (c->list, new_kbnode (pkt));
  return 1;
}


static int
add_ring_trust (CTX c, PACKET *pkt)
{
  if (!c->list)
    {
      log_error ("ring trust w/o key\n");
      return 0;
    }
  add_kbnode (c->list, new_kbnode (pkt));
  return 1;
}


static int
add_signature (CTX c, PACKET *pkt)
{
  kbnode_t node;

  c->any.sig_seen = 1;
  if (pkt->pkttype == PKT_SIGNATURE && !c->list)
    {
      /* This is the first signature for the following datafile.
       * GPG does not write such packets; instead it always uses
       * onepass-sig packets.  The drawback of PGP's method
       * of prepending the signature to the data is
       * that it is not possible to make a signature from data read
       * from stdin.	(GPG is able to read PGP stuff anyway.) */
      node = new_kbnode (pkt);
      c->list = node;
      return 1;
    }
  else if (!c->list)
    return 0; /* oops (invalid packet sequence)*/
  else if (!c->list->pkt)
    BUG();    /* so nicht */

  /* Add a new signature node item at the end. */
  node = new_kbnode (pkt);
  add_kbnode (c->list, node);

  return 1;
}

static gpg_error_t
symkey_decrypt_seskey (DEK *dek, byte *seskey, size_t slen)
{
  gpg_error_t err;
  gcry_cipher_hd_t hd;
  unsigned int noncelen, keylen;
  enum gcry_cipher_modes ciphermode;

  if (dek->use_aead)
    {
      err = openpgp_aead_algo_info (dek->use_aead, &ciphermode, &noncelen);
      if (err)
        return err;
    }
  else
    {
      ciphermode = GCRY_CIPHER_MODE_CFB;
      noncelen = 0;
    }

  /* Check that the session key has a size of 16 to 32 bytes.  */
  if ((dek->use_aead && (slen < (noncelen + 16 + 16)
                         || slen > (noncelen + 32 + 16)))
      || (!dek->use_aead && (slen < 17 || slen > 33)))
    {
      log_error ( _("weird size for an encrypted session key (%d)\n"),
		  (int)slen);
      return gpg_error (GPG_ERR_BAD_KEY);
    }

  err = openpgp_cipher_open (&hd, dek->algo, ciphermode, GCRY_CIPHER_SECURE);
  if (!err)
    err = gcry_cipher_setkey (hd, dek->key, dek->keylen);
  if (!err)
    err = gcry_cipher_setiv (hd, noncelen? seskey : NULL, noncelen);
  if (err)
    goto leave;

  if (dek->use_aead)
    {
      byte ad[4];

      ad[0] = (0xc0 | PKT_SYMKEY_ENC);
      ad[1] = 5;
      ad[2] = dek->algo;
      ad[3] = dek->use_aead;
      err = gcry_cipher_authenticate (hd, ad, 4);
      if (err)
        goto leave;
      gcry_cipher_final (hd);
      keylen = slen - noncelen - 16;
      err = gcry_cipher_decrypt (hd, seskey+noncelen, keylen, NULL, 0);
      if (err)
        goto leave;
      err = gcry_cipher_checktag (hd, seskey+noncelen+keylen, 16);
      if (err)
        goto leave;
      /* Now we replace the dek components with the real session key to
       * decrypt the contents of the sequencing packet. */
      if (keylen > DIM(dek->key))
        {
          err = gpg_error (GPG_ERR_TOO_LARGE);
          goto leave;
        }
      dek->keylen = keylen;
      memcpy (dek->key, seskey + noncelen, dek->keylen);
    }
  else
    {
      gcry_cipher_decrypt (hd, seskey, slen, NULL, 0 );
      /* Here we can only test whether the algo given in decrypted
       * session key is a valid OpenPGP algo.  With 11 defined
       * symmetric algorithms we will miss 4.3% of wrong passphrases
       * here.  The actual checking is done later during bulk
       * decryption; we can't bring this check forward easily.  We
       * need to use the GPG_ERR_CHECKSUM so that we won't run into
       * the gnupg < 2.2 bug compatible case which would terminate the
       * process on GPG_ERR_CIPHER_ALGO.  Note that with AEAD (above)
       * we will have a reliable test here.  */
      if (openpgp_cipher_test_algo (seskey[0])
          || openpgp_cipher_get_algo_keylen (seskey[0]) != slen - 1)
        {
          err = gpg_error (GPG_ERR_CHECKSUM);
          goto leave;
        }

      /* Now we replace the dek components with the real session key to
       * decrypt the contents of the sequencing packet. */
      keylen = slen-1;
      if (keylen > DIM(dek->key))
        {
          err = gpg_error (GPG_ERR_TOO_LARGE);
          goto leave;
        }
      dek->algo = seskey[0];
      dek->keylen = keylen;
      memcpy (dek->key, seskey + 1, dek->keylen);
    }

  /*log_hexdump( "thekey", dek->key, dek->keylen );*/

 leave:
  gcry_cipher_close (hd);
  return err;
}


static void
proc_symkey_enc (CTX c, PACKET *pkt)
{
  gpg_error_t err;
  PKT_symkey_enc *enc;

  enc = pkt->pkt.symkey_enc;
  if (!enc)
    log_error ("invalid symkey encrypted packet\n");
  else if(!c->dek)
    {
      int algo = enc->cipher_algo;
      const char *s = openpgp_cipher_algo_name (algo);
      const char *a = (enc->aead_algo ? openpgp_aead_algo_name (enc->aead_algo)
                       /**/           : "CFB");

      if (!openpgp_cipher_test_algo (algo))
        {
          if (!opt.quiet)
            {
              if (enc->seskeylen)
                log_info (_("%s.%s encrypted session key\n"), s, a );
              else
                log_info (_("%s.%s encrypted data\n"), s, a );
            }
        }
      else
        {
          log_error (_("encrypted with unknown algorithm %d.%s\n"), algo, a);
          s = NULL; /* Force a goto leave.  */
        }

      if (openpgp_md_test_algo (enc->s2k.hash_algo))
        {
          log_error(_("passphrase generated with unknown digest"
                      " algorithm %d\n"),enc->s2k.hash_algo);
          s = NULL;
        }

      c->last_was_session_key = 2;
      if (!s || opt.list_only)
        goto leave;

      if (opt.override_session_key)
        {
          c->dek = xmalloc_clear (sizeof *c->dek);
          if (get_override_session_key (c->dek, opt.override_session_key))
            {
              xfree (c->dek);
              c->dek = NULL;
            }
        }
      else
        {
          c->dek = passphrase_to_dek (algo, &enc->s2k, 0, 0, NULL,
                                      GETPASSWORD_FLAG_SYMDECRYPT, NULL);
          if (c->dek)
            {
              c->dek->symmetric = 1;
              c->dek->use_aead = enc->aead_algo;

              /* FIXME: This doesn't work perfectly if a symmetric key
                 comes before a public key in the message - if the
                 user doesn't know the passphrase, then there is a
                 chance that the "decrypted" algorithm will happen to
                 be a valid one, which will make the returned dek
                 appear valid, so we won't try any public keys that
                 come later. */
              if (enc->seskeylen)
                {
                  err = symkey_decrypt_seskey (c->dek,
                                               enc->seskey, enc->seskeylen);
                  if (err)
                    {
                      log_info ("decryption of the symmetrically encrypted"
                                 " session key failed: %s\n",
                                 gpg_strerror (err));
                      if (gpg_err_code (err) != GPG_ERR_BAD_KEY
                          && gpg_err_code (err) != GPG_ERR_CHECKSUM)
                        log_fatal ("process terminated to be bug compatible"
                                   " with GnuPG <= 2.2\n");
                      else
                        write_status_text (STATUS_ERROR,
                                           "symkey_decrypt.maybe_error"
                                           " 11_BAD_PASSPHRASE");

                      if (c->dek->s2k_cacheid[0])
                        {
                          if (opt.debug)
                            log_debug ("cleared passphrase cached with ID:"
                                       " %s\n", c->dek->s2k_cacheid);
                          passphrase_clear_cache (c->dek->s2k_cacheid);
                        }
                      xfree (c->dek);
                      c->dek = NULL;
                    }
                }
              else
                c->dek->algo_info_printed = 1;
            }
        }
    }

 leave:
  /* Record infos from the packet.  */
  {
    struct symlist_item  *symitem;
    symitem = xcalloc (1, sizeof *symitem);
    if (enc)
      {
        symitem->cipher_algo = enc->cipher_algo;
        symitem->cfb_mode = !enc->aead_algo;
      }
    else
      symitem->other_error = 1;
    symitem->next = c->symenc_list;
    c->symenc_list = symitem;
  }
  c->symkeys++;
  free_packet (pkt, NULL);
}


static void
proc_pubkey_enc (CTX c, PACKET *pkt)
{
  PKT_pubkey_enc *enc;

  /* Check whether the secret key is available and store in this case.  */
  c->last_was_session_key = 1;
  enc = pkt->pkt.pubkey_enc;
  /*printf("enc: encrypted by a pubkey with keyid %08lX\n", enc->keyid[1] );*/
  /* Hmmm: why do I have this algo check here - anyway there is
   * function to check it. */
  if (opt.verbose)
    log_info (_("public key is %s\n"), keystr (enc->keyid));

  if (is_status_enabled ())
    {
      char buf[50];
      snprintf (buf, sizeof buf, "%08lX%08lX %d 0",
                (ulong)enc->keyid[0], (ulong)enc->keyid[1], enc->pubkey_algo);
      write_status_text (STATUS_ENC_TO, buf);
    }

  if (!opt.list_only && !opt.override_session_key)
    {
      struct pubkey_enc_list *x = xmalloc (sizeof *x);

      x->keyid[0] = enc->keyid[0];
      x->keyid[1] = enc->keyid[1];
      x->pubkey_algo = enc->pubkey_algo;
      x->result = -1;
      x->data[0] = x->data[1] = NULL;
      if (enc->data[0])
        {
          x->data[0] = mpi_copy (enc->data[0]);
          x->data[1] = mpi_copy (enc->data[1]);
        }
      x->next = c->pkenc_list;
      c->pkenc_list = x;
    }

  free_packet(pkt, NULL);
}


/*
 * Print the list of public key encrypted packets which we could
 * not decrypt.
 */
static void
print_pkenc_list (ctrl_t ctrl, struct pubkey_enc_list *list)
{
  for (; list; list = list->next)
    {
      PKT_public_key *pk;
      char pkstrbuf[PUBKEY_STRING_SIZE];
      char *p;

      pk = xmalloc_clear (sizeof *pk);

      pk->pubkey_algo = list->pubkey_algo;
      if (!get_pubkey (ctrl, pk, list->keyid))
        {
          pubkey_string (pk, pkstrbuf, sizeof pkstrbuf);

          log_info (_("encrypted with %s key, ID %s, created %s\n"),
                    pkstrbuf, keystr_from_pk (pk),
                    strtimestamp (pk->timestamp));
          p = get_user_id_native (ctrl, list->keyid);
          log_printf (_("      \"%s\"\n"), p);
          xfree (p);
        }
      else
        log_info (_("encrypted with %s key, ID %s\n"),
                  openpgp_pk_algo_name (list->pubkey_algo),
                  keystr(list->keyid));

      free_public_key (pk);
    }
}


static void
proc_encrypted (CTX c, PACKET *pkt)
{
  int result = 0;
  int early_plaintext = literals_seen;
  unsigned int compliance_de_vs = 0;

  if (pkt->pkttype == PKT_ENCRYPTED_AEAD)
    c->seen_pkt_encrypted_aead = 1;
  if (pkt->pkttype == PKT_ENCRYPTED_MDC)
    c->seen_pkt_encrypted_mdc = 1;

  if (early_plaintext)
    {
      log_info (_("WARNING: multiple plaintexts seen\n"));
      write_status_errcode ("decryption.early_plaintext", GPG_ERR_BAD_DATA);
      /* We fail only later so that we can print some more info first.  */
    }

  if (!opt.quiet)
    {
      if (c->symkeys>1)
        log_info (_("encrypted with %lu passphrases\n"), c->symkeys);
      else if (c->symkeys == 1)
        log_info (_("encrypted with 1 passphrase\n"));
      print_pkenc_list (c->ctrl, c->pkenc_list);
    }

  /* Figure out the session key by looking at all pkenc packets. */
  if (opt.list_only || c->dek)
    ;
  else if (opt.override_session_key)
    {
      c->dek = xmalloc_clear (sizeof *c->dek);
      result = get_override_session_key (c->dek, opt.override_session_key);
      if (result)
        {
          xfree (c->dek);
          c->dek = NULL;
          log_info (_("public key decryption failed: %s\n"),
                    gpg_strerror (result));
          write_status_error ("pkdecrypt_failed", result);
        }
    }
  else if (c->pkenc_list)
    {
      c->dek = xmalloc_secure_clear (sizeof *c->dek);
      result = get_session_key (c->ctrl, c->pkenc_list, c->dek);
      if (is_status_enabled ())
        {
          struct pubkey_enc_list *list;

          for (list = c->pkenc_list; list; list = list->next)
            if (list->result)
              { /* Key was not tried or it caused an error.  */
                char buf[20];
                snprintf (buf, sizeof buf, "%08lX%08lX",
                          (ulong)list->keyid[0], (ulong)list->keyid[1]);
                write_status_text (STATUS_NO_SECKEY, buf);
              }
        }

      if (result)
        {
          log_info (_("public key decryption failed: %s\n"),
                    gpg_strerror (result));
          write_status_error ("pkdecrypt_failed", result);

          /* Error: Delete the DEK. */
          xfree (c->dek);
          c->dek = NULL;
        }
    }

  if (c->dek && opt.verbose > 1)
    log_info (_("public key encrypted data: good DEK\n"));

  write_status (STATUS_BEGIN_DECRYPTION);

  /*log_debug("dat: %sencrypted data\n", c->dek?"":"conventional ");*/
  if (opt.list_only)
    result = -1;
  else if (!c->dek && !c->last_was_session_key)
    {
      int algo;
      STRING2KEY s2kbuf;
      STRING2KEY *s2k = NULL;
      int canceled;

      if (opt.override_session_key)
        {
          c->dek = xmalloc_clear (sizeof *c->dek);
          result = get_override_session_key (c->dek, opt.override_session_key);
          if (result)
            {
              xfree (c->dek);
              c->dek = NULL;
            }
        }
      else
        {
          /* Assume this is old style conventional encrypted data. */
          algo = opt.def_cipher_algo;
          if (algo)
            log_info (_("assuming %s encrypted data\n"),
                      openpgp_cipher_algo_name (algo));
          else if (openpgp_cipher_test_algo (CIPHER_ALGO_IDEA))
            {
              algo = opt.def_cipher_algo;
              if (!algo)
                algo = opt.s2k_cipher_algo;
              log_info (_("IDEA cipher unavailable, "
                          "optimistically attempting to use %s instead\n"),
                        openpgp_cipher_algo_name (algo));
            }
          else
            {
              algo = CIPHER_ALGO_IDEA;
              if (!opt.s2k_digest_algo)
                {
                  /* If no digest is given we assume SHA-1. */
                  s2kbuf.mode = 0;
                  s2kbuf.hash_algo = DIGEST_ALGO_SHA1;
                  s2k = &s2kbuf;
                }
              log_info (_("assuming %s encrypted data\n"), "IDEA");
            }

          c->dek = passphrase_to_dek (algo, s2k, 0, 0, NULL,
                                      GETPASSWORD_FLAG_SYMDECRYPT, &canceled);
          if (c->dek)
            c->dek->algo_info_printed = 1;
          else if (canceled)
            result = gpg_error (GPG_ERR_CANCELED);
          else
            result = gpg_error (GPG_ERR_INV_PASSPHRASE);
        }
    }
  else if (!c->dek)
    {
      if (c->symkeys && !c->pkenc_list)
        result = gpg_error (GPG_ERR_BAD_KEY);

      if (!result)
        result = gpg_error (GPG_ERR_NO_SECKEY);
    }

  /* Compute compliance with CO_DE_VS.  */
  if (!result && (is_status_enabled () || opt.flags.require_compliance)
      /* Overriding session key voids compliance.  */
      && !opt.override_session_key
      /* Check symmetric cipher.  */
      && gnupg_gcrypt_is_compliant (CO_DE_VS)
      && gnupg_cipher_is_compliant (CO_DE_VS, c->dek->algo,
                                    GCRY_CIPHER_MODE_CFB))
    {
      struct pubkey_enc_list *i;
      struct symlist_item *si;
      int compliant = 1;
      PKT_public_key *pk = xmalloc (sizeof *pk);

      if ( !(c->pkenc_list || c->symkeys) )
        log_debug ("%s: where else did the session key come from?\n", __func__);

      /* Check that all seen symmetric key packets use compliant
       * algos.  This is so that no non-compliant encrypted session
       * key can be sneaked in.  */
      for (si = c->symenc_list; si && compliant; si = si->next)
        {
          if (!si->cfb_mode
              || !gnupg_cipher_is_compliant (CO_DE_VS, si->cipher_algo,
                                             GCRY_CIPHER_MODE_CFB))
            compliant = 0;
        }

      /* Check that every known public key used to encrypt the session key
       * is compliant.  */
      for (i = c->pkenc_list; i && compliant; i = i->next)
        {
          memset (pk, 0, sizeof *pk);
          pk->pubkey_algo = i->pubkey_algo;
          if (!get_pubkey (c->ctrl, pk, i->keyid)
              && !gnupg_pk_is_compliant (CO_DE_VS, pk->pubkey_algo, 0,
                                         pk->pkey, nbits_from_pk (pk), NULL))
            compliant = 0;
          release_public_key_parts (pk);
        }

      xfree (pk);

      if (compliant)
        compliance_de_vs |= 1;
    }

  if (!result)
    {
      int compl_error;
      result = decrypt_data (c->ctrl, c, pkt->pkt.encrypted, c->dek,
                             &compl_error);
      if (!result && !compl_error)
        compliance_de_vs |= 2;
    }

  /* Trigger the deferred error.  */
  if (!result && early_plaintext)
    result = gpg_error (GPG_ERR_BAD_DATA);

  if (result == -1)
    ;
  else if (!result
           && !opt.ignore_mdc_error
           && !pkt->pkt.encrypted->mdc_method
           && !pkt->pkt.encrypted->aead_algo)
    {
      /* The message has been decrypted but does not carry an MDC or
       * uses AEAD encryption.  --ignore-mdc-error has also not been
       * used.  To avoid attacks changing an MDC message to a non-MDC
       * message, we fail here.  */
      log_error (_("WARNING: message was not integrity protected\n"));
      if (!pkt->pkt.encrypted->mdc_method
          && (openpgp_cipher_get_algo_blklen (c->dek->algo) == 8
              || c->dek->algo == CIPHER_ALGO_TWOFISH))
        {
          /* Before 2.2.8 we did not fail hard for a missing MDC if
           * one of the old ciphers where used.  Although these cases
           * are rare in practice we print a hint on how to decrypt
           * such messages.  */
          log_string
            (GPGRT_LOGLVL_INFO,
             _("Hint: If this message was created before the year 2003 it is\n"
               "likely that this message is legitimate.  This is because back\n"
               "then integrity protection was not widely used.\n"));
          log_info (_("Use the option '%s' to decrypt anyway.\n"),
                     "--ignore-mdc-error");
          write_status_errcode ("nomdc_with_legacy_cipher",
                                GPG_ERR_DECRYPT_FAILED);
        }
      log_info (_("decryption forced to fail!\n"));
      write_status (STATUS_DECRYPTION_FAILED);
    }
  else if (!result || (gpg_err_code (result) == GPG_ERR_BAD_SIGNATURE
                       && !pkt->pkt.encrypted->aead_algo
                       && opt.ignore_mdc_error))
    {
      /* All is fine or for an MDC message the MDC failed but the
       * --ignore-mdc-error option is active.  For compatibility
       * reasons we issue GOODMDC also for AEAD messages.  */
      write_status (STATUS_DECRYPTION_OKAY);
      if (opt.verbose > 1)
        log_info(_("decryption okay\n"));

      if (pkt->pkt.encrypted->aead_algo)
        {
          write_status (STATUS_GOODMDC);
          compliance_de_vs |= 4;
        }
      else if (pkt->pkt.encrypted->mdc_method && !result)
        {
          write_status (STATUS_GOODMDC);
          compliance_de_vs |= 4;
        }
      else
        log_info (_("WARNING: message was not integrity protected\n"));
    }
  else if (gpg_err_code (result) == GPG_ERR_BAD_SIGNATURE
           || gpg_err_code (result) == GPG_ERR_TRUNCATED)
    {
      glo_ctrl.lasterr = result;
      log_error (_("WARNING: encrypted message has been manipulated!\n"));
      write_status (STATUS_BADMDC);
      write_status (STATUS_DECRYPTION_FAILED);
    }
  else
    {
      if (gpg_err_code (result) == GPG_ERR_BAD_KEY
          || gpg_err_code (result) == GPG_ERR_CHECKSUM
          || gpg_err_code (result) == GPG_ERR_CIPHER_ALGO)
        {
          if (c->symkeys)
            write_status_text (STATUS_ERROR,
                               "symkey_decrypt.maybe_error"
                               " 11_BAD_PASSPHRASE");

          if (c->dek && *c->dek->s2k_cacheid != '\0')
            {
              if (opt.debug)
                log_debug ("cleared passphrase cached with ID: %s\n",
                           c->dek->s2k_cacheid);
              passphrase_clear_cache (c->dek->s2k_cacheid);
            }
        }
      glo_ctrl.lasterr = result;
      write_status (STATUS_DECRYPTION_FAILED);
      log_error (_("decryption failed: %s\n"), gpg_strerror (result));
      /* Hmmm: does this work when we have encrypted using multiple
       * ways to specify the session key (symmmetric and PK). */
    }


  /* If we concluded that the decryption was compliant, issue a
   * compliance status before the end of the decryption status.  */
  if (compliance_de_vs == (4|2|1))
    {
      write_status_strings (STATUS_DECRYPTION_COMPLIANCE_MODE,
                            gnupg_status_compliance_flag (CO_DE_VS),
                            NULL);
    }

  xfree (c->dek);
  c->dek = NULL;
  free_packet (pkt, NULL);
  c->last_was_session_key = 0;
  write_status (STATUS_END_DECRYPTION);

  /* Bump the counter even if we have not seen a literal data packet
   * inside an encryption container.  This acts as a sentinel in case
   * a misplace extra literal data packets follows after this
   * encrypted packet.  */
  literals_seen++;

  /* The --require-compliance option allows one to simplify decryption in
   * de-vs compliance mode by just looking at the exit status.  */
  if (opt.flags.require_compliance
      && opt.compliance == CO_DE_VS
      && compliance_de_vs != (4|2|1))
    {
      log_error (_("operation forced to fail due to"
                   " unfulfilled compliance rules\n"));
      g10_errors_seen = 1;
    }
}


static int
have_seen_pkt_encrypted_aead_or_mdc( CTX c )
{
  CTX cc;

  for (cc = c; cc; cc = cc->anchor)
    {
      if (cc->seen_pkt_encrypted_aead)
	return 1;
      if (cc->seen_pkt_encrypted_mdc)
	return 1;
    }

  return 0;
}


static void
proc_plaintext( CTX c, PACKET *pkt )
{
  PKT_plaintext *pt = pkt->pkt.plaintext;
  int any, clearsig, rc;
  kbnode_t n;
  unsigned char *extrahash;
  size_t extrahashlen;

  /* This is a literal data packet.  Bump a counter for later checks.  */
  literals_seen++;

  if (pt->namelen == 8 && !memcmp( pt->name, "_CONSOLE", 8))
    log_info (_("Note: sender requested \"for-your-eyes-only\"\n"));
  else if (opt.verbose)
    {
      /* We don't use print_utf8_buffer because that would require a
       * string change which we don't want in 2.2.  It is also not
       * clear whether the filename is always utf-8 encoded.  */
      char *tmp = make_printable_string (pt->name, pt->namelen, 0);
      log_info (_("original file name='%.*s'\n"), (int)strlen (tmp), tmp);
      xfree (tmp);
    }

  free_md_filter_context (&c->mfx);
  if (gcry_md_open (&c->mfx.md, 0, 0))
    BUG ();
  /* fixme: we may need to push the textfilter if we have sigclass 1
   * and no armoring - Not yet tested
   * Hmmm, why don't we need it at all if we have sigclass 1
   * Should we assume that plaintext in mode 't' has always sigclass 1??
   * See: Russ Allbery's mail 1999-02-09
   */
  any = clearsig = 0;
  for (n=c->list; n; n = n->next )
    {
      if (n->pkt->pkttype == PKT_ONEPASS_SIG)
        {
          /* The onepass signature case. */
          if (n->pkt->pkt.onepass_sig->digest_algo)
            {
              if (!opt.skip_verify)
                gcry_md_enable (c->mfx.md,
                                n->pkt->pkt.onepass_sig->digest_algo);

              any = 1;
            }
        }
      else if (n->pkt->pkttype == PKT_GPG_CONTROL
               && n->pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START)
        {
          /* The clearsigned message case. */
          size_t datalen = n->pkt->pkt.gpg_control->datalen;
          const byte *data = n->pkt->pkt.gpg_control->data;

          /* Check that we have at least the sigclass and one hash.  */
          if  (datalen < 2)
            log_fatal ("invalid control packet CTRLPKT_CLEARSIGN_START\n");
          /* Note that we don't set the clearsig flag for not-dash-escaped
           * documents.  */
          clearsig = (*data == 0x01);
          for (data++, datalen--; datalen; datalen--, data++)
            if (!opt.skip_verify)
              gcry_md_enable (c->mfx.md, *data);
          any = 1;
          break;  /* Stop here as one-pass signature packets are not
                     expected.  */
        }
      else if (n->pkt->pkttype == PKT_SIGNATURE)
        {
          /* The SIG+LITERAL case that PGP used to use.  */
          if (!opt.skip_verify)
            gcry_md_enable (c->mfx.md, n->pkt->pkt.signature->digest_algo);
          any = 1;
        }
    }

  if (!any && !opt.skip_verify && !have_seen_pkt_encrypted_aead_or_mdc(c))
    {
      /* This is for the old GPG LITERAL+SIG case.  It's not legal
         according to 2440, so hopefully it won't come up that often.
         There is no good way to specify what algorithms to use in
         that case, so these there are the historical answer. */
	gcry_md_enable (c->mfx.md, DIGEST_ALGO_RMD160);
	gcry_md_enable (c->mfx.md, DIGEST_ALGO_SHA1);
    }
  if (DBG_HASHING)
    {
      gcry_md_debug (c->mfx.md, "verify");
      if (c->mfx.md2)
        gcry_md_debug (c->mfx.md2, "verify2");
    }

  rc=0;

  if (literals_seen > 1)
    {
      log_info (_("WARNING: multiple plaintexts seen\n"));

      write_status_text (STATUS_ERROR, "proc_pkt.plaintext 89_BAD_DATA");
      log_inc_errorcount ();
      rc = gpg_error (GPG_ERR_UNEXPECTED);
    }

  if (!rc)
    {
      /* It we are in --verify mode, we do not want to output the
       * signed text.  However, if --output is also used we do what
       * has been requested and write out the signed data.  */
      rc = handle_plaintext (pt, &c->mfx,
                             (opt.outfp || opt.outfile)? 0 :  c->sigs_only,
                             clearsig);
      if (gpg_err_code (rc) == GPG_ERR_EACCES && !c->sigs_only)
        {
          /* Can't write output but we hash it anyway to check the
             signature. */
          rc = handle_plaintext( pt, &c->mfx, 1, clearsig );
        }
    }

  if (rc)
    log_error ("handle plaintext failed: %s\n", gpg_strerror (rc));

  /* We add a marker control packet instead of the plaintext packet.
   * This is so that we can later detect invalid packet sequences.
   * The packet is further used to convey extra data from the
   * plaintext packet to the signature verification. */
  extrahash = xtrymalloc (6 + pt->namelen);
  if (!extrahash)
    {
      /* No way to return an error.  */
      rc = gpg_error_from_syserror ();
      log_error ("malloc failed in %s: %s\n", __func__, gpg_strerror (rc));
      extrahashlen = 0;
    }
  else
    {
      extrahash[0] = pt->mode;
      extrahash[1] = pt->namelen;
      if (pt->namelen)
        memcpy (extrahash+2, pt->name, pt->namelen);
      extrahashlen = 2 + pt->namelen;
      extrahash[extrahashlen++] = pt->timestamp >> 24;
      extrahash[extrahashlen++] = pt->timestamp >> 16;
      extrahash[extrahashlen++] = pt->timestamp >>  8;
      extrahash[extrahashlen++] = pt->timestamp      ;
    }

  free_packet (pkt, NULL);
  c->last_was_session_key = 0;

  n = new_kbnode (create_gpg_control (CTRLPKT_PLAINTEXT_MARK,
                                      extrahash, extrahashlen));
  xfree (extrahash);
  if (c->list)
    add_kbnode (c->list, n);
  else
    c->list = n;
}


static int
proc_compressed_cb (iobuf_t a, void *info)
{
  if ( ((CTX)info)->signed_data.used
       && ((CTX)info)->signed_data.data_fd != -1)
    return proc_signature_packets_by_fd (((CTX)info)->ctrl, info, a,
                                         ((CTX)info)->signed_data.data_fd);
  else
    return proc_signature_packets (((CTX)info)->ctrl, info, a,
                                   ((CTX)info)->signed_data.data_names,
                                   ((CTX)info)->sigfilename );
}


static int
proc_encrypt_cb (iobuf_t a, void *info )
{
  CTX c = info;
  return proc_encryption_packets (c->ctrl, info, a );
}


static int
proc_compressed (CTX c, PACKET *pkt)
{
  PKT_compressed *zd = pkt->pkt.compressed;
  int rc;

  /*printf("zip: compressed data packet\n");*/
  if (c->sigs_only)
    rc = handle_compressed (c->ctrl, c, zd, proc_compressed_cb, c);
  else if( c->encrypt_only )
    rc = handle_compressed (c->ctrl, c, zd, proc_encrypt_cb, c);
  else
    rc = handle_compressed (c->ctrl, c, zd, NULL, NULL);

  if (gpg_err_code (rc) == GPG_ERR_BAD_DATA)
    {
      if  (!c->any.uncompress_failed)
        {
          CTX cc;

          for (cc=c; cc; cc = cc->anchor)
            cc->any.uncompress_failed = 1;
          log_error ("uncompressing failed: %s\n", gpg_strerror (rc));
        }
    }
  else if (rc)
    log_error ("uncompressing failed: %s\n", gpg_strerror (rc));

  free_packet (pkt, NULL);
  c->last_was_session_key = 0;
  return rc;
}


/*
 * Check the signature.  If R_PK is not NULL a copy of the public key
 * used to verify the signature will be stored there, or NULL if not
 * found.  If FORCED_PK is not NULL, this public key is used to verify
 * _data signatures_ and no key lookup is done.  Returns: 0 = valid
 * signature or an error code
 */
static int
do_check_sig (CTX c, kbnode_t node, const void *extrahash, size_t extrahashlen,
              PKT_public_key *forced_pk, int *is_selfsig,
	      int *is_expkey, int *is_revkey, PKT_public_key **r_pk)
{
  PKT_signature *sig;
  gcry_md_hd_t md = NULL;
  gcry_md_hd_t md2 = NULL;
  gcry_md_hd_t md_good = NULL;
  int algo, rc;

  if (r_pk)
    *r_pk = NULL;

  log_assert (node->pkt->pkttype == PKT_SIGNATURE);
  if (is_selfsig)
    *is_selfsig = 0;
  sig = node->pkt->pkt.signature;

  algo = sig->digest_algo;
  rc = openpgp_md_test_algo (algo);
  if (rc)
    return rc;

  if (sig->sig_class == 0x00)
    {
      if (c->mfx.md)
        {
          if (gcry_md_copy (&md, c->mfx.md ))
            BUG ();
        }
      else /* detached signature */
        {
          /* check_signature() will enable the md. */
          if (gcry_md_open (&md, 0, 0 ))
            BUG ();
        }
    }
  else if (sig->sig_class == 0x01)
    {
      /* How do we know that we have to hash the (already hashed) text
         in canonical mode ??? (calculating both modes???) */
      if (c->mfx.md)
        {
          if (gcry_md_copy (&md, c->mfx.md ))
            BUG ();
          if (c->mfx.md2 && gcry_md_copy (&md2, c->mfx.md2))
            BUG ();
	}
      else /* detached signature */
        {
          log_debug ("Do we really need this here?");
          /* check_signature() will enable the md*/
          if (gcry_md_open (&md, 0, 0 ))
            BUG ();
          if (gcry_md_open (&md2, 0, 0 ))
            BUG ();
	}
    }
  else if ((sig->sig_class&~3) == 0x10
           ||   sig->sig_class == 0x18
           ||   sig->sig_class == 0x1f
	   ||   sig->sig_class == 0x20
	   ||   sig->sig_class == 0x28
           ||   sig->sig_class == 0x30)
    {
      if (c->list->pkt->pkttype == PKT_PUBLIC_KEY
          || c->list->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          return check_key_signature (c->ctrl, c->list, node, is_selfsig);
	}
      else if (sig->sig_class == 0x20)
        {
          log_error (_("standalone revocation - "
                       "use \"gpg --import\" to apply\n"));
          return GPG_ERR_NOT_PROCESSED;
	}
      else
        {
          log_error ("invalid root packet for sigclass %02x\n", sig->sig_class);
          return GPG_ERR_SIG_CLASS;
	}
    }
  else
    return GPG_ERR_SIG_CLASS;

  /* We only get here if we are checking the signature of a binary
     (0x00) or text document (0x01).  */
  rc = check_signature2 (c->ctrl, sig, md, extrahash, extrahashlen,
                         forced_pk,
                         NULL, is_expkey, is_revkey, r_pk);
  if (! rc)
    md_good = md;
  else if (gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE && md2)
    {
      PKT_public_key *pk2;

      rc = check_signature2 (c->ctrl, sig, md2, extrahash, extrahashlen,
                             forced_pk,
                             NULL, is_expkey, is_revkey,
                             r_pk? &pk2 : NULL);
      if (!rc)
        {
          md_good = md2;
          if (r_pk)
            {
              free_public_key (*r_pk);
              *r_pk = pk2;
            }
        }
    }

  if (md_good)
    {
      unsigned char *buffer = gcry_md_read (md_good, sig->digest_algo);
      sig->digest_len = gcry_md_get_algo_dlen (map_md_openpgp_to_gcry (algo));
      memcpy (sig->digest, buffer, sig->digest_len);
    }

  gcry_md_close (md);
  gcry_md_close (md2);

  return rc;
}


static void
print_userid (PACKET *pkt)
{
  if (!pkt)
    BUG();

  if (pkt->pkttype != PKT_USER_ID)
    {
      es_printf ("ERROR: unexpected packet type %d", pkt->pkttype );
      return;
    }
  if (opt.with_colons)
    {
      if (pkt->pkt.user_id->attrib_data)
        es_printf("%u %lu",
                  pkt->pkt.user_id->numattribs,
                  pkt->pkt.user_id->attrib_len);
      else
        es_write_sanitized (es_stdout, pkt->pkt.user_id->name,
                            pkt->pkt.user_id->len, ":", NULL);
    }
  else
    print_utf8_buffer (es_stdout, pkt->pkt.user_id->name,
                       pkt->pkt.user_id->len );
}


/*
 * List the keyblock in a user friendly way
 */
static void
list_node (CTX c, kbnode_t node)
{
  if (!node)
    ;
  else if (node->pkt->pkttype == PKT_PUBLIC_KEY
           || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
    {
      PKT_public_key *pk = node->pkt->pkt.public_key;

      if (opt.with_colons)
        {
          u32 keyid[2];

          keyid_from_pk( pk, keyid );
          if (pk->flags.primary)
            c->trustletter = (opt.fast_list_mode
                              ? 0
                              : get_validity_info
                                  (c->ctrl,
                                   node->pkt->pkttype == PKT_PUBLIC_KEY
                                   ? node : NULL,
                                   pk, NULL));
          es_printf ("%s:", pk->flags.primary? "pub":"sub" );
          if (c->trustletter)
            es_putc (c->trustletter, es_stdout);
          es_printf (":%u:%d:%08lX%08lX:%s:%s::",
                     nbits_from_pk( pk ),
                     pk->pubkey_algo,
                     (ulong)keyid[0],(ulong)keyid[1],
                     colon_datestr_from_pk( pk ),
                     colon_strtime (pk->expiredate) );
          if (pk->flags.primary && !opt.fast_list_mode)
            es_putc (get_ownertrust_info (c->ctrl, pk, 1), es_stdout);
          es_putc (':', es_stdout);
          es_putc ('\n', es_stdout);
        }
      else
        {
          print_key_line (c->ctrl, es_stdout, pk, 0);
        }

      if (opt.keyid_format == KF_NONE && !opt.with_colons)
        ; /* Already printed.  */
      else if ((pk->flags.primary && opt.fingerprint) || opt.fingerprint > 1)
        print_fingerprint (c->ctrl, NULL, pk, 0);

      if (pk->flags.primary)
        {
          int kl = opt.keyid_format == KF_NONE? 0 : keystrlen ();

          /* Now list all userids with their signatures. */
          for (node = node->next; node; node = node->next)
            {
              if (node->pkt->pkttype == PKT_SIGNATURE)
                {
                  list_node (c,  node );
                }
              else if (node->pkt->pkttype == PKT_USER_ID)
                {
                  if (opt.with_colons)
                    es_printf ("%s:::::::::",
                               node->pkt->pkt.user_id->attrib_data?"uat":"uid");
                  else
                    es_printf ("uid%*s",
                               kl + (opt.legacy_list_mode? 9:11),
                               "" );
                  print_userid (node->pkt);
                  if (opt.with_colons)
                    es_putc (':', es_stdout);
                  es_putc ('\n', es_stdout);
		}
              else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
                {
                  list_node(c,  node );
                }
            }
        }
    }
  else if (node->pkt->pkttype == PKT_SECRET_KEY
           || node->pkt->pkttype == PKT_SECRET_SUBKEY)
    {

      log_debug ("FIXME: No way to print secret key packets here\n");
      /* fixme: We may use a function to turn a secret key packet into
         a public key one and use that here.  */
    }
  else if (node->pkt->pkttype == PKT_SIGNATURE)
    {
      PKT_signature *sig = node->pkt->pkt.signature;
      int is_selfsig = 0;
      int rc2 = 0;
      size_t n;
      char *p;
      int sigrc = ' ';

      if (!opt.verbose)
        return;

      if (sig->sig_class == 0x20 || sig->sig_class == 0x30)
        es_fputs ("rev", es_stdout);
      else
        es_fputs ("sig", es_stdout);
      if (opt.check_sigs)
        {
          fflush (stdout);
          rc2 = do_check_sig (c, node, NULL, 0, NULL,
                              &is_selfsig, NULL, NULL, NULL);
          switch (gpg_err_code (rc2))
            {
            case 0:		          sigrc = '!'; break;
            case GPG_ERR_BAD_SIGNATURE:   sigrc = '-'; break;
            case GPG_ERR_NO_PUBKEY:
            case GPG_ERR_UNUSABLE_PUBKEY: sigrc = '?'; break;
            default:		          sigrc = '%'; break;
	    }
	}
      else /* Check whether this is a self signature.  */
        {
          u32 keyid[2];

          if (c->list->pkt->pkttype == PKT_PUBLIC_KEY
              || c->list->pkt->pkttype == PKT_SECRET_KEY )
            {
              keyid_from_pk (c->list->pkt->pkt.public_key, keyid);

              if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1])
                is_selfsig = 1;
            }
	}

      if (opt.with_colons)
        {
          es_putc (':', es_stdout);
          if (sigrc != ' ')
            es_putc (sigrc, es_stdout);
          es_printf ("::%d:%08lX%08lX:%s:%s:", sig->pubkey_algo,
                     (ulong)sig->keyid[0], (ulong)sig->keyid[1],
                     colon_datestr_from_sig (sig),
                     colon_expirestr_from_sig (sig));

          if (sig->trust_depth || sig->trust_value)
            es_printf ("%d %d",sig->trust_depth,sig->trust_value);
          es_putc (':', es_stdout);

          if (sig->trust_regexp)
            es_write_sanitized (es_stdout, sig->trust_regexp,
                                strlen (sig->trust_regexp), ":", NULL);
          es_putc (':', es_stdout);
	}
      else
        es_printf ("%c       %s %s   ",
                   sigrc, keystr (sig->keyid), datestr_from_sig(sig));
      if (sigrc == '%')
        es_printf ("[%s] ", gpg_strerror (rc2) );
      else if (sigrc == '?')
        ;
      else if (is_selfsig)
        {
          if (opt.with_colons)
            es_putc (':', es_stdout);
          es_fputs (sig->sig_class == 0x18? "[keybind]":"[selfsig]", es_stdout);
          if (opt.with_colons)
            es_putc (':', es_stdout);
	}
      else if (!opt.fast_list_mode)
        {
          p = get_user_id (c->ctrl, sig->keyid, &n, NULL);
          es_write_sanitized (es_stdout, p, n,
                              opt.with_colons?":":NULL, NULL );
          xfree (p);
	}
      if (opt.with_colons)
        es_printf (":%02x%c:", sig->sig_class, sig->flags.exportable?'x':'l');
      es_putc ('\n', es_stdout);
    }
  else
    log_error ("invalid node with packet of type %d\n", node->pkt->pkttype);
}


int
proc_packets (ctrl_t ctrl, void *anchor, iobuf_t a )
{
  int rc;
  CTX c = xmalloc_clear (sizeof *c);

  c->ctrl = ctrl;
  c->anchor = anchor;
  rc = do_proc_packets (c, a);
  xfree (c);

  return rc;
}


int
proc_signature_packets (ctrl_t ctrl, void *anchor, iobuf_t a,
			strlist_t signedfiles, const char *sigfilename )
{
  CTX c = xmalloc_clear (sizeof *c);
  int rc;

  c->ctrl = ctrl;
  c->anchor = anchor;
  c->sigs_only = 1;

  c->signed_data.data_fd = -1;
  c->signed_data.data_names = signedfiles;
  c->signed_data.used = !!signedfiles;

  c->sigfilename = sigfilename;
  rc = do_proc_packets (c, a);

  /* If we have not encountered any signature we print an error
     messages, send a NODATA status back and return an error code.
     Using log_error is required because verify_files does not check
     error codes for each file but we want to terminate the process
     with an error. */
  if (!rc && !c->any.sig_seen)
    {
      write_status_text (STATUS_NODATA, "4");
      log_error (_("no signature found\n"));
      rc = GPG_ERR_NO_DATA;
    }

  /* Propagate the signature seen flag upward. Do this only on success
     so that we won't issue the nodata status several times.  */
  if (!rc && c->anchor && c->any.sig_seen)
    c->anchor->any.sig_seen = 1;

  xfree (c);
  return rc;
}


int
proc_signature_packets_by_fd (ctrl_t ctrl,
                              void *anchor, iobuf_t a, int signed_data_fd )
{
  int rc;
  CTX c;

  c = xtrycalloc (1, sizeof *c);
  if (!c)
    return gpg_error_from_syserror ();

  c->ctrl = ctrl;
  c->anchor = anchor;
  c->sigs_only = 1;

  c->signed_data.data_fd = signed_data_fd;
  c->signed_data.data_names = NULL;
  c->signed_data.used = (signed_data_fd != -1);

  rc = do_proc_packets (c, a);

  /* If we have not encountered any signature we print an error
     messages, send a NODATA status back and return an error code.
     Using log_error is required because verify_files does not check
     error codes for each file but we want to terminate the process
     with an error. */
  if (!rc && !c->any.sig_seen)
    {
      write_status_text (STATUS_NODATA, "4");
      log_error (_("no signature found\n"));
      rc = gpg_error (GPG_ERR_NO_DATA);
    }

  /* Propagate the signature seen flag upward. Do this only on success
     so that we won't issue the nodata status several times. */
  if (!rc && c->anchor && c->any.sig_seen)
    c->anchor->any.sig_seen = 1;

  xfree ( c );
  return rc;
}


int
proc_encryption_packets (ctrl_t ctrl, void *anchor, iobuf_t a )
{
  CTX c = xmalloc_clear (sizeof *c);
  int rc;

  c->ctrl = ctrl;
  c->anchor = anchor;
  c->encrypt_only = 1;
  rc = do_proc_packets (c, a);
  xfree (c);
  return rc;
}


static int
check_nesting (CTX c)
{
  int level;

  for (level=0; c; c = c->anchor)
    level++;

  if (level > MAX_NESTING_DEPTH)
    {
      log_error ("input data with too deeply nested packets\n");
      write_status_text (STATUS_UNEXPECTED, "1");
      return GPG_ERR_BAD_DATA;
    }

  return 0;
}


static int
do_proc_packets (CTX c, iobuf_t a)
{
  PACKET *pkt;
  struct parse_packet_ctx_s parsectx;
  int rc = 0;
  int any_data = 0;
  int newpkt;

  rc = check_nesting (c);
  if (rc)
    return rc;

  pkt = xmalloc( sizeof *pkt );
  c->iobuf = a;
  init_packet(pkt);
  init_parse_packet (&parsectx, a);
  while ((rc=parse_packet (&parsectx, pkt)) != -1)
    {
      any_data = 1;
      if (rc)
        {
          free_packet (pkt, &parsectx);
          /* Stop processing when an invalid packet has been encountered
           * but don't do so when we are doing a --list-packets.  */
          if (gpg_err_code (rc) == GPG_ERR_INV_PACKET
              && opt.list_packets == 0)
            break;
          continue;
	}
      newpkt = -1;
      if (opt.list_packets)
        {
          switch (pkt->pkttype)
            {
            case PKT_PUBKEY_ENC:    proc_pubkey_enc (c, pkt); break;
            case PKT_SYMKEY_ENC:    proc_symkey_enc (c, pkt); break;
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC:
            case PKT_ENCRYPTED_AEAD:proc_encrypted (c, pkt); break;
            case PKT_COMPRESSED:    rc = proc_compressed (c, pkt); break;
            default: newpkt = 0; break;
	    }
	}
      else if (c->sigs_only)
        {
          switch (pkt->pkttype)
            {
            case PKT_PUBLIC_KEY:
            case PKT_SECRET_KEY:
            case PKT_USER_ID:
            case PKT_SYMKEY_ENC:
            case PKT_PUBKEY_ENC:
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC:
            case PKT_ENCRYPTED_AEAD:
              write_status_text( STATUS_UNEXPECTED, "0" );
              rc = GPG_ERR_UNEXPECTED;
              goto leave;

            case PKT_SIGNATURE:   newpkt = add_signature (c, pkt); break;
            case PKT_PLAINTEXT:   proc_plaintext (c, pkt); break;
            case PKT_COMPRESSED:  rc = proc_compressed (c, pkt); break;
            case PKT_ONEPASS_SIG: newpkt = add_onepass_sig (c, pkt); break;
            case PKT_GPG_CONTROL: newpkt = add_gpg_control (c, pkt); break;
            default: newpkt = 0; break;
	    }
	}
      else if (c->encrypt_only)
        {
          switch (pkt->pkttype)
            {
            case PKT_PUBLIC_KEY:
            case PKT_SECRET_KEY:
            case PKT_USER_ID:
              write_status_text (STATUS_UNEXPECTED, "0");
              rc = GPG_ERR_UNEXPECTED;
              goto leave;

            case PKT_SIGNATURE:   newpkt = add_signature (c, pkt); break;
            case PKT_SYMKEY_ENC:  proc_symkey_enc (c, pkt); break;
            case PKT_PUBKEY_ENC:  proc_pubkey_enc (c, pkt); break;
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC:
            case PKT_ENCRYPTED_AEAD: proc_encrypted (c, pkt); break;
            case PKT_PLAINTEXT:   proc_plaintext (c, pkt); break;
            case PKT_COMPRESSED:  rc = proc_compressed (c, pkt); break;
            case PKT_ONEPASS_SIG: newpkt = add_onepass_sig (c, pkt); break;
            case PKT_GPG_CONTROL: newpkt = add_gpg_control (c, pkt); break;
            default: newpkt = 0; break;
	    }
	}
      else
        {
          switch (pkt->pkttype)
            {
            case PKT_PUBLIC_KEY:
            case PKT_SECRET_KEY:
              release_list (c);
              c->list = new_kbnode (pkt);
              newpkt = 1;
              break;
            case PKT_PUBLIC_SUBKEY:
            case PKT_SECRET_SUBKEY:
              newpkt = add_subkey (c, pkt);
              break;
            case PKT_USER_ID:     newpkt = add_user_id (c, pkt); break;
            case PKT_SIGNATURE:   newpkt = add_signature (c, pkt); break;
            case PKT_PUBKEY_ENC:  proc_pubkey_enc (c, pkt); break;
            case PKT_SYMKEY_ENC:  proc_symkey_enc (c, pkt); break;
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC:
            case PKT_ENCRYPTED_AEAD: proc_encrypted (c, pkt); break;
            case PKT_PLAINTEXT:   proc_plaintext (c, pkt); break;
            case PKT_COMPRESSED:  rc = proc_compressed (c, pkt); break;
            case PKT_ONEPASS_SIG: newpkt = add_onepass_sig (c, pkt); break;
            case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
            case PKT_RING_TRUST:  newpkt = add_ring_trust (c, pkt); break;
            default: newpkt = 0; break;
	    }
	}

      if (rc)
        goto leave;

      /* This is a very ugly construct and frankly, I don't remember why
       * I used it.  Adding the MDC check here is a hack.
       * The right solution is to initiate another context for encrypted
       * packet and not to reuse the current one ...  It works right
       * when there is a compression packet between which adds just
       * an extra layer.
       * Hmmm: Rewrite this whole module here??
       */
      if (pkt->pkttype != PKT_SIGNATURE && pkt->pkttype != PKT_MDC)
        c->any.data = (pkt->pkttype == PKT_PLAINTEXT);

      if (newpkt == -1)
        ;
      else if (newpkt)
        {
          pkt = xmalloc (sizeof *pkt);
          init_packet (pkt);
	}
      else
        free_packet (pkt, &parsectx);
    }

  if (rc == GPG_ERR_INV_PACKET)
    write_status_text (STATUS_NODATA, "3");

  if (any_data)
    rc = 0;
  else if (rc == -1)
    write_status_text (STATUS_NODATA, "2");


 leave:
  release_list (c);
  xfree(c->dek);
  free_packet (pkt, &parsectx);
  deinit_parse_packet (&parsectx);
  xfree (pkt);
  free_md_filter_context (&c->mfx);
  return rc;
}


/* Return true if the AKL has the WKD method specified.  */
static int
akl_has_wkd_method (void)
{
  struct akl *akl;

  for (akl = opt.auto_key_locate; akl; akl = akl->next)
    if (akl->type == AKL_WKD)
      return 1;
  return 0;
}


/* Return the ISSUER fingerprint buffer and its length at R_LEN.
 * Returns NULL if not available.  The returned buffer is valid as
 * long as SIG is not modified.  */
const byte *
issuer_fpr_raw (PKT_signature *sig, size_t *r_len)
{
  const byte *p;
  size_t n;

  p = parse_sig_subpkt (sig, 1, SIGSUBPKT_ISSUER_FPR, &n);
  if (p && ((n == 21 && p[0] == 4) || (n == 33 && p[0] == 5)))
    {
      *r_len = n - 1;
      return p+1;
    }
  *r_len = 0;
  return NULL;
}


/* Return the ISSUER fingerprint string in human readable format if
 * available.  Caller must release the string.  */
/* FIXME: Move to another file.  */
char *
issuer_fpr_string (PKT_signature *sig)
{
  const byte *p;
  size_t n;

  p = issuer_fpr_raw (sig, &n);
  return p? bin2hex (p, n, NULL) : NULL;
}


static void
print_good_bad_signature (int statno, const char *keyid_str, kbnode_t un,
                          PKT_signature *sig, int rc)
{
  char *p;

  write_status_text_and_buffer (statno, keyid_str,
                                un? un->pkt->pkt.user_id->name:"[?]",
                                un? un->pkt->pkt.user_id->len:3,
                                -1);

  if (un)
    p = utf8_to_native (un->pkt->pkt.user_id->name,
                        un->pkt->pkt.user_id->len, 0);
  else
    p = xstrdup ("[?]");

  if (rc)
    log_info (_("BAD signature from \"%s\""), p);
  else if (sig->flags.expired)
    log_info (_("Expired signature from \"%s\""), p);
  else
    log_info (_("Good signature from \"%s\""), p);

  xfree (p);
}


static int
check_sig_and_print (CTX c, kbnode_t node)
{
  PKT_signature *sig = node->pkt->pkt.signature;
  const char *astr;
  gpg_error_t rc;
  int is_expkey = 0;
  int is_revkey = 0;
  char *issuer_fpr = NULL;
  PKT_public_key *pk = NULL;  /* The public key for the signature or NULL. */
  const void *extrahash = NULL;
  size_t extrahashlen = 0;
  kbnode_t included_keyblock = NULL;
  char pkstrbuf[PUBKEY_STRING_SIZE] = { 0 };


  if (opt.skip_verify)
    {
      log_info(_("signature verification suppressed\n"));
      return 0;
    }

  /* Check that the message composition is valid.
   *
   * Per RFC-2440bis (-15) allowed:
   *
   * S{1,n}           -- detached signature.
   * S{1,n} P         -- old style PGP2 signature
   * O{1,n} P S{1,n}  -- standard OpenPGP signature.
   * C P S{1,n}       -- cleartext signature.
   *
   *
   *      O = One-Pass Signature packet.
   *      S = Signature packet.
   *      P = OpenPGP Message packet (Encrypted | Compressed | Literal)
   *             (Note that the current rfc2440bis draft also allows
   *              for a signed message but that does not work as it
   *              introduces ambiguities.)
   *          We keep track of these packages using the marker packet
   *          CTRLPKT_PLAINTEXT_MARK.
   *      C = Marker packet for cleartext signatures.
   *
   * We reject all other messages.
   *
   * Actually we are calling this too often, i.e. for verification of
   * each message but better have some duplicate work than to silently
   * introduce a bug here.
   */
  {
    kbnode_t n;
    int n_onepass, n_sig;

/*     log_debug ("checking signature packet composition\n"); */
/*     dump_kbnode (c->list); */

    n = c->list;
    log_assert (n);
    if ( n->pkt->pkttype == PKT_SIGNATURE )
      {
        /* This is either "S{1,n}" case (detached signature) or
           "S{1,n} P" (old style PGP2 signature). */
        for (n = n->next; n; n = n->next)
          if (n->pkt->pkttype != PKT_SIGNATURE)
            break;
        if (!n)
          ; /* Okay, this is a detached signature.  */
        else if (n->pkt->pkttype == PKT_GPG_CONTROL
                 && (n->pkt->pkt.gpg_control->control
                     == CTRLPKT_PLAINTEXT_MARK) )
          {
            if (n->next)
              goto ambiguous;  /* We only allow one P packet. */
            extrahash = n->pkt->pkt.gpg_control->data;
            extrahashlen = n->pkt->pkt.gpg_control->datalen;
          }
        else
          goto ambiguous;
      }
    else if (n->pkt->pkttype == PKT_ONEPASS_SIG)
      {
        /* This is the "O{1,n} P S{1,n}" case (standard signature). */
        for (n_onepass=1, n = n->next;
             n && n->pkt->pkttype == PKT_ONEPASS_SIG; n = n->next)
          n_onepass++;
        if (!n || !(n->pkt->pkttype == PKT_GPG_CONTROL
                    && (n->pkt->pkt.gpg_control->control
                        == CTRLPKT_PLAINTEXT_MARK)))
          goto ambiguous;
        extrahash = n->pkt->pkt.gpg_control->data;
        extrahashlen = n->pkt->pkt.gpg_control->datalen;

        for (n_sig=0, n = n->next;
             n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
          n_sig++;
        if (!n_sig)
          goto ambiguous;

	/* If we wanted to disallow multiple sig verification, we'd do
	 * something like this:
         *
	 * if (n)
         *   goto ambiguous;
         *
         * However, this can stay allowable as we can't get here.  */

        if (n_onepass != n_sig)
          {
            log_info ("number of one-pass packets does not match "
                      "number of signature packets\n");
            goto ambiguous;
          }
      }
    else if (n->pkt->pkttype == PKT_GPG_CONTROL
             && n->pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START )
      {
        /* This is the "C P S{1,n}" case (clear text signature). */
        n = n->next;
        if (!n || !(n->pkt->pkttype == PKT_GPG_CONTROL
                    && (n->pkt->pkt.gpg_control->control
                        == CTRLPKT_PLAINTEXT_MARK)))
          goto ambiguous;
        extrahash = n->pkt->pkt.gpg_control->data;
        extrahashlen = n->pkt->pkt.gpg_control->datalen;
        for (n_sig=0, n = n->next;
             n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
          n_sig++;
        if (n || !n_sig)
          goto ambiguous;
      }
    else
      {
      ambiguous:
        log_error(_("can't handle this ambiguous signature data\n"));
        return 0;
      }
  } /* End checking signature packet composition.  */

  if (sig->signers_uid)
    write_status_buffer (STATUS_NEWSIG,
                         sig->signers_uid, strlen (sig->signers_uid), 0);
  else
    write_status_text (STATUS_NEWSIG, NULL);

  astr = openpgp_pk_algo_name ( sig->pubkey_algo );
  issuer_fpr = issuer_fpr_string (sig);

  if (issuer_fpr)
    {
      log_info (_("Signature made %s\n"), asctimestamp(sig->timestamp));
      log_info (_("               using %s key %s\n"),
                astr? astr: "?", issuer_fpr);

    }
  else if (!keystrlen () || keystrlen () > 8)
    {
      log_info (_("Signature made %s\n"), asctimestamp(sig->timestamp));
      log_info (_("               using %s key %s\n"),
                astr? astr: "?", keystr(sig->keyid));
    }
  else /* Legacy format.  */
    log_info (_("Signature made %s using %s key ID %s\n"),
              asctimestamp(sig->timestamp), astr? astr: "?",
              keystr(sig->keyid));

  /* In verbose mode print the signers UID.  */
  if (sig->signers_uid)
    log_info (_("               issuer \"%s\"\n"), sig->signers_uid);

  rc = do_check_sig (c, node, extrahash, extrahashlen, NULL,
                     NULL, &is_expkey, &is_revkey, &pk);

  /* If the key is not found but the signature includes a key block we
   * use that key block for verification and on success import it.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && sig->flags.key_block
      && opt.flags.auto_key_import)
    {
      PKT_public_key *included_pk;
      const byte *kblock;
      size_t kblock_len;

      included_pk = xcalloc (1, sizeof *included_pk);
      kblock = parse_sig_subpkt (sig, 1, SIGSUBPKT_KEY_BLOCK, &kblock_len);
      if (kblock && kblock_len > 1
          && !get_pubkey_from_buffer (c->ctrl, included_pk,
                                      kblock+1, kblock_len-1,
                                      sig->keyid, &included_keyblock))
        {
          rc = do_check_sig (c, node, extrahash, extrahashlen, included_pk,
                             NULL, &is_expkey, &is_revkey, &pk);
          if (opt.verbose)
            log_debug ("checked signature using included key block: %s\n",
                       gpg_strerror (rc));
          if (!rc)
            {
              /* The keyblock has been verified, we now import it.  */
              rc = import_included_key_block (c->ctrl, included_keyblock);
            }

        }
      free_public_key (included_pk);
    }

  /* If the key isn't found, check for a preferred keyserver.  Note
   * that this is only done if honor-keyserver-url has been set.  We
   * test for this in the loop so that we can show info about the
   * preferred keyservers.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && sig->flags.pref_ks)
    {
      const byte *p;
      int seq = 0;
      size_t n;
      int any_pref_ks = 0;

      while ((p=enum_sig_subpkt (sig, 1, SIGSUBPKT_PREF_KS, &n, &seq, NULL)))
        {
          /* According to my favorite copy editor, in English grammar,
             you say "at" if the key is located on a web page, but
             "from" if it is located on a keyserver.  I'm not going to
             even try to make two strings here :) */
          log_info(_("Key available at: ") );
          print_utf8_buffer (log_get_stream(), p, n);
          log_printf ("\n");
          any_pref_ks = 1;

          if ((opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE)
              && (opt.keyserver_options.options&KEYSERVER_HONOR_KEYSERVER_URL))
            {
              struct keyserver_spec *spec;

              spec = parse_preferred_keyserver (sig);
              if (spec)
                {
                  int res;

                  if (DBG_LOOKUP)
                    log_debug ("trying auto-key-retrieve method %s\n",
                               "Pref-KS");

                  free_public_key (pk);
                  pk = NULL;
                  glo_ctrl.in_auto_key_retrieve++;
                  res = keyserver_import_keyid (c->ctrl, sig->keyid,spec,
                                                KEYSERVER_IMPORT_FLAG_QUICK);
                  glo_ctrl.in_auto_key_retrieve--;
                  if (!res)
                    rc = do_check_sig (c, node, extrahash, extrahashlen, NULL,
                                       NULL, &is_expkey, &is_revkey, &pk);
                  else if (DBG_LOOKUP)
                    log_debug ("lookup via %s failed: %s\n", "Pref-KS",
                               gpg_strerror (res));
                  free_keyserver_spec (spec);

                  if (!rc)
                    break;
                }
            }
        }

      if (any_pref_ks
          && (opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE)
          && !(opt.keyserver_options.options&KEYSERVER_HONOR_KEYSERVER_URL))
        log_info (_("Note: Use '%s' to make use of this info\n"),
                  "--keyserver-option honor-keyserver-url");
    }

  /* If the above methods didn't work, our next try is to retrieve the
   * key from the WKD.  This requires that WKD is in the AKL and the
   * Signer's UID is in the signature.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && (opt.keyserver_options.options & KEYSERVER_AUTO_KEY_RETRIEVE)
      && !opt.flags.disable_signer_uid
      && akl_has_wkd_method ()
      && sig->signers_uid)
    {
      int res;

      if (DBG_LOOKUP)
        log_debug ("trying auto-key-retrieve method %s\n", "WKD");
      free_public_key (pk);
      pk = NULL;
      glo_ctrl.in_auto_key_retrieve++;
      res = keyserver_import_wkd (c->ctrl, sig->signers_uid,
                                  KEYSERVER_IMPORT_FLAG_QUICK, NULL, NULL);
      glo_ctrl.in_auto_key_retrieve--;
      /* Fixme: If the fingerprint is embedded in the signature,
       * compare it to the fingerprint of the returned key.  */
      if (!res)
        rc = do_check_sig (c, node, extrahash, extrahashlen, NULL,
                           NULL, &is_expkey, &is_revkey, &pk);
      else if (DBG_LOOKUP)
        log_debug ("lookup via %s failed: %s\n", "WKD", gpg_strerror (res));
    }

  /* If the above methods didn't work, our next try is to locate
   * the key via its fingerprint from a keyserver.  This requires
   * that the signers fingerprint is encoded in the signature.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && (opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE)
      && keyserver_any_configured (c->ctrl))
    {
      int res;
      const byte *p;
      size_t n;

      p = issuer_fpr_raw (sig, &n);
      if (p)
        {
          if (DBG_LOOKUP)
            log_debug ("trying auto-key-retrieve method %s\n", "KS");

          /* v4 or v5 packet with a SHA-1/256 fingerprint.  */
          free_public_key (pk);
          pk = NULL;
          glo_ctrl.in_auto_key_retrieve++;
          res = keyserver_import_fprint (c->ctrl, p, n, opt.keyserver,
                                         KEYSERVER_IMPORT_FLAG_QUICK);
          glo_ctrl.in_auto_key_retrieve--;
          if (!res)
            rc = do_check_sig (c, node, extrahash, extrahashlen, NULL,
                               NULL, &is_expkey, &is_revkey, &pk);
          else if (DBG_LOOKUP)
            log_debug ("lookup via %s failed: %s\n", "KS", gpg_strerror (res));
        }
    }

  /* Do do something with the result of the signature checking.  */
  if (!rc || gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE)
    {
      /* We have checked the signature and the result is either a good
       * signature or a bad signature.  Further examination follows.  */
      kbnode_t un, keyblock;
      int count = 0;
      int keyblock_has_pk = 0;  /* For failsafe check.  */
      int statno;
      char keyid_str[50];
      PKT_public_key *mainpk = NULL;

      if (rc)
        statno = STATUS_BADSIG;
      else if (sig->flags.expired)
        statno = STATUS_EXPSIG;
      else if (is_expkey)
        statno = STATUS_EXPKEYSIG;
      else if(is_revkey)
        statno = STATUS_REVKEYSIG;
      else
        statno = STATUS_GOODSIG;

      /* FIXME: We should have the public key in PK and thus the
       * keyblock has already been fetched.  Thus we could use the
       * fingerprint or PK itself to lookup the entire keyblock.  That
       * would best be done with a cache.  */
      if (included_keyblock)
        {
          keyblock = included_keyblock;
          included_keyblock = NULL;
        }
      else
        keyblock = get_pubkeyblock_for_sig (c->ctrl, sig);

      snprintf (keyid_str, sizeof keyid_str, "%08lX%08lX [uncertain] ",
                (ulong)sig->keyid[0], (ulong)sig->keyid[1]);

      /* Find and print the primary user ID along with the
         "Good|Expired|Bad signature" line.  */
      for (un=keyblock; un; un = un->next)
        {
          int valid;

          if (!keyblock_has_pk
              && (un->pkt->pkttype == PKT_PUBLIC_KEY
                  || un->pkt->pkttype == PKT_PUBLIC_SUBKEY)
              && !cmp_public_keys (un->pkt->pkt.public_key, pk))
            {
              keyblock_has_pk = 1;
            }
          if (un->pkt->pkttype == PKT_PUBLIC_KEY)
            {
              mainpk = un->pkt->pkt.public_key;
              continue;
            }
          if (un->pkt->pkttype != PKT_USER_ID)
            continue;
          if (!un->pkt->pkt.user_id->created)
            continue;
          if (un->pkt->pkt.user_id->flags.revoked)
            continue;
          if (un->pkt->pkt.user_id->flags.expired)
            continue;
          if (!un->pkt->pkt.user_id->flags.primary)
            continue;
          /* We want the textual primary user ID here */
          if (un->pkt->pkt.user_id->attrib_data)
            continue;

          log_assert (mainpk);

	  /* Since this is just informational, don't actually ask the
	     user to update any trust information.  (Note: we register
	     the signature later.)  Because print_good_bad_signature
	     does not print a LF we need to compute the validity
	     before calling that function.  */
          if ((opt.verify_options & VERIFY_SHOW_UID_VALIDITY))
            valid = get_validity (c->ctrl, keyblock, mainpk,
                                  un->pkt->pkt.user_id, NULL, 0);
          else
            valid = 0; /* Not used.  */

          keyid_str[17] = 0; /* cut off the "[uncertain]" part */

          print_good_bad_signature (statno, keyid_str, un, sig, rc);

          if ((opt.verify_options & VERIFY_SHOW_UID_VALIDITY))
            log_printf (" [%s]\n",trust_value_to_string(valid));
          else
            log_printf ("\n");

          count++;
          /* At this point we could in theory stop because the primary
           * UID flag is never set for more than one User ID per
           * keyblock.  However, we use this loop also for a failsafe
           * check that the public key used to create the signature is
           * contained in the keyring.*/
	}

      log_assert (mainpk);
      if (!keyblock_has_pk)
        {
          log_error ("signature key lost from keyblock\n");
          rc = gpg_error (GPG_ERR_INTERNAL);
        }

      /* In case we did not found a valid textual userid above
         we print the first user id packet or a "[?]" instead along
         with the "Good|Expired|Bad signature" line.  */
      if (!count)
        {
          /* Try for an invalid textual userid */
          for (un=keyblock; un; un = un->next)
            {
              if (un->pkt->pkttype == PKT_USER_ID
                  && !un->pkt->pkt.user_id->attrib_data)
                break;
            }

          /* Try for any userid at all */
          if (!un)
            {
              for (un=keyblock; un; un = un->next)
                {
                  if (un->pkt->pkttype == PKT_USER_ID)
                    break;
		}
	    }

          if (opt.trust_model==TM_ALWAYS || !un)
            keyid_str[17] = 0; /* cut off the "[uncertain]" part */

          print_good_bad_signature (statno, keyid_str, un, sig, rc);

          if (opt.trust_model != TM_ALWAYS && un)
            log_printf (" %s",_("[uncertain]") );
          log_printf ("\n");
	}

      /* If we have a good signature and already printed
       * the primary user ID, print all the other user IDs */
      if (count
          && !rc
          && !(opt.verify_options & VERIFY_SHOW_PRIMARY_UID_ONLY))
        {
          char *p;
          for( un=keyblock; un; un = un->next)
            {
              if (un->pkt->pkttype != PKT_USER_ID)
                continue;
              if ((un->pkt->pkt.user_id->flags.revoked
                   || un->pkt->pkt.user_id->flags.expired)
                  && !(opt.verify_options & VERIFY_SHOW_UNUSABLE_UIDS))
                continue;
              /* Skip textual primary user ids which we printed above. */
              if (un->pkt->pkt.user_id->flags.primary
                  && !un->pkt->pkt.user_id->attrib_data )
                continue;

              /* If this user id has attribute data, print that.  */
              if (un->pkt->pkt.user_id->attrib_data)
                {
                  dump_attribs (un->pkt->pkt.user_id, mainpk);

                  if (opt.verify_options&VERIFY_SHOW_PHOTOS)
                    show_photos (c->ctrl,
                                 un->pkt->pkt.user_id->attribs,
                                 un->pkt->pkt.user_id->numattribs,
                                 mainpk ,un->pkt->pkt.user_id);
                }

              p = utf8_to_native (un->pkt->pkt.user_id->name,
				  un->pkt->pkt.user_id->len, 0);
              log_info (_("                aka \"%s\""), p);
              xfree (p);

              if ((opt.verify_options & VERIFY_SHOW_UID_VALIDITY))
                {
                  const char *valid;

                  if (un->pkt->pkt.user_id->flags.revoked)
                    valid = _("revoked");
                  else if (un->pkt->pkt.user_id->flags.expired)
                    valid = _("expired");
                  else
		    /* Since this is just informational, don't
		       actually ask the user to update any trust
		       information.  */
                    valid = (trust_value_to_string
                             (get_validity (c->ctrl, keyblock, mainpk,
                                            un->pkt->pkt.user_id, NULL, 0)));
                  log_printf (" [%s]\n",valid);
                }
              else
                log_printf ("\n");
            }
	}

      /* For good signatures print notation data.  */
      if (!rc)
        {
          if ((opt.verify_options & VERIFY_SHOW_POLICY_URLS))
            show_policy_url (sig, 0, 1);
          else
            show_policy_url (sig, 0, 2);

          if ((opt.verify_options & VERIFY_SHOW_KEYSERVER_URLS))
            show_keyserver_url (sig, 0, 1);
          else
            show_keyserver_url (sig, 0, 2);

          if ((opt.verify_options & VERIFY_SHOW_NOTATIONS))
            show_notation
              (sig, 0, 1,
               (((opt.verify_options&VERIFY_SHOW_STD_NOTATIONS)?1:0)
                + ((opt.verify_options&VERIFY_SHOW_USER_NOTATIONS)?2:0)));
          else
            show_notation (sig, 0, 2, 0);
        }

      /* Fill PKSTRBUF with the algostring in case we later need it.  */
      if (pk)
        pubkey_string (pk, pkstrbuf, sizeof pkstrbuf);

      /* For good signatures print the VALIDSIG status line.  */
      if (!rc && (is_status_enabled ()
                  || opt.assert_signer_list
                  || opt.assert_pubkey_algos) && pk)
        {
          char pkhex[MAX_FINGERPRINT_LEN*2+1];
          char mainpkhex[MAX_FINGERPRINT_LEN*2+1];

          hexfingerprint (pk, pkhex, sizeof pkhex);
          hexfingerprint (mainpk, mainpkhex, sizeof mainpkhex);

          /* TODO: Replace the reserved '0' in the field below with
             bits for status flags (policy url, notation, etc.).  */
          write_status_printf (STATUS_VALIDSIG,
                               "%s %s %lu %lu %d 0 %d %d %02X %s",
                               pkhex,
                               strtimestamp (sig->timestamp),
                               (ulong)sig->timestamp,
                               (ulong)sig->expiredate,
                               sig->version, sig->pubkey_algo,
                               sig->digest_algo,
                               sig->sig_class,
                               mainpkhex);
          /* Handle the --assert-signer option.  */
          check_assert_signer_list (mainpkhex, pkhex);
          /* Handle the --assert-pubkey-algo option.  */
          check_assert_pubkey_algo (pkstrbuf, pkhex);
	}

      /* Print compliance warning for Good signatures.  */
      if (!rc && pk && !opt.quiet
          && !gnupg_pk_is_compliant (opt.compliance, pk->pubkey_algo, 0,
                                     pk->pkey, nbits_from_pk (pk), NULL))
        {
          log_info (_("WARNING: This key is not suitable for signing"
                      " in %s mode\n"),
                    gnupg_compliance_option_string (opt.compliance));
        }

      /* For good signatures compute and print the trust information.
         Note that in the Tofu trust model this may ask the user on
         how to resolve a conflict.  */
      if (!rc)
        {
          rc = check_signatures_trust (c->ctrl, keyblock, pk, sig);
        }

      /* Print extra information about the signature.  */
      if (sig->flags.expired)
        {
          log_info (_("Signature expired %s\n"), asctimestamp(sig->expiredate));
          if (!rc)
            rc = gpg_error (GPG_ERR_GENERAL); /* Need a better error here?  */
        }
      else if (sig->expiredate)
        log_info (_("Signature expires %s\n"), asctimestamp(sig->expiredate));

      if (opt.verbose)
        {
          log_info (_("%s signature, digest algorithm %s%s%s\n"),
                    sig->sig_class==0x00?_("binary"):
                    sig->sig_class==0x01?_("textmode"):_("unknown"),
                    gcry_md_algo_name (sig->digest_algo),
                    *pkstrbuf?_(", key algorithm "):"", pkstrbuf);
        }

      /* Print final warnings.  */
      if (!rc && !c->signed_data.used)
        {
          /* Signature is basically good but we test whether the
             deprecated command
               gpg --verify FILE.sig
             was used instead of
               gpg --verify FILE.sig FILE
             to verify a detached signature.  If we figure out that a
             data file with a matching name exists, we print a warning.

             The problem is that the first form would also verify a
             standard signature.  This behavior could be used to
             create a made up .sig file for a tarball by creating a
             standard signature from a valid detached signature packet
             (for example from a signed git tag).  Then replace the
             sig file on the FTP server along with a changed tarball.
             Using the first form the verify command would correctly
             verify the signature but don't even consider the tarball.  */
          kbnode_t n;
          char *dfile;

          dfile = get_matching_datafile (c->sigfilename);
          if (dfile)
            {
              for (n = c->list; n; n = n->next)
                if (n->pkt->pkttype != PKT_SIGNATURE)
                  break;
              if (n)
                {
                  /* Not only signature packets in the tree thus this
                     is not a detached signature.  */
                  log_info (_("WARNING: not a detached signature; "
                              "file '%s' was NOT verified!\n"), dfile);
                  assert_signer_true = 0;
                }
              xfree (dfile);
            }
        }

      /* Compute compliance with CO_DE_VS.  */
      if (pk
          && gnupg_gcrypt_is_compliant (CO_DE_VS)
          && gnupg_pk_is_compliant (CO_DE_VS, pk->pubkey_algo, 0, pk->pkey,
                                    nbits_from_pk (pk), NULL)
          && gnupg_digest_is_compliant (CO_DE_VS, sig->digest_algo))
        write_status_strings (STATUS_VERIFICATION_COMPLIANCE_MODE,
                              gnupg_status_compliance_flag (CO_DE_VS),
                              NULL);
      else if (opt.flags.require_compliance
               && opt.compliance == CO_DE_VS)
        {
          log_error (_("operation forced to fail due to"
                       " unfulfilled compliance rules\n"));
          if (!rc)
            rc = gpg_error (GPG_ERR_FORBIDDEN);
        }


      free_public_key (pk);
      pk = NULL;
      release_kbnode( keyblock );
      if (rc)
        g10_errors_seen = 1;
      if (opt.batch && rc)
        g10_exit (1);
    }
  else  /* Error checking the signature. (neither Good nor Bad).  */
    {
      write_status_printf (STATUS_ERRSIG, "%08lX%08lX %d %d %02x %lu %d %s",
                           (ulong)sig->keyid[0], (ulong)sig->keyid[1],
                           sig->pubkey_algo, sig->digest_algo,
                           sig->sig_class, (ulong)sig->timestamp,
                           gpg_err_code (rc),
                           issuer_fpr? issuer_fpr:"-");
      if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY)
        {
          write_status_printf (STATUS_NO_PUBKEY, "%08lX%08lX",
                               (ulong)sig->keyid[0], (ulong)sig->keyid[1]);
	}
      if (gpg_err_code (rc) != GPG_ERR_NOT_PROCESSED)
        log_error (_("Can't check signature: %s\n"), gpg_strerror (rc));
    }

  free_public_key (pk);
  release_kbnode (included_keyblock);
  xfree (issuer_fpr);
  return rc;
}


/*
 * Process the tree which starts at node
 */
static void
proc_tree (CTX c, kbnode_t node)
{
  kbnode_t n1;
  int rc;

  if (opt.list_packets || opt.list_only)
    return;

  /* We must skip our special plaintext marker packets here because
     they may be the root packet.  These packets are only used in
     additional checks and skipping them here doesn't matter.  */
  while (node
         && node->pkt->pkttype == PKT_GPG_CONTROL
          && node->pkt->pkt.gpg_control->control == CTRLPKT_PLAINTEXT_MARK)
    {
      node = node->next;
    }
  if (!node)
    return;

  c->trustletter = ' ';
  if (node->pkt->pkttype == PKT_PUBLIC_KEY
      || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
    {
      merge_keys_and_selfsig (c->ctrl, node);
      list_node (c, node);
    }
  else if (node->pkt->pkttype == PKT_SECRET_KEY)
    {
      merge_keys_and_selfsig (c->ctrl, node);
      list_node (c, node);
    }
  else if (node->pkt->pkttype == PKT_ONEPASS_SIG)
    {
      /* Check all signatures.  */
      if (!c->any.data)
        {
          int use_textmode = 0;

          free_md_filter_context (&c->mfx);
          /* Prepare to create all requested message digests.  */
          rc = gcry_md_open (&c->mfx.md, 0, 0);
          if (rc)
            goto hash_err;

          /* Fixme: why looking for the signature packet and not the
             one-pass packet?  */
          for (n1 = node; (n1 = find_next_kbnode (n1, PKT_SIGNATURE));)
            gcry_md_enable (c->mfx.md, n1->pkt->pkt.signature->digest_algo);

          if (n1 && n1->pkt->pkt.onepass_sig->sig_class == 0x01)
            use_textmode = 1;

          /* Ask for file and hash it. */
          if (c->sigs_only)
            {
              if (c->signed_data.used && c->signed_data.data_fd != -1)
                rc = hash_datafile_by_fd (c->mfx.md, NULL,
                                          c->signed_data.data_fd,
                                          use_textmode);
              else
                rc = hash_datafiles (c->mfx.md, NULL,
                                     c->signed_data.data_names,
                                     c->sigfilename,
                                     use_textmode);
	    }
          else
            {
              rc = ask_for_detached_datafile (c->mfx.md, NULL,
                                              iobuf_get_real_fname (c->iobuf),
                                              use_textmode);
	    }

        hash_err:
          if (rc)
            {
              log_error ("can't hash datafile: %s\n", gpg_strerror (rc));
              return;
	    }
	}
      else if (c->signed_data.used)
        {
          log_error (_("not a detached signature\n"));
          return;
        }

      for (n1 = node; (n1 = find_next_kbnode (n1, PKT_SIGNATURE));)
        check_sig_and_print (c, n1);

    }
  else if (node->pkt->pkttype == PKT_GPG_CONTROL
           && node->pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START)
    {
      /* Clear text signed message.  */
      if (!c->any.data)
        {
          log_error ("cleartext signature without data\n");
          return;
        }
      else if (c->signed_data.used)
        {
          log_error (_("not a detached signature\n"));
          return;
        }

      for (n1 = node; (n1 = find_next_kbnode (n1, PKT_SIGNATURE));)
        check_sig_and_print (c, n1);

    }
  else if (node->pkt->pkttype == PKT_SIGNATURE)
    {
      PKT_signature *sig = node->pkt->pkt.signature;
      int multiple_ok = 1;

      n1 = find_next_kbnode (node, PKT_SIGNATURE);
      if (n1)
        {
          byte class = sig->sig_class;
          byte hash  = sig->digest_algo;

          for (; n1; (n1 = find_next_kbnode(n1, PKT_SIGNATURE)))
            {
              /* We can't currently handle multiple signatures of
               * different classes (we'd pretty much have to run a
               * different hash context for each), but if they are all
               * the same and it is detached signature, we make an
               * exception.  Note that the old code also disallowed
               * multiple signatures if the digest algorithms are
               * different.  We softened this restriction only for
               * detached signatures, to be on the safe side. */
              if (n1->pkt->pkt.signature->sig_class != class
                  || (c->any.data
                      && n1->pkt->pkt.signature->digest_algo != hash))
                {
                  multiple_ok = 0;
                  log_info (_("WARNING: multiple signatures detected.  "
                              "Only the first will be checked.\n"));
                  break;
                }
            }
        }

      if (sig->sig_class != 0x00 && sig->sig_class != 0x01)
        {
          log_info(_("standalone signature of class 0x%02x\n"), sig->sig_class);
        }
      else if (!c->any.data)
        {
          /* Detached signature */
          free_md_filter_context (&c->mfx);
          rc = gcry_md_open (&c->mfx.md, sig->digest_algo, 0);
          if (rc)
            goto detached_hash_err;

          if (multiple_ok)
            {
              /* If we have and want to handle multiple signatures we
               * need to enable all hash algorithms for the context.  */
              for (n1 = node; (n1 = find_next_kbnode (n1, PKT_SIGNATURE)); )
                if (!openpgp_md_test_algo (n1->pkt->pkt.signature->digest_algo))
                  gcry_md_enable (c->mfx.md,
                                  map_md_openpgp_to_gcry
                                  (n1->pkt->pkt.signature->digest_algo));
            }

          if (RFC2440 || RFC4880)
            ; /* Strict RFC mode.  */
          else if (sig->digest_algo == DIGEST_ALGO_SHA1
                   && sig->pubkey_algo == PUBKEY_ALGO_DSA
                   && sig->sig_class == 0x01)
            {
              /* Enable a workaround for a pgp5 bug when the detached
               * signature has been created in textmode.  Note that we
               * do not implement this for multiple signatures with
               * different hash algorithms. */
              rc = gcry_md_open (&c->mfx.md2, sig->digest_algo, 0);
              if (rc)
                goto detached_hash_err;
	    }

          /* Here we used to have another hack to work around a pgp
           * 2 bug: It worked by not using the textmode for detached
           * signatures; this would let the first signature check
           * (on md) fail but the second one (on md2), which adds an
           * extra CR would then have produced the "correct" hash.
           * This is very, very ugly hack but it may haved help in
           * some cases (and break others).
           *	 c->mfx.md2? 0 :(sig->sig_class == 0x01)
           */

          if (DBG_HASHING)
            {
              gcry_md_debug (c->mfx.md, "verify");
              if (c->mfx.md2)
                gcry_md_debug (c->mfx.md2, "verify2");
            }

          if (c->sigs_only)
            {
              if (c->signed_data.used && c->signed_data.data_fd != -1)
                rc = hash_datafile_by_fd (c->mfx.md, c->mfx.md2,
                                          c->signed_data.data_fd,
                                          (sig->sig_class == 0x01));
              else
                rc = hash_datafiles (c->mfx.md, c->mfx.md2,
                                     c->signed_data.data_names,
                                     c->sigfilename,
                                     (sig->sig_class == 0x01));
	    }
          else
            {
              rc = ask_for_detached_datafile (c->mfx.md, c->mfx.md2,
                                              iobuf_get_real_fname(c->iobuf),
                                              (sig->sig_class == 0x01));
	    }

        detached_hash_err:
          if (rc)
            {
              log_error ("can't hash datafile: %s\n", gpg_strerror (rc));
              return;
	    }
	}
      else if (c->signed_data.used)
        {
          log_error (_("not a detached signature\n"));
          return;
        }
      else if (!opt.quiet)
        log_info (_("old style (PGP 2.x) signature\n"));

      if (multiple_ok)
        {
          for (n1 = node; n1; (n1 = find_next_kbnode(n1, PKT_SIGNATURE)))
	    check_sig_and_print (c, n1);
        }
      else
        check_sig_and_print (c, node);

    }
  else
    {
      dump_kbnode (c->list);
      log_error ("invalid root packet detected in proc_tree()\n");
      dump_kbnode (node);
    }
}
