/* mainproc.c - handle packets
 * Copyright (C) 1998-2009 Free Software Foundation, Inc.
 * Copyright (C) 2013-2014 Werner Koch
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

/* Put an upper limit on nested packets.  The 32 is an arbitrary
   value, a much lower should actually be sufficient.  */
#define MAX_NESTING_DEPTH 32


/* An object to build a list of keyid related info.  */
struct kidlist_item
{
  struct kidlist_item *next;
  u32 kid[2];
  int pubkey_algo;
  int reason;
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
  ulong symkeys;
  struct kidlist_item *pkenc_list; /* List of encryption packets. */
  struct {
    unsigned int sig_seen:1;      /* Set to true if a signature packet
                                     has been seen. */
    unsigned int data:1;          /* Any data packet seen */
    unsigned int uncompress_failed:1;
  } any;
};


/*** Local prototypes.  ***/
static int do_proc_packets (ctrl_t ctrl, CTX c, iobuf_t a);
static void list_node (CTX c, kbnode_t node);
static void proc_tree (CTX c, kbnode_t node);
static int literals_seen;


/*** Functions.  ***/


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
      struct kidlist_item *tmp = c->pkenc_list->next;
      xfree (c->pkenc_list);
      c->pkenc_list = tmp;
    }
  c->pkenc_list = NULL;
  c->list = NULL;
  c->any.data = 0;
  c->any.uncompress_failed = 0;
  c->last_was_session_key = 0;
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

static int
symkey_decrypt_seskey (DEK *dek, byte *seskey, size_t slen)
{
  gcry_cipher_hd_t hd;

  if(slen < 17 || slen > 33)
    {
      log_error ( _("weird size for an encrypted session key (%d)\n"),
		  (int)slen);
      return GPG_ERR_BAD_KEY;
    }

  if (openpgp_cipher_open (&hd, dek->algo, GCRY_CIPHER_MODE_CFB, 1))
      BUG ();
  if (gcry_cipher_setkey ( hd, dek->key, dek->keylen ))
    BUG ();
  gcry_cipher_setiv ( hd, NULL, 0 );
  gcry_cipher_decrypt ( hd, seskey, slen, NULL, 0 );
  gcry_cipher_close ( hd );

  /* Now we replace the dek components with the real session key to
     decrypt the contents of the sequencing packet. */

  dek->keylen=slen-1;
  dek->algo=seskey[0];

  if(dek->keylen > DIM(dek->key))
    BUG ();

  memcpy(dek->key, seskey + 1, dek->keylen);

  /*log_hexdump( "thekey", dek->key, dek->keylen );*/

  return 0;
}


static void
proc_symkey_enc (CTX c, PACKET *pkt)
{
  PKT_symkey_enc *enc;

  enc = pkt->pkt.symkey_enc;
  if (!enc)
    log_error ("invalid symkey encrypted packet\n");
  else if(!c->dek)
    {
      int algo = enc->cipher_algo;
      const char *s = openpgp_cipher_algo_name (algo);

      if (!openpgp_cipher_test_algo (algo))
        {
          if (!opt.quiet)
            {
              if (enc->seskeylen)
                log_info (_("%s encrypted session key\n"), s );
              else
                log_info (_("%s encrypted data\n"), s );
            }
        }
      else
        log_error (_("encrypted with unknown algorithm %d\n"), algo);

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
          c->dek = passphrase_to_dek (algo, &enc->s2k, 0, 0, NULL, NULL);
          if (c->dek)
            {
              c->dek->symmetric = 1;

              /* FIXME: This doesn't work perfectly if a symmetric key
                 comes before a public key in the message - if the
                 user doesn't know the passphrase, then there is a
                 chance that the "decrypted" algorithm will happen to
                 be a valid one, which will make the returned dek
                 appear valid, so we won't try any public keys that
                 come later. */
              if (enc->seskeylen)
                {
                  if (symkey_decrypt_seskey (c->dek,
                                             enc->seskey, enc->seskeylen))
                    {
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
  c->symkeys++;
  free_packet (pkt, NULL);
}


static void
proc_pubkey_enc (ctrl_t ctrl, CTX c, PACKET *pkt)
{
  PKT_pubkey_enc *enc;
  int result = 0;

  /* Check whether the secret key is available and store in this case.  */
  c->last_was_session_key = 1;
  enc = pkt->pkt.pubkey_enc;
  /*printf("enc: encrypted by a pubkey with keyid %08lX\n", enc->keyid[1] );*/
  /* Hmmm: why do I have this algo check here - anyway there is
   * function to check it. */
  if (opt.verbose)
    log_info (_("public key is %s\n"), keystr (enc->keyid));

  if (is_status_enabled())
    {
      char buf[50];
      /* FIXME: For ECC support we need to map the OpenPGP algo number
         to the Libgcrypt defined one.  This is due a chicken-egg
         problem: We need to have code in Libgcrypt for a new
         algorithm so to implement a proposed new algorithm before the
         IANA will finally assign an OpenPGP identifier.  */
      snprintf (buf, sizeof buf, "%08lX%08lX %d 0",
		(ulong)enc->keyid[0], (ulong)enc->keyid[1], enc->pubkey_algo);
      write_status_text (STATUS_ENC_TO, buf);
    }

  if (!opt.list_only && opt.override_session_key)
    {
      /* It does not make much sense to store the session key in
       * secure memory because it has already been passed on the
       * command line and the GCHQ knows about it.  */
      c->dek = xmalloc_clear (sizeof *c->dek);
      result = get_override_session_key (c->dek, opt.override_session_key);
      if (result)
        {
          xfree (c->dek);
          c->dek = NULL;
	}
    }
  else if (enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E
           || enc->pubkey_algo == PUBKEY_ALGO_ECDH
           || enc->pubkey_algo == PUBKEY_ALGO_RSA
           || enc->pubkey_algo == PUBKEY_ALGO_RSA_E
           || enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL)
    {
      /* Note that we also allow type 20 Elgamal keys for decryption.
         There are still a couple of those keys in active use as a
         subkey.  */

      /* FIXME: Store this all in a list and process it later so that
         we can prioritize what key to use.  This gives a better user
         experience if wildcard keyids are used.  */
      if  (!c->dek && ((!enc->keyid[0] && !enc->keyid[1])
                       || opt.try_all_secrets
                       || have_secret_key_with_kid (enc->keyid)))
        {
          if(opt.list_only)
            result = -1;
          else
            {
              c->dek = xmalloc_secure_clear (sizeof *c->dek);
              if ((result = get_session_key (ctrl, enc, c->dek)))
                {
                  /* Error: Delete the DEK. */
                  xfree (c->dek);
                  c->dek = NULL;
		}
	    }
	}
      else
        result = GPG_ERR_NO_SECKEY;
    }
  else
    result = GPG_ERR_PUBKEY_ALGO;

  if (result == -1)
    ;
  else
    {
      /* Store it for later display.  */
      struct kidlist_item *x = xmalloc (sizeof *x);
      x->kid[0] = enc->keyid[0];
      x->kid[1] = enc->keyid[1];
      x->pubkey_algo = enc->pubkey_algo;
      x->reason = result;
      x->next = c->pkenc_list;
      c->pkenc_list = x;

      if (!result && opt.verbose > 1)
        log_info (_("public key encrypted data: good DEK\n"));
    }

  free_packet(pkt, NULL);
}


/*
 * Print the list of public key encrypted packets which we could
 * not decrypt.
 */
static void
print_pkenc_list (ctrl_t ctrl, struct kidlist_item *list, int failed)
{
  for (; list; list = list->next)
    {
      PKT_public_key *pk;
      const char *algstr;

      if (failed && !list->reason)
        continue;
      if (!failed && list->reason)
        continue;

      algstr = openpgp_pk_algo_name (list->pubkey_algo);
      pk = xmalloc_clear (sizeof *pk);

      if (!algstr)
        algstr = "[?]";
      pk->pubkey_algo = list->pubkey_algo;
      if (!get_pubkey (ctrl, pk, list->kid))
        {
          char *p;
          log_info (_("encrypted with %u-bit %s key, ID %s, created %s\n"),
                    nbits_from_pk (pk), algstr, keystr_from_pk(pk),
                    strtimestamp (pk->timestamp));
          p = get_user_id_native (ctrl, list->kid);
          log_printf (_("      \"%s\"\n"), p);
          xfree (p);
        }
      else
        log_info (_("encrypted with %s key, ID %s\n"),
                  algstr, keystr(list->kid));

      free_public_key (pk);

      if (gpg_err_code (list->reason) == GPG_ERR_NO_SECKEY)
        {
          if (is_status_enabled())
            {
              char buf[20];
              snprintf (buf, sizeof buf, "%08lX%08lX",
                        (ulong)list->kid[0], (ulong)list->kid[1]);
              write_status_text (STATUS_NO_SECKEY, buf);
	    }
	}
      else if (list->reason)
        {
          log_info (_("public key decryption failed: %s\n"),
                    gpg_strerror (list->reason));
          write_status_error ("pkdecrypt_failed", list->reason);
        }
    }
}


static void
proc_encrypted (CTX c, PACKET *pkt)
{
  int result = 0;

  if (!opt.quiet)
    {
      if (c->symkeys>1)
        log_info (_("encrypted with %lu passphrases\n"), c->symkeys);
      else if (c->symkeys == 1)
        log_info (_("encrypted with 1 passphrase\n"));
      print_pkenc_list (c->ctrl, c->pkenc_list, 1 );
      print_pkenc_list (c->ctrl, c->pkenc_list, 0 );
    }

  /* FIXME: Figure out the session key by looking at all pkenc packets. */

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

          c->dek = passphrase_to_dek (algo, s2k, 0, 0, NULL, &canceled);
          if (c->dek)
            c->dek->algo_info_printed = 1;
          else if (canceled)
            result = gpg_error (GPG_ERR_CANCELED);
          else
            result = gpg_error (GPG_ERR_INV_PASSPHRASE);
        }
    }
  else if (!c->dek)
    result = GPG_ERR_NO_SECKEY;

  if (!result)
    result = decrypt_data (c->ctrl, c, pkt->pkt.encrypted, c->dek );

  if (result == -1)
    ;
  else if (!result
           && !opt.ignore_mdc_error
           && !pkt->pkt.encrypted->mdc_method
           && openpgp_cipher_get_algo_blklen (c->dek->algo) != 8
           && c->dek->algo != CIPHER_ALGO_TWOFISH)
    {
      /* The message has been decrypted but has no MDC despite that a
         modern cipher (blocklength != 64 bit, except for Twofish) is
         used and the option to ignore MDC errors is not used: To
         avoid attacks changing an MDC message to a non-MDC message,
         we fail here.  */
      log_error (_("WARNING: message was not integrity protected\n"));
      if (opt.verbose > 1)
        log_info ("decryption forced to fail\n");
      write_status (STATUS_DECRYPTION_FAILED);
    }
  else if (!result || (gpg_err_code (result) == GPG_ERR_BAD_SIGNATURE
                       && opt.ignore_mdc_error))
    {
      write_status (STATUS_DECRYPTION_OKAY);
      if (opt.verbose > 1)
        log_info(_("decryption okay\n"));
      if (pkt->pkt.encrypted->mdc_method && !result)
        write_status (STATUS_GOODMDC);
      else if (!opt.no_mdc_warn)
        log_info (_("WARNING: message was not integrity protected\n"));
    }
  else if (gpg_err_code (result) == GPG_ERR_BAD_SIGNATURE)
    {
      glo_ctrl.lasterr = result;
      log_error (_("WARNING: encrypted message has been manipulated!\n"));
      write_status (STATUS_BADMDC);
      write_status (STATUS_DECRYPTION_FAILED);
    }
  else
    {
      if (gpg_err_code (result) == GPG_ERR_BAD_KEY
          && *c->dek->s2k_cacheid != '\0')
        {
          if (opt.debug)
            log_debug ("cleared passphrase cached with ID: %s\n",
                       c->dek->s2k_cacheid);
          passphrase_clear_cache (c->dek->s2k_cacheid);
        }
      glo_ctrl.lasterr = result;
      write_status (STATUS_DECRYPTION_FAILED);
      log_error (_("decryption failed: %s\n"), gpg_strerror (result));
      /* Hmmm: does this work when we have encrypted using multiple
       * ways to specify the session key (symmmetric and PK). */
    }

  xfree (c->dek);
  c->dek = NULL;
  free_packet (pkt, NULL);
  c->last_was_session_key = 0;
  write_status (STATUS_END_DECRYPTION);
}


static void
proc_plaintext( CTX c, PACKET *pkt )
{
  PKT_plaintext *pt = pkt->pkt.plaintext;
  int any, clearsig, rc;
  kbnode_t n;

  literals_seen++;

  if (pt->namelen == 8 && !memcmp( pt->name, "_CONSOLE", 8))
    log_info (_("Note: sender requested \"for-your-eyes-only\"\n"));
  else if (opt.verbose)
    log_info (_("original file name='%.*s'\n"), pt->namelen, pt->name);

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
              gcry_md_enable (c->mfx.md, n->pkt->pkt.onepass_sig->digest_algo);
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
            gcry_md_enable (c->mfx.md, *data);
          any = 1;
          break;  /* Stop here as one-pass signature packets are not
                     expected.  */
        }
      else if (n->pkt->pkttype == PKT_SIGNATURE)
        {
          /* The SIG+LITERAL case that PGP used to use.  */
          gcry_md_enable ( c->mfx.md, n->pkt->pkt.signature->digest_algo );
          any = 1;
        }
    }

  if (!any && !opt.skip_verify)
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

      if (!opt.flags.allow_multiple_messages)
        {
          write_status_text (STATUS_ERROR, "proc_pkt.plaintext 89_BAD_DATA");
          log_inc_errorcount ();
          rc = gpg_error (GPG_ERR_UNEXPECTED);
        }
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

  free_packet (pkt, NULL);
  c->last_was_session_key = 0;

  /* We add a marker control packet instead of the plaintext packet.
   * This is so that we can later detect invalid packet sequences.  */
  n = new_kbnode (create_gpg_control (CTRLPKT_PLAINTEXT_MARK, NULL, 0));
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
 * used to verify the signature will be stored tehre, or NULL if not
 * found.  Returns: 0 = valid signature or an error code
 */
static int
do_check_sig (CTX c, kbnode_t node, int *is_selfsig,
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
  rc = check_signature2 (c->ctrl, sig, md, NULL, is_expkey, is_revkey, r_pk);
  if (! rc)
    md_good = md;
  else if (gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE && md2)
    {
      PKT_public_key *pk2;

      rc = check_signature2 (c->ctrl, sig, md2, NULL, is_expkey, is_revkey,
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
          rc2 = do_check_sig (c, node, &is_selfsig, NULL, NULL, NULL);
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
          p = get_user_id (c->ctrl, sig->keyid, &n);
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
  rc = do_proc_packets (ctrl, c, a);
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
  rc = do_proc_packets (ctrl, c, a);

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

  rc = do_proc_packets (ctrl, c, a);

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
  rc = do_proc_packets (ctrl, c, a);
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
do_proc_packets (ctrl_t ctrl, CTX c, iobuf_t a)
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
            case PKT_PUBKEY_ENC:    proc_pubkey_enc (ctrl, c, pkt); break;
            case PKT_SYMKEY_ENC:    proc_symkey_enc (c, pkt); break;
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC: proc_encrypted (c, pkt); break;
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
            case PKT_PUBKEY_ENC:  proc_pubkey_enc (ctrl, c, pkt); break;
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC: proc_encrypted (c, pkt); break;
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
            case PKT_PUBKEY_ENC:  proc_pubkey_enc (ctrl, c, pkt); break;
            case PKT_SYMKEY_ENC:  proc_symkey_enc (c, pkt); break;
            case PKT_ENCRYPTED:
            case PKT_ENCRYPTED_MDC: proc_encrypted (c, pkt); break;
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


/* Helper for pka_uri_from_sig to parse the to-be-verified address out
   of the notation data. */
static pka_info_t *
get_pka_address (PKT_signature *sig)
{
  pka_info_t *pka = NULL;
  struct notation *nd,*notation;

  notation=sig_to_notation(sig);

  for(nd=notation;nd;nd=nd->next)
    {
      if(strcmp(nd->name,"pka-address@gnupg.org")!=0)
        continue; /* Not the notation we want. */

      /* For now we only use the first valid PKA notation. In future
	 we might want to keep additional PKA notations in a linked
	 list. */
      if (is_valid_mailbox (nd->value))
	{
	  pka = xmalloc (sizeof *pka + strlen(nd->value));
	  pka->valid = 0;
	  pka->checked = 0;
	  pka->uri = NULL;
	  strcpy (pka->email, nd->value);
	  break;
	}
    }

  free_notation(notation);

  return pka;
}


/* Return the URI from a DNS PKA record.  If this record has already
   be retrieved for the signature we merely return it; if not we go
   out and try to get that DNS record. */
static const char *
pka_uri_from_sig (CTX c, PKT_signature *sig)
{
  if (!sig->flags.pka_tried)
    {
      log_assert (!sig->pka_info);
      sig->flags.pka_tried = 1;
      sig->pka_info = get_pka_address (sig);
      if (sig->pka_info)
        {
          char *url;
          unsigned char *fpr;
          size_t fprlen;

          if (!gpg_dirmngr_get_pka (c->ctrl, sig->pka_info->email,
                                    &fpr, &fprlen, &url))
            {
              if (fpr && fprlen == sizeof sig->pka_info->fpr)
                {
                  memcpy (sig->pka_info->fpr, fpr, fprlen);
                  if (url)
                    {
                      sig->pka_info->valid = 1;
                      if (!*url)
                        xfree (url);
                      else
                        sig->pka_info->uri = url;
                      url = NULL;
                    }
                }
              xfree (fpr);
              xfree (url);
            }
        }
    }
  return sig->pka_info? sig->pka_info->uri : NULL;
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


/* Return the ISSUER fingerprint string in human readbale format if
 * available.  Caller must release the string.  */
static char *
issuer_fpr_string (PKT_signature *sig)
{
  const byte *p;
  size_t n;

  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_ISSUER_FPR, &n);
  if (p && n == 21 && p[0] == 4)
    return bin2hex (p+1, n-1, NULL);
  return NULL;
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
  int rc;
  int is_expkey = 0;
  int is_revkey = 0;
  char *issuer_fpr;
  PKT_public_key *pk = NULL;  /* The public key for the signature or NULL. */

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
        for (n_sig=0, n = n->next;
             n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
          n_sig++;
        if (!n_sig)
          goto ambiguous;

	/* If we wanted to disallow multiple sig verification, we'd do
	   something like this:

	   if (n && !opt.allow_multisig_verification)
             goto ambiguous;

	   However, now that we have --allow-multiple-messages, this
	   can stay allowable as we can't get here unless multiple
	   messages (i.e. multiple literals) are allowed. */

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
  }

  if (sig->signers_uid)
    write_status_buffer (STATUS_NEWSIG,
                         sig->signers_uid, strlen (sig->signers_uid), 0);
  else
    write_status_text (STATUS_NEWSIG, NULL);

  astr = openpgp_pk_algo_name ( sig->pubkey_algo );
  if ((issuer_fpr = issuer_fpr_string (sig)))
    {
      log_info (_("Signature made %s\n"), asctimestamp(sig->timestamp));
      log_info (_("               using %s key %s\n"),
                astr? astr: "?", issuer_fpr);

      xfree (issuer_fpr);
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

  rc = do_check_sig (c, node, NULL, &is_expkey, &is_revkey, &pk);

  /* If the key isn't found, check for a preferred keyserver.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY && sig->flags.pref_ks)
    {
      const byte *p;
      int seq = 0;
      size_t n;

      while ((p=enum_sig_subpkt (sig->hashed,SIGSUBPKT_PREF_KS,&n,&seq,NULL)))
        {
          /* According to my favorite copy editor, in English grammar,
             you say "at" if the key is located on a web page, but
             "from" if it is located on a keyserver.  I'm not going to
             even try to make two strings here :) */
          log_info(_("Key available at: ") );
          print_utf8_buffer (log_get_stream(), p, n);
          log_printf ("\n");

          if (opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE
              && opt.keyserver_options.options&KEYSERVER_HONOR_KEYSERVER_URL)
            {
              struct keyserver_spec *spec;

              spec = parse_preferred_keyserver (sig);
              if (spec)
                {
                  int res;

                  free_public_key (pk);
                  pk = NULL;
                  glo_ctrl.in_auto_key_retrieve++;
                  res = keyserver_import_keyid (c->ctrl, sig->keyid,spec, 1);
                  glo_ctrl.in_auto_key_retrieve--;
                  if (!res)
                    rc = do_check_sig (c, node, NULL,
                                       &is_expkey, &is_revkey, &pk);
                  free_keyserver_spec (spec);

                  if (!rc)
                    break;
                }
            }
        }
    }

  /* If the avove methods didn't work, our next try is to use the URI
   * from a DNS PKA record.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && (opt.keyserver_options.options & KEYSERVER_AUTO_KEY_RETRIEVE)
      && (opt.keyserver_options.options & KEYSERVER_HONOR_PKA_RECORD))
    {
      const char *uri = pka_uri_from_sig (c, sig);

      if (uri)
        {
          /* FIXME: We might want to locate the key using the
             fingerprint instead of the keyid. */
          int res;
          struct keyserver_spec *spec;

          spec = parse_keyserver_uri (uri, 1);
          if (spec)
            {
              free_public_key (pk);
              pk = NULL;
              glo_ctrl.in_auto_key_retrieve++;
              res = keyserver_import_keyid (c->ctrl, sig->keyid, spec, 1);
              glo_ctrl.in_auto_key_retrieve--;
              free_keyserver_spec (spec);
              if (!res)
                rc = do_check_sig (c, node, NULL, &is_expkey, &is_revkey, &pk);
            }
        }
    }

  /* If the above methods didn't work, our next try is to locate
   * the key via its fingerprint from a keyserver.  This requires
   * that the signers fingerprint is encoded in the signature.  We
   * favor this over the WKD method (to be tried next), because an
   * arbitrary keyserver is less subject to web bug like monitoring.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && (opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE)
      && keyserver_any_configured (c->ctrl))
    {
      int res;
      const byte *p;
      size_t n;

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_ISSUER_FPR, &n);
      if (p && n == 21 && p[0] == 4)
        {
          /* v4 packet with a SHA-1 fingerprint.  */
          free_public_key (pk);
          pk = NULL;
          glo_ctrl.in_auto_key_retrieve++;
          res = keyserver_import_fprint (c->ctrl, p+1, n-1, opt.keyserver, 1);
          glo_ctrl.in_auto_key_retrieve--;
          if (!res)
            rc = do_check_sig (c, node, NULL, &is_expkey, &is_revkey, &pk);
        }
    }

  /* If the above methods didn't work, our next try is to retrieve the
   * key from the WKD. */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && (opt.keyserver_options.options & KEYSERVER_AUTO_KEY_RETRIEVE)
      && !opt.flags.disable_signer_uid
      && akl_has_wkd_method ()
      && sig->signers_uid)
    {
      int res;

      free_public_key (pk);
      pk = NULL;
      glo_ctrl.in_auto_key_retrieve++;
      res = keyserver_import_wkd (c->ctrl, sig->signers_uid, 1, NULL, NULL);
      glo_ctrl.in_auto_key_retrieve--;
      /* Fixme: If the fingerprint is embedded in the signature,
       * compare it to the fingerprint of the returned key.  */
      if (!res)
        rc = do_check_sig (c, node, NULL, &is_expkey, &is_revkey, &pk);
    }

  /* If the above methods did't work, our next try is to use a
   * keyserver.  */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && (opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE)
      && keyserver_any_configured (c->ctrl))
    {
      int res;

      free_public_key (pk);
      pk = NULL;
      glo_ctrl.in_auto_key_retrieve++;
      res = keyserver_import_keyid (c->ctrl, sig->keyid, opt.keyserver, 1);
      glo_ctrl.in_auto_key_retrieve--;
      if (!res)
        rc = do_check_sig (c, node, NULL, &is_expkey, &is_revkey, &pk);
    }

  if (!rc || gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE)
    {
      kbnode_t un, keyblock;
      int count = 0;
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
       * keyboock has already been fetched.  Thus we could use the
       * fingerprint or PK itself to lookup the entire keyblock.  That
       * would best be done with a cache.  */
      keyblock = get_pubkeyblock (c->ctrl, sig->keyid);

      snprintf (keyid_str, sizeof keyid_str, "%08lX%08lX [uncertain] ",
                (ulong)sig->keyid[0], (ulong)sig->keyid[1]);

      /* Find and print the primary user ID along with the
         "Good|Expired|Bad signature" line.  */
      for (un=keyblock; un; un = un->next)
        {
          int valid;

          if (un->pkt->pkttype==PKT_PUBLIC_KEY)
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
	}

      log_assert (mainpk);

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

      /* For good signatures print the VALIDSIG status line.  */
      if (!rc && is_status_enabled () && pk)
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
	}

      /* For good signatures compute and print the trust information.
         Note that in the Tofu trust model this may ask the user on
         how to resolve a conflict.  */
      if (!rc)
        {
          if ((opt.verify_options & VERIFY_PKA_LOOKUPS))
            pka_uri_from_sig (c, sig); /* Make sure PKA info is available. */
          rc = check_signatures_trust (c->ctrl, sig);
        }

      /* Print extra information about the signature.  */
      if (sig->flags.expired)
        {
          log_info (_("Signature expired %s\n"), asctimestamp(sig->expiredate));
          rc = GPG_ERR_GENERAL; /* Need a better error here?  */
        }
      else if (sig->expiredate)
        log_info (_("Signature expires %s\n"), asctimestamp(sig->expiredate));

      if (opt.verbose)
        {
          char pkstrbuf[PUBKEY_STRING_SIZE];

          if (pk)
            pubkey_string (pk, pkstrbuf, sizeof pkstrbuf);
          else
            *pkstrbuf = 0;

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
                }
              xfree (dfile);
            }
        }

      free_public_key (pk);
      pk = NULL;
      release_kbnode( keyblock );
      if (rc)
        g10_errors_seen = 1;
      if (opt.batch && rc)
        g10_exit (1);
    }
  else
    {
      char buf[50];

      snprintf (buf, sizeof buf, "%08lX%08lX %d %d %02x %lu %d",
                (ulong)sig->keyid[0], (ulong)sig->keyid[1],
                sig->pubkey_algo, sig->digest_algo,
                sig->sig_class, (ulong)sig->timestamp, gpg_err_code (rc));
      write_status_text (STATUS_ERRSIG, buf);
      if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY)
        {
          buf[16] = 0;
          write_status_text (STATUS_NO_PUBKEY, buf);
	}
      if (gpg_err_code (rc) != GPG_ERR_NOT_PROCESSED)
        log_error (_("Can't check signature: %s\n"), gpg_strerror (rc));
    }

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
              rc = ask_for_detached_datafile (c->mfx.md, c->mfx.md2,
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
