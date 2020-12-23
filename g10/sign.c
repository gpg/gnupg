/* sign.c - sign data
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2010, 2012 Free Software Foundation, Inc.
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
#include "../common/ttyio.h"
#include "trustdb.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "pkglue.h"
#include "../common/sysutils.h"
#include "call-agent.h"
#include "../common/mbox-util.h"
#include "../common/compliance.h"

#ifdef HAVE_DOSISH_SYSTEM
#define LF "\r\n"
#else
#define LF "\n"
#endif

/* Bitflags to convey hints on what kind of signayire is created.  */
#define SIGNHINT_KEYSIG  1
#define SIGNHINT_SELFSIG 2


/* Hack */
static int recipient_digest_algo=0;


/****************
 * Create notations and other stuff.  It is assumed that the stings in
 * STRLIST are already checked to contain only printable data and have
 * a valid NAME=VALUE format.
 */
static void
mk_notation_policy_etc (PKT_signature *sig,
			PKT_public_key *pk, PKT_public_key *pksk)
{
  const char *string;
  char *p = NULL;
  strlist_t pu = NULL;
  struct notation *nd = NULL;
  struct expando_args args;

  log_assert (sig->version >= 4);

  memset (&args, 0, sizeof(args));
  args.pk = pk;
  args.pksk = pksk;

  /* Notation data. */
  if (IS_SIG(sig) && opt.sig_notations)
    nd = opt.sig_notations;
  else if (IS_CERT(sig) && opt.cert_notations)
    nd = opt.cert_notations;

  if (nd)
    {
      struct notation *item;

      for (item = nd; item; item = item->next)
        {
          item->altvalue = pct_expando (item->value,&args);
          if (!item->altvalue)
            log_error (_("WARNING: unable to %%-expand notation "
                         "(too large).  Using unexpanded.\n"));
        }

      keygen_add_notations (sig, nd);

      for (item = nd; item; item = item->next)
        {
          xfree (item->altvalue);
          item->altvalue = NULL;
        }
    }

  /* Set policy URL. */
  if (IS_SIG(sig) && opt.sig_policy_url)
    pu = opt.sig_policy_url;
  else if (IS_CERT(sig) && opt.cert_policy_url)
    pu = opt.cert_policy_url;

  for (; pu; pu = pu->next)
    {
      string = pu->d;

      p = pct_expando (string, &args);
      if (!p)
        {
          log_error(_("WARNING: unable to %%-expand policy URL "
                      "(too large).  Using unexpanded.\n"));
          p = xstrdup(string);
        }

      build_sig_subpkt (sig, (SIGSUBPKT_POLICY
                              | ((pu->flags & 1)?SIGSUBPKT_FLAG_CRITICAL:0)),
                        p, strlen (p));

      xfree (p);
    }

  /* Preferred keyserver URL. */
  if (IS_SIG(sig) && opt.sig_keyserver_url)
    pu = opt.sig_keyserver_url;

  for (; pu; pu = pu->next)
    {
      string = pu->d;

      p = pct_expando (string, &args);
      if (!p)
        {
          log_error (_("WARNING: unable to %%-expand preferred keyserver URL"
                       " (too large).  Using unexpanded.\n"));
          p = xstrdup (string);
        }

      build_sig_subpkt (sig, (SIGSUBPKT_PREF_KS
                              | ((pu->flags & 1)?SIGSUBPKT_FLAG_CRITICAL:0)),
                        p, strlen (p));
      xfree (p);
    }

  /* Set signer's user id.  */
  if (IS_SIG (sig) && !opt.flags.disable_signer_uid)
    {
      char *mbox;

      /* For now we use the uid which was used to locate the key.  */
      if (pksk->user_id && (mbox = mailbox_from_userid (pksk->user_id->name)))
        {
          if (DBG_LOOKUP)
            log_debug ("setting Signer's UID to '%s'\n", mbox);
          build_sig_subpkt (sig, SIGSUBPKT_SIGNERS_UID, mbox, strlen (mbox));
          xfree (mbox);
        }
      else if (opt.sender_list)
        {
          /* If a list of --sender was given we scan that list and use
           * the first one matching a user id of the current key.  */

          /* FIXME: We need to get the list of user ids for the PKSK
           * packet.  That requires either a function to look it up
           * again or we need to extend the key packet struct to link
           * to the primary key which in turn could link to the user
           * ids.  Too much of a change right now.  Let's take just
           * one from the supplied list and hope that the caller
           * passed a matching one.  */
          build_sig_subpkt (sig, SIGSUBPKT_SIGNERS_UID,
                            opt.sender_list->d, strlen (opt.sender_list->d));
        }
    }
}



/*
 * Put the Key Block subpakcet into SIG for key PKSK.  Returns an
 * error code on failure.
 */
static gpg_error_t
mk_sig_subpkt_key_block (ctrl_t ctrl, PKT_signature *sig, PKT_public_key *pksk)
{
  gpg_error_t err;
  char *mbox;
  char *filterexp = NULL;
  int save_opt_armor = opt.armor;
  int save_opt_verbose = opt.verbose;
  char hexfpr[2*MAX_FINGERPRINT_LEN + 1];
  void *data = NULL;
  size_t datalen;
  kbnode_t keyblock = NULL;

  push_export_filters ();
  opt.armor = 0;

  hexfingerprint (pksk, hexfpr, sizeof hexfpr);

  /* Get the user id so that we know which one to insert into the
   * key.  */
  if (pksk->user_id
      && (mbox = mailbox_from_userid (pksk->user_id->name)))
    {
      if (DBG_LOOKUP)
        log_debug ("including key with UID '%s' (specified)\n", mbox);
      filterexp = xasprintf ("keep-uid= -- mbox = %s", mbox);
      xfree (mbox);
    }
  else if (opt.sender_list)
    {
      /* If --sender was given we use the first one from that list.  */
      if (DBG_LOOKUP)
        log_debug ("including key with UID '%s' (--sender)\n",
                   opt.sender_list->d);
      filterexp = xasprintf ("keep-uid= -- mbox = %s", opt.sender_list->d);
    }
  else  /* Use the primary user id.  */
    {
      if (DBG_LOOKUP)
        log_debug ("including key with primary UID\n");
      filterexp = xstrdup ("keep-uid= primary -t");
    }

  if (DBG_LOOKUP)
    log_debug ("export filter expression: %s\n", filterexp);
  err = parse_and_set_export_filter (filterexp);
  if (err)
    goto leave;
  xfree (filterexp);
  filterexp = xasprintf ("drop-subkey= fpr <> %s && usage !~ e", hexfpr);
  if (DBG_LOOKUP)
    log_debug ("export filter expression: %s\n", filterexp);
  err = parse_and_set_export_filter (filterexp);
  if (err)
    goto leave;


  opt.verbose = 0;
  err = export_pubkey_buffer (ctrl, hexfpr, EXPORT_MINIMAL|EXPORT_CLEAN,
                              "", 1, /* Prefix with the reserved byte. */
                              NULL, &keyblock, &data, &datalen);
  opt.verbose = save_opt_verbose;
  if (err)
    {
      log_error ("failed to get to be included key: %s\n", gpg_strerror (err));
      goto leave;
    }

  build_sig_subpkt (sig, SIGSUBPKT_KEY_BLOCK, data, datalen);

 leave:
  xfree (data);
  release_kbnode (keyblock);
  xfree (filterexp);
  opt.armor = save_opt_armor;
  pop_export_filters ();
  return err;
}


/*
 * Helper to hash a user ID packet.
 */
static void
hash_uid (gcry_md_hd_t md, int sigversion, const PKT_user_id *uid)
{
  byte buf[5];

  (void)sigversion;

  if (uid->attrib_data)
    {
      buf[0] = 0xd1;	               /* Indicates an attribute packet.  */
      buf[1] = uid->attrib_len >> 24;  /* Always use 4 length bytes.  */
      buf[2] = uid->attrib_len >> 16;
      buf[3] = uid->attrib_len >>  8;
      buf[4] = uid->attrib_len;
    }
  else
    {
      buf[0] = 0xb4;	               /* Indicates a userid packet.  */
      buf[1] = uid->len >> 24;         /* Always use 4 length bytes.  */
      buf[2] = uid->len >> 16;
      buf[3] = uid->len >>  8;
      buf[4] = uid->len;
    }
  gcry_md_write( md, buf, 5 );

  if (uid->attrib_data)
    gcry_md_write (md, uid->attrib_data, uid->attrib_len );
  else
    gcry_md_write (md, uid->name, uid->len );
}


/*
 * Helper to hash some parts from the signature
 */
static void
hash_sigversion_to_magic (gcry_md_hd_t md, const PKT_signature *sig)
{
  byte buf[6];
  size_t n;

  gcry_md_putc (md, sig->version);
  gcry_md_putc (md, sig->sig_class);
  gcry_md_putc (md, sig->pubkey_algo);
  gcry_md_putc (md, sig->digest_algo);
  if (sig->hashed)
    {
      n = sig->hashed->len;
      gcry_md_putc (md, (n >> 8) );
      gcry_md_putc (md,  n       );
      gcry_md_write (md, sig->hashed->data, n );
      n += 6;
    }
  else
    {
      gcry_md_putc (md, 0);  /* Always hash the length of the subpacket.  */
      gcry_md_putc (md, 0);
      n = 6;
    }
  /* Add some magic.  */
  buf[0] = sig->version;
  buf[1] = 0xff;
  buf[2] = n >> 24;         /* (n is only 16 bit, so this is always 0) */
  buf[3] = n >> 16;
  buf[4] = n >>  8;
  buf[5] = n;
  gcry_md_write (md, buf, 6);
}


/* Perform the sign operation.  If CACHE_NONCE is given the agent is
 * advised to use that cached passphrase for the key.  SIGNHINTS has
 * hints so that we can do some additional checks. */
static int
do_sign (ctrl_t ctrl, PKT_public_key *pksk, PKT_signature *sig,
	 gcry_md_hd_t md, int mdalgo,
         const char *cache_nonce, unsigned int signhints)
{
  gpg_error_t err;
  byte *dp;
  char *hexgrip;

  if (pksk->timestamp > sig->timestamp )
    {
      ulong d = pksk->timestamp - sig->timestamp;
      log_info (ngettext("key %s was created %lu second"
                         " in the future (time warp or clock problem)\n",
                         "key %s was created %lu seconds"
                         " in the future (time warp or clock problem)\n",
                         d), keystr_from_pk (pksk), d);
      if (!opt.ignore_time_conflict)
        return gpg_error (GPG_ERR_TIME_CONFLICT);
    }

  print_pubkey_algo_note (pksk->pubkey_algo);

  if (!mdalgo)
    mdalgo = gcry_md_get_algo (md);

  if ((signhints & SIGNHINT_KEYSIG) && !(signhints & SIGNHINT_SELFSIG)
      && mdalgo == GCRY_MD_SHA1
      && !opt.flags.allow_weak_key_signatures)
    {
      /* We do not allow the creation of third-party key signatures
       * using SHA-1 because we also reject them when verifying.  Note
       * that this will render dsa1024 keys unsuitable for such
       * keysigs and in turn the WoT. */
      print_sha1_keysig_rejected_note ();
      err = gpg_error (GPG_ERR_DIGEST_ALGO);
      goto leave;
    }

  /* Check compliance.  */
  if (! gnupg_digest_is_allowed (opt.compliance, 1, mdalgo))
    {
      log_error (_("digest algorithm '%s' may not be used in %s mode\n"),
		 gcry_md_algo_name (mdalgo),
		 gnupg_compliance_option_string (opt.compliance));
      err = gpg_error (GPG_ERR_DIGEST_ALGO);
      goto leave;
    }

  if (! gnupg_pk_is_allowed (opt.compliance, PK_USE_SIGNING,
                             pksk->pubkey_algo, 0,
                             pksk->pkey, nbits_from_pk (pksk), NULL))
    {
      log_error (_("key %s may not be used for signing in %s mode\n"),
                 keystr_from_pk (pksk),
                 gnupg_compliance_option_string (opt.compliance));
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  if (!gnupg_rng_is_compliant (opt.compliance))
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
      log_error (_("%s is not compliant with %s mode\n"),
                 "RNG",
                 gnupg_compliance_option_string (opt.compliance));
      write_status_error ("random-compliance", err);
      goto leave;
    }

  print_digest_algo_note (mdalgo);
  dp = gcry_md_read  (md, mdalgo);
  sig->digest_algo = mdalgo;
  sig->digest_start[0] = dp[0];
  sig->digest_start[1] = dp[1];
  mpi_release (sig->data[0]);
  sig->data[0] = NULL;
  mpi_release (sig->data[1]);
  sig->data[1] = NULL;


  err = hexkeygrip_from_pk (pksk, &hexgrip);
  if (!err)
    {
      char *desc;
      gcry_sexp_t s_sigval;

      desc = gpg_format_keydesc (ctrl, pksk, FORMAT_KEYDESC_NORMAL, 1);
      err = agent_pksign (NULL/*ctrl*/, cache_nonce, hexgrip, desc,
                          pksk->keyid, pksk->main_keyid, pksk->pubkey_algo,
                          dp, gcry_md_get_algo_dlen (mdalgo), mdalgo,
                          &s_sigval);
      xfree (desc);

      if (err)
        ;
      else if (pksk->pubkey_algo == GCRY_PK_RSA
               || pksk->pubkey_algo == GCRY_PK_RSA_S)
        sig->data[0] = get_mpi_from_sexp (s_sigval, "s", GCRYMPI_FMT_USG);
      else if (openpgp_oid_is_ed25519 (pksk->pkey[0]))
        {
          sig->data[0] = get_mpi_from_sexp (s_sigval, "r", GCRYMPI_FMT_OPAQUE);
          sig->data[1] = get_mpi_from_sexp (s_sigval, "s", GCRYMPI_FMT_OPAQUE);
        }
      else
        {
          sig->data[0] = get_mpi_from_sexp (s_sigval, "r", GCRYMPI_FMT_USG);
          sig->data[1] = get_mpi_from_sexp (s_sigval, "s", GCRYMPI_FMT_USG);
        }

      gcry_sexp_release (s_sigval);
    }
  xfree (hexgrip);

 leave:
  if (err)
    {
      log_error (_("signing failed: %s\n"), gpg_strerror (err));
      if (gpg_err_source (err) == GPG_ERR_SOURCE_SCD
          && gpg_err_code (err) == GPG_ERR_INV_ID)
        print_further_info ("a reason might be a card with replaced keys");
    }
  else
    {
      if (opt.verbose)
        {
          char *ustr = get_user_id_string_native (ctrl, sig->keyid);
          log_info (_("%s/%s signature from: \"%s\"\n"),
                    openpgp_pk_algo_name (pksk->pubkey_algo),
                    openpgp_md_algo_name (sig->digest_algo),
                    ustr);
          xfree (ustr);
	}
    }
  return err;
}


static int
complete_sig (ctrl_t ctrl,
              PKT_signature *sig, PKT_public_key *pksk, gcry_md_hd_t md,
              const char *cache_nonce, unsigned int signhints)
{
  int rc;

  /* if (!(rc = check_secret_key (pksk, 0))) */
  rc = do_sign (ctrl, pksk, sig, md, 0, cache_nonce, signhints);
  return rc;
}


/* Return true if the key seems to be on a version 1 OpenPGP card.
   This works by asking the agent and may fail if the card has not yet
   been used with the agent.  */
static int
openpgp_card_v1_p (PKT_public_key *pk)
{
  gpg_error_t err;
  int result;

  /* Shortcut if we are not using RSA: The v1 cards only support RSA
     thus there is no point in looking any further.  */
  if (!is_RSA (pk->pubkey_algo))
    return 0;

  if (!pk->flags.serialno_valid)
    {
      char *hexgrip;

      err = hexkeygrip_from_pk (pk, &hexgrip);
      if (err)
        {
          log_error ("error computing a keygrip: %s\n", gpg_strerror (err));
          return 0; /* Ooops.  */
        }

      xfree (pk->serialno);
      agent_get_keyinfo (NULL, hexgrip, &pk->serialno, NULL);
      xfree (hexgrip);
      pk->flags.serialno_valid = 1;
    }

  if (!pk->serialno)
    result = 0; /* Error from a past agent_get_keyinfo or no card.  */
  else
    {
      /* The version number of the card is included in the serialno.  */
      result = !strncmp (pk->serialno, "D2760001240101", 14);
    }
  return result;
}


/* Get a matching hash algorithm for DSA and ECDSA.  */
static int
match_dsa_hash (unsigned int qbytes)
{
  if (qbytes <= 20)
    return DIGEST_ALGO_SHA1;

  if (qbytes <= 28)
    return DIGEST_ALGO_SHA224;

  if (qbytes <= 32)
    return DIGEST_ALGO_SHA256;

  if (qbytes <= 48)
    return DIGEST_ALGO_SHA384;

  if (qbytes <= 66 )	/* 66 corresponds to 521 (64 to 512) */
    return DIGEST_ALGO_SHA512;

  return DEFAULT_DIGEST_ALGO;
  /* DEFAULT_DIGEST_ALGO will certainly fail, but it's the best wrong
     answer we have if a digest larger than 512 bits is requested.  */
}


/*
  First try --digest-algo.  If that isn't set, see if the recipient
  has a preferred algorithm (which is also filtered through
  --personal-digest-prefs).  If we're making a signature without a
  particular recipient (i.e. signing, rather than signing+encrypting)
  then take the first algorithm in --personal-digest-prefs that is
  usable for the pubkey algorithm.  If --personal-digest-prefs isn't
  set, then take the OpenPGP default (i.e. SHA-1).

  Note that Ed25519+EdDSA takes an input of arbitrary length and thus
  we don't enforce any particular algorithm like we do for standard
  ECDSA. However, we use SHA256 as the default algorithm.

  Possible improvement: Use the highest-ranked usable algorithm from
  the signing key prefs either before or after using the personal
  list?
*/
static int
hash_for (PKT_public_key *pk)
{
  if (opt.def_digest_algo)
    {
      return opt.def_digest_algo;
    }
  else if (recipient_digest_algo && !is_weak_digest (recipient_digest_algo))
    {
      return recipient_digest_algo;
    }
  else if (pk->pubkey_algo == PUBKEY_ALGO_EDDSA
           && openpgp_oid_is_ed25519 (pk->pkey[0]))
    {
      if (opt.personal_digest_prefs)
        return opt.personal_digest_prefs[0].value;
      else
        return DIGEST_ALGO_SHA256;
    }
  else if (pk->pubkey_algo == PUBKEY_ALGO_DSA
           || pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
    {
      unsigned int qbytes = gcry_mpi_get_nbits (pk->pkey[1]);

      if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
        qbytes = ecdsa_qbits_from_Q (qbytes);
      qbytes = qbytes/8;

      /* It's a DSA key, so find a hash that is the same size as q or
	 larger.  If q is 160, assume it is an old DSA key and use a
	 160-bit hash unless --enable-dsa2 is set, in which case act
	 like a new DSA key that just happens to have a 160-bit q
	 (i.e. allow truncation).  If q is not 160, by definition it
	 must be a new DSA key.  We ignore the personal_digest_prefs
	 for ECDSA because they should always macth the curve and
	 truncated hashes are not useful either.  Even worse,
	 smartcards may reject non matching hash lengths for curves
	 (e.g. using SHA-512 with brainpooolP385r1 on a Yubikey).  */

      if (pk->pubkey_algo == PUBKEY_ALGO_DSA && opt.personal_digest_prefs)
	{
	  prefitem_t *prefs;

	  if (qbytes != 20 || opt.flags.dsa2)
	    {
	      for (prefs=opt.personal_digest_prefs; prefs->type; prefs++)
		if (gcry_md_get_algo_dlen (prefs->value) >= qbytes)
		  return prefs->value;
	    }
	  else
	    {
	      for (prefs=opt.personal_digest_prefs; prefs->type; prefs++)
		if (gcry_md_get_algo_dlen (prefs->value) == qbytes)
		  return prefs->value;
	    }
	}

      return match_dsa_hash(qbytes);
    }
  else if (openpgp_card_v1_p (pk))
    {
      /* The sk lives on a smartcard, and old smartcards only handle
	 SHA-1 and RIPEMD/160.  Newer smartcards (v2.0) don't have
	 this restriction anymore.  Fortunately the serial number
	 encodes the version of the card and thus we know that this
	 key is on a v1 card. */
      if(opt.personal_digest_prefs)
	{
	  prefitem_t *prefs;

	  for (prefs=opt.personal_digest_prefs;prefs->type;prefs++)
	    if (prefs->value==DIGEST_ALGO_SHA1
                || prefs->value==DIGEST_ALGO_RMD160)
	      return prefs->value;
	}

      return DIGEST_ALGO_SHA1;
    }
  else if (opt.personal_digest_prefs)
    {
      /* It's not DSA, so we can use whatever the first hash algorithm
	 is in the pref list */
      return opt.personal_digest_prefs[0].value;
    }
  else
    return DEFAULT_DIGEST_ALGO;
}


static void
print_status_sig_created (PKT_public_key *pk, PKT_signature *sig, int what)
{
  byte array[MAX_FINGERPRINT_LEN];
  char buf[100+MAX_FINGERPRINT_LEN*2];
  size_t n;

  snprintf (buf, sizeof buf - 2*MAX_FINGERPRINT_LEN, "%c %d %d %02x %lu ",
            what, sig->pubkey_algo, sig->digest_algo, sig->sig_class,
            (ulong)sig->timestamp );
  fingerprint_from_pk (pk, array, &n);
  bin2hex (array, n, buf + strlen (buf));

  write_status_text( STATUS_SIG_CREATED, buf );
}


/*
 * Loop over the secret certificates in SK_LIST and build the one pass
 * signature packets.  OpenPGP says that the data should be bracket by
 * the onepass-sig and signature-packet; so we build these onepass
 * packet here in reverse order
 */
static int
write_onepass_sig_packets (SK_LIST sk_list, IOBUF out, int sigclass )
{
    int skcount;
    SK_LIST sk_rover;

    for (skcount=0, sk_rover=sk_list; sk_rover; sk_rover = sk_rover->next)
        skcount++;

    for (; skcount; skcount--) {
        PKT_public_key *pk;
        PKT_onepass_sig *ops;
        PACKET pkt;
        int i, rc;

        for (i=0, sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
            if (++i == skcount)
                break;
        }

        pk = sk_rover->pk;
        ops = xmalloc_clear (sizeof *ops);
        ops->sig_class = sigclass;
        ops->digest_algo = hash_for (pk);
        ops->pubkey_algo = pk->pubkey_algo;
        keyid_from_pk (pk, ops->keyid);
        ops->last = (skcount == 1);

        init_packet(&pkt);
        pkt.pkttype = PKT_ONEPASS_SIG;
        pkt.pkt.onepass_sig = ops;
        rc = build_packet (out, &pkt);
        free_packet (&pkt, NULL);
        if (rc) {
            log_error ("build onepass_sig packet failed: %s\n",
                       gpg_strerror (rc));
            return rc;
        }
    }

    return 0;
}

/*
 * Helper to write the plaintext (literal data) packet
 */
static int
write_plaintext_packet (IOBUF out, IOBUF inp, const char *fname, int ptmode)
{
    PKT_plaintext *pt = NULL;
    u32 filesize;
    int rc = 0;

    if (!opt.no_literal)
      pt=setup_plaintext_name(fname,inp);

    /* try to calculate the length of the data */
    if ( !iobuf_is_pipe_filename (fname) && *fname )
      {
        off_t tmpsize;
        int overflow;

        if( !(tmpsize = iobuf_get_filelength(inp, &overflow))
            && !overflow && opt.verbose)
	  log_info (_("WARNING: '%s' is an empty file\n"), fname);

        /* We can't encode the length of very large files because
           OpenPGP uses only 32 bit for file sizes.  So if the size of
           a file is larger than 2^32 minus some bytes for packet
           headers, we switch to partial length encoding. */
        if ( tmpsize < (IOBUF_FILELENGTH_LIMIT - 65536) )
          filesize = tmpsize;
        else
          filesize = 0;

        /* Because the text_filter modifies the length of the
         * data, it is not possible to know the used length
         * without a double read of the file - to avoid that
         * we simple use partial length packets. */
        if ( ptmode == 't' || ptmode == 'u' || ptmode == 'm')
	  filesize = 0;
      }
    else
      filesize = opt.set_filesize? opt.set_filesize : 0; /* stdin */

    if (!opt.no_literal) {
        PACKET pkt;

        /* Note that PT has been initialized above in no_literal mode.  */
        pt->timestamp = make_timestamp ();
        pt->mode = ptmode;
        pt->len = filesize;
        pt->new_ctb = !pt->len;
        pt->buf = inp;
        init_packet(&pkt);
        pkt.pkttype = PKT_PLAINTEXT;
        pkt.pkt.plaintext = pt;
        /*cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;*/
        if( (rc = build_packet (out, &pkt)) )
            log_error ("build_packet(PLAINTEXT) failed: %s\n",
                       gpg_strerror (rc) );
        pt->buf = NULL;
        free_packet (&pkt, NULL);
    }
    else {
        byte copy_buffer[4096];
        int  bytes_copied;

        while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
            if ( (rc=iobuf_write(out, copy_buffer, bytes_copied)) ) {
                log_error ("copying input to output failed: %s\n",
                           gpg_strerror (rc));
                break;
            }
        wipememory(copy_buffer,4096); /* burn buffer */
    }
    /* fixme: it seems that we never freed pt/pkt */

    return rc;
}

/*
 * Write the signatures from the SK_LIST to OUT. HASH must be a non-finalized
 * hash which will not be changes here.
 */
static int
write_signature_packets (ctrl_t ctrl,
                         SK_LIST sk_list, IOBUF out, gcry_md_hd_t hash,
                         int sigclass, u32 timestamp, u32 duration,
			 int status_letter, const char *cache_nonce)
{
  SK_LIST sk_rover;

  /* Loop over the certificates with secret keys. */
  for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next)
    {
      PKT_public_key *pk;
      PKT_signature *sig;
      gcry_md_hd_t md;
      gpg_error_t err;

      pk = sk_rover->pk;

      /* Build the signature packet.  */
      sig = xtrycalloc (1, sizeof *sig);
      if (!sig)
        return gpg_error_from_syserror ();

      if (duration || opt.sig_policy_url
          || opt.sig_notations || opt.sig_keyserver_url)
        sig->version = 4;
      else
        sig->version = pk->version;

      keyid_from_pk (pk, sig->keyid);
      sig->digest_algo = hash_for (pk);
      sig->pubkey_algo = pk->pubkey_algo;
      if (timestamp)
        sig->timestamp = timestamp;
      else
        sig->timestamp = make_timestamp();
      if (duration)
        sig->expiredate = sig->timestamp + duration;
      sig->sig_class = sigclass;

      if (gcry_md_copy (&md, hash))
        BUG ();

      if (sig->version >= 4)
        {
          build_sig_subpkt_from_sig (sig, pk);
          mk_notation_policy_etc (sig, NULL, pk);
          if (opt.flags.include_key_block && IS_SIG (sig))
            err = mk_sig_subpkt_key_block (ctrl, sig, pk);
          else
            err = 0;
        }
      else
        err = 0;  /* Actually never reached.  */
      hash_sigversion_to_magic (md, sig);
      gcry_md_final (md);

      if (!err)
        err = do_sign (ctrl, pk, sig, md, hash_for (pk), cache_nonce, 0);
      gcry_md_close (md);
      if (!err)
        {
          /* Write the packet.  */
          PACKET pkt;

          init_packet (&pkt);
          pkt.pkttype = PKT_SIGNATURE;
          pkt.pkt.signature = sig;
          err = build_packet (out, &pkt);
          if (!err && is_status_enabled())
            print_status_sig_created (pk, sig, status_letter);
          free_packet (&pkt, NULL);
          if (err)
            log_error ("build signature packet failed: %s\n",
                       gpg_strerror (err));
	}
      else
        free_seckey_enc (sig);

      if (err)
        return err;
    }

  return 0;
}


/****************
 * Sign the files whose names are in FILENAME.
 * If DETACHED has the value true,
 * make a detached signature.  If FILENAMES->d is NULL read from stdin
 * and ignore the detached mode.  Sign the file with all secret keys
 * which can be taken from LOCUSR, if this is NULL, use the default one
 * If ENCRYPTFLAG is true, use REMUSER (or ask if it is NULL) to encrypt the
 * signed data for these users.  If ENCRYPTFLAG is 2 symmetric encryption
 * is also used.
 * If OUTFILE is not NULL; this file is used for output and the function
 * does not ask for overwrite permission; output is then always
 * uncompressed, non-armored and in binary mode.
 */
int
sign_file (ctrl_t ctrl, strlist_t filenames, int detached, strlist_t locusr,
	   int encryptflag, strlist_t remusr, const char *outfile )
{
    const char *fname;
    armor_filter_context_t *afx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    progress_filter_context_t *pfx;
    encrypt_filter_context_t efx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    PK_LIST pk_list = NULL;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int multifile = 0;
    u32 duration=0;

    pfx = new_progress_context ();
    afx = new_armor_context ();
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &efx, 0, sizeof efx);
    efx.ctrl = ctrl;
    init_packet( &pkt );

    if( filenames ) {
	fname = filenames->d;
	multifile = !!filenames->next;
    }
    else
	fname = NULL;

    if( fname && filenames->next && (!detached || encryptflag) )
	log_bug("multiple files can only be detached signed");

    if(encryptflag==2
       && (rc=setup_symkey(&efx.symkey_s2k,&efx.symkey_dek)))
      goto leave;

    if (opt.ask_sig_expire && !opt.batch)
      duration = ask_expire_interval(1,opt.def_sig_expire);
    else
      duration = parse_expire_string(opt.def_sig_expire);

    /* Note: In the old non-agent version the following call used to
       unprotect the secret key.  This is now done on demand by the agent.  */
    if( (rc = build_sk_list (ctrl, locusr, &sk_list, PUBKEY_USAGE_SIG )) )
	goto leave;

    if (encryptflag
        && (rc=build_pk_list (ctrl, remusr, &pk_list)))
      goto leave;

    /* prepare iobufs */
    if( multifile )  /* have list of filenames */
	inp = NULL; /* we do it later */
    else {
      inp = iobuf_open(fname);
      if (inp && is_secured_file (iobuf_get_fd (inp)))
        {
          iobuf_close (inp);
          inp = NULL;
          gpg_err_set_errno (EPERM);
        }
      if( !inp )
        {
          rc = gpg_error_from_syserror ();
          log_error (_("can't open '%s': %s\n"), fname? fname: "[stdin]",
                     strerror(errno) );
          goto leave;
	}

        handle_progress (pfx, inp, fname);
    }

    if( outfile ) {
        if (is_secured_filename ( outfile )) {
            out = NULL;
            gpg_err_set_errno (EPERM);
        }
        else
          out = iobuf_create (outfile, 0);
	if( !out )
	  {
            rc = gpg_error_from_syserror ();
	    log_error(_("can't create '%s': %s\n"), outfile, strerror(errno) );
	    goto leave;
	  }
	else if( opt.verbose )
	    log_info(_("writing to '%s'\n"), outfile );
    }
    else if( (rc = open_outfile (-1, fname,
                                 opt.armor? 1: detached? 2:0, 0, &out)))
	goto leave;

    /* prepare to calculate the MD over the input */
    if( opt.textmode && !outfile && !multifile )
      {
	memset( &tfx, 0, sizeof tfx);
	iobuf_push_filter( inp, text_filter, &tfx );
      }

    if ( gcry_md_open (&mfx.md, 0, 0) )
      BUG ();
    if (DBG_HASHING)
      gcry_md_debug (mfx.md, "sign");

    /* If we're encrypting and signing, it is reasonable to pick the
       hash algorithm to use out of the recipient key prefs.  This is
       best effort only, as in a DSA2 and smartcard world there are
       cases where we cannot please everyone with a single hash (DSA2
       wants >160 and smartcards want =160).  In the future this could
       be more complex with different hashes for each sk, but the
       current design requires a single hash for all SKs. */
    if(pk_list)
      {
	if(opt.def_digest_algo)
	  {
	    if(!opt.expert &&
	       select_algo_from_prefs(pk_list,PREFTYPE_HASH,
				      opt.def_digest_algo,
				      NULL)!=opt.def_digest_algo)
              log_info(_("WARNING: forcing digest algorithm %s (%d)"
                         " violates recipient preferences\n"),
                       gcry_md_algo_name (opt.def_digest_algo),
                       opt.def_digest_algo );
	  }
	else
	  {
	    int algo;
            int conflict = 0;
	    struct pref_hint hint = { 0 };

	    /* Of course, if the recipient asks for something
	       unreasonable (like the wrong hash for a DSA key) then
	       don't do it.  Check all sk's - if any are DSA or live
	       on a smartcard, then the hash has restrictions and we
	       may not be able to give the recipient what they want.
	       For DSA, pass a hint for the largest q we have.  Note
	       that this means that a q>160 key will override a q=160
	       key and force the use of truncation for the q=160 key.
	       The alternative would be to ignore the recipient prefs
	       completely and get a different hash for each DSA key in
	       hash_for().  The override behavior here is more or less
	       reasonable as it is under the control of the user which
	       keys they sign with for a given message and the fact
	       that the message with multiple signatures won't be
	       usable on an implementation that doesn't understand
	       DSA2 anyway. */

	    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next )
	      {
		if (sk_rover->pk->pubkey_algo == PUBKEY_ALGO_DSA
                    || sk_rover->pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
		  {
		    int temp_hashlen = (gcry_mpi_get_nbits
                                        (sk_rover->pk->pkey[1]));

		    if (sk_rover->pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
                      {
                        temp_hashlen = ecdsa_qbits_from_Q (temp_hashlen);
                        if (!temp_hashlen)
                          conflict = 1;  /* Better don't use the prefs. */
                        temp_hashlen = (temp_hashlen+7)/8;
                        /* Fixup for that funny nistp521 (yes, 521)
                         * were we need to use a 512 bit hash algo.  */
                        if (temp_hashlen == 66)
                          temp_hashlen = 64;
                      }
                    else
                      temp_hashlen = (temp_hashlen+7)/8;

		    /* Pick a hash that is large enough for our
		       largest q or matches our Q but if tehreare
		       several of them we run into a conflict and
		       don't use the preferences.  */

		    if (hint.digest_length < temp_hashlen)
                      {
                        if (sk_rover->pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
                          {
                            if (hint.exact)
                              conflict = 1;
                            hint.exact = 1;
                          }
                        hint.digest_length = temp_hashlen;
                      }
		  }
	      }

	    if (!conflict
                && (algo = select_algo_from_prefs (pk_list,PREFTYPE_HASH,
                                                   -1,&hint)) > 0)
                {
                  /* Note that we later check that the algo is not weak.  */
                  recipient_digest_algo = algo;
                }
	  }
      }

    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next)
      gcry_md_enable (mfx.md, hash_for (sk_rover->pk));

    if( !multifile )
	iobuf_push_filter( inp, md_filter, &mfx );

    if( detached && !encryptflag)
	afx->what = 2;

    if( opt.armor && !outfile  )
	push_armor_filter (afx, out);

    if( encryptflag ) {
	efx.pk_list = pk_list;
	/* fixme: set efx.cfx.datalen if known */
	iobuf_push_filter( out, encrypt_filter, &efx );
    }

    if (opt.compress_algo && !outfile && !detached)
      {
        int compr_algo=opt.compress_algo;

	/* If not forced by user */
	if(compr_algo==-1)
	  {
	    /* If we're not encrypting, then select_algo_from_prefs
	       will fail and we'll end up with the default.  If we are
	       encrypting, select_algo_from_prefs cannot fail since
	       there is an assumed preference for uncompressed data.
	       Still, if it did fail, we'll also end up with the
	       default. */

	    if((compr_algo=
		select_algo_from_prefs(pk_list,PREFTYPE_ZIP,-1,NULL))==-1)
	      compr_algo=default_compress_algo();
	  }
 	else if(!opt.expert && pk_list
 		&& select_algo_from_prefs(pk_list,PREFTYPE_ZIP,
					  compr_algo,NULL)!=compr_algo)
 	  log_info(_("WARNING: forcing compression algorithm %s (%d)"
 		     " violates recipient preferences\n"),
 		   compress_algo_to_string(compr_algo),compr_algo);

	/* algo 0 means no compression */
	if( compr_algo )
	  push_compress_filter(out,&zfx,compr_algo);
      }

    /* Write the one-pass signature packets if needed */
    if (!detached) {
        rc = write_onepass_sig_packets (sk_list, out,
                                        opt.textmode && !outfile ? 0x01:0x00);
        if (rc)
            goto leave;
    }

    write_status_begin_signing (mfx.md);

    /* Setup the inner packet. */
    if( detached ) {
	if( multifile ) {
	    strlist_t sl;

	    if( opt.verbose )
		log_info(_("signing:") );
	    /* must walk reverse trough this list */
	    for( sl = strlist_last(filenames); sl;
			sl = strlist_prev( filenames, sl ) ) {
                inp = iobuf_open(sl->d);
                if (inp && is_secured_file (iobuf_get_fd (inp)))
                  {
                    iobuf_close (inp);
                    inp = NULL;
                    gpg_err_set_errno (EPERM);
                  }
		if( !inp )
		  {
                    rc = gpg_error_from_syserror ();
		    log_error(_("can't open '%s': %s\n"),
			      sl->d,strerror(errno));
		    goto leave;
		  }
                handle_progress (pfx, inp, sl->d);
		if( opt.verbose )
                  log_printf (" '%s'", sl->d );
		if(opt.textmode)
		  {
		    memset( &tfx, 0, sizeof tfx);
		    iobuf_push_filter( inp, text_filter, &tfx );
		  }
		iobuf_push_filter( inp, md_filter, &mfx );
		while( iobuf_get(inp) != -1 )
		    ;
		iobuf_close(inp); inp = NULL;
	    }
	    if( opt.verbose )
              log_printf ("\n");
	}
	else {
	    /* read, so that the filter can calculate the digest */
	    while( iobuf_get(inp) != -1 )
		;
	}
    }
    else {
        rc = write_plaintext_packet (out, inp, fname,
                                     opt.textmode && !outfile ?
                                     (opt.mimemode? 'm':'t'):'b');
    }

    /* catch errors from above */
    if (rc)
	goto leave;

    /* write the signatures */
    rc = write_signature_packets (ctrl, sk_list, out, mfx.md,
                                  opt.textmode && !outfile? 0x01 : 0x00,
				  0, duration, detached ? 'D':'S', NULL);
    if( rc )
        goto leave;


  leave:
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out);
        if (encryptflag)
            write_status( STATUS_END_ENCRYPTION );
    }
    iobuf_close(inp);
    gcry_md_close ( mfx.md );
    release_sk_list( sk_list );
    release_pk_list( pk_list );
    recipient_digest_algo=0;
    release_progress_context (pfx);
    release_armor_context (afx);
    return rc;
}



/****************
 * make a clear signature. note that opt.armor is not needed
 */
int
clearsign_file (ctrl_t ctrl,
                const char *fname, strlist_t locusr, const char *outfile )
{
    armor_filter_context_t *afx;
    progress_filter_context_t *pfx;
    gcry_md_hd_t textmd = NULL;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    u32 duration=0;

    pfx = new_progress_context ();
    afx = new_armor_context ();
    init_packet( &pkt );

    if (opt.ask_sig_expire && !opt.batch)
      duration = ask_expire_interval (1,opt.def_sig_expire);
    else
      duration = parse_expire_string (opt.def_sig_expire);

    /* Note: In the old non-agent version the following call used to
       unprotect the secret key.  This is now done on demand by the agent.  */
    if( (rc=build_sk_list (ctrl, locusr, &sk_list, PUBKEY_USAGE_SIG )) )
	goto leave;

    /* prepare iobufs */
    inp = iobuf_open(fname);
    if (inp && is_secured_file (iobuf_get_fd (inp)))
      {
        iobuf_close (inp);
        inp = NULL;
        gpg_err_set_errno (EPERM);
      }
    if( !inp ) {
        rc = gpg_error_from_syserror ();
	log_error (_("can't open '%s': %s\n"),
                   fname? fname: "[stdin]", strerror(errno) );
	goto leave;
    }
    handle_progress (pfx, inp, fname);

    if( outfile ) {
        if (is_secured_filename (outfile) ) {
            outfile = NULL;
            gpg_err_set_errno (EPERM);
        }
        else
          out = iobuf_create (outfile, 0);
	if( !out )
	  {
            rc = gpg_error_from_syserror ();
	    log_error(_("can't create '%s': %s\n"), outfile, strerror(errno) );
	    goto leave;
	  }
	else if( opt.verbose )
	    log_info(_("writing to '%s'\n"), outfile );
    }
    else if ((rc = open_outfile (-1, fname, 1, 0, &out)))
	goto leave;

    iobuf_writestr(out, "-----BEGIN PGP SIGNED MESSAGE-----" LF );

    {
	const char *s;
	int any = 0;
	byte hashs_seen[256];

	memset( hashs_seen, 0, sizeof hashs_seen );
	iobuf_writestr(out, "Hash: " );
	for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	    int i = hash_for (sk_rover->pk);

	    if( !hashs_seen[ i & 0xff ] ) {
		s = gcry_md_algo_name ( i );
		if( s ) {
		    hashs_seen[ i & 0xff ] = 1;
		    if( any )
			iobuf_put(out, ',' );
		    iobuf_writestr(out, s );
		    any = 1;
		}
	    }
	}
	log_assert(any);
	iobuf_writestr(out, LF );
    }

    if( opt.not_dash_escaped )
      iobuf_writestr( out,
                      "NotDashEscaped: You need "GPG_NAME
                      " to verify this message" LF );
    iobuf_writestr(out, LF );

    if ( gcry_md_open (&textmd, 0, 0) )
      BUG ();
    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next)
      gcry_md_enable (textmd, hash_for(sk_rover->pk));

    if ( DBG_HASHING )
      gcry_md_debug ( textmd, "clearsign" );

    copy_clearsig_text (out, inp, textmd, !opt.not_dash_escaped,
                        opt.escape_from);
    /* fixme: check for read errors */

    /* now write the armor */
    afx->what = 2;
    push_armor_filter (afx, out);

    /* Write the signatures.  */
    rc = write_signature_packets (ctrl, sk_list, out, textmd, 0x01, 0,
                                  duration, 'C', NULL);
    if( rc )
        goto leave;

  leave:
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    iobuf_close(inp);
    gcry_md_close ( textmd );
    release_sk_list( sk_list );
    release_progress_context (pfx);
    release_armor_context (afx);
    return rc;
}

/*
 * Sign and conventionally encrypt the given file.
 * FIXME: Far too much code is duplicated - revamp the whole file.
 */
int
sign_symencrypt_file (ctrl_t ctrl, const char *fname, strlist_t locusr)
{
    armor_filter_context_t *afx;
    progress_filter_context_t *pfx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    cipher_filter_context_t cfx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    STRING2KEY *s2k = NULL;
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int algo;
    u32 duration=0;
    int canceled;

    pfx = new_progress_context ();
    afx = new_armor_context ();
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &tfx, 0, sizeof tfx);
    memset( &cfx, 0, sizeof cfx);
    init_packet( &pkt );

    if (opt.ask_sig_expire && !opt.batch)
      duration = ask_expire_interval (1, opt.def_sig_expire);
    else
      duration = parse_expire_string (opt.def_sig_expire);

    /* Note: In the old non-agent version the following call used to
       unprotect the secret key.  This is now done on demand by the agent.  */
    rc = build_sk_list (ctrl, locusr, &sk_list, PUBKEY_USAGE_SIG);
    if (rc)
	goto leave;

    /* prepare iobufs */
    inp = iobuf_open(fname);
    if (inp && is_secured_file (iobuf_get_fd (inp)))
      {
        iobuf_close (inp);
        inp = NULL;
        gpg_err_set_errno (EPERM);
      }
    if( !inp ) {
        rc = gpg_error_from_syserror ();
	log_error (_("can't open '%s': %s\n"),
                   fname? fname: "[stdin]", strerror(errno) );
	goto leave;
    }
    handle_progress (pfx, inp, fname);

    /* prepare key */
    s2k = xmalloc_clear( sizeof *s2k );
    s2k->mode = opt.s2k_mode;
    s2k->hash_algo = S2K_DIGEST_ALGO;

    algo = default_cipher_algo();
    if (!opt.quiet || !opt.batch)
        log_info (_("%s encryption will be used\n"),
                  openpgp_cipher_algo_name (algo) );
    cfx.dek = passphrase_to_dek (algo, s2k, 1, 1, NULL, &canceled);

    if (!cfx.dek || !cfx.dek->keylen) {
        rc = gpg_error (canceled?GPG_ERR_CANCELED:GPG_ERR_BAD_PASSPHRASE);
        log_error(_("error creating passphrase: %s\n"), gpg_strerror (rc) );
        goto leave;
    }

    cfx.dek->use_mdc = use_mdc (NULL, cfx.dek->algo);

    /* now create the outfile */
    rc = open_outfile (-1, fname, opt.armor? 1:0, 0, &out);
    if (rc)
	goto leave;

    /* prepare to calculate the MD over the input */
    if (opt.textmode)
	iobuf_push_filter (inp, text_filter, &tfx);
    if ( gcry_md_open (&mfx.md, 0, 0) )
      BUG ();
    if ( DBG_HASHING )
      gcry_md_debug (mfx.md, "symc-sign");

    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next)
      gcry_md_enable (mfx.md, hash_for (sk_rover->pk));

    iobuf_push_filter (inp, md_filter, &mfx);

    /* Push armor output filter */
    if (opt.armor)
	push_armor_filter (afx, out);

    /* Write the symmetric key packet */
    /*(current filters: armor)*/
    {
	PKT_symkey_enc *enc = xmalloc_clear( sizeof *enc );
	enc->version = 4;
	enc->cipher_algo = cfx.dek->algo;
	enc->s2k = *s2k;
	pkt.pkttype = PKT_SYMKEY_ENC;
	pkt.pkt.symkey_enc = enc;
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build symkey packet failed: %s\n", gpg_strerror (rc) );
	xfree(enc);
    }

    /* Push the encryption filter */
    iobuf_push_filter( out, cipher_filter, &cfx );

    /* Push the compress filter */
    if (default_compress_algo())
      {
        if (cfx.dek && cfx.dek->use_mdc)
          zfx.new_ctb = 1;
        push_compress_filter (out, &zfx,default_compress_algo() );
      }

    /* Write the one-pass signature packets */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_onepass_sig_packets (sk_list, out,
                                    opt.textmode? 0x01:0x00);
    if (rc)
      goto leave;

    write_status_begin_signing (mfx.md);

    /* Pipe data through all filters; i.e. write the signed stuff */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_plaintext_packet (out, inp, fname,
                                 opt.textmode ? (opt.mimemode?'m':'t'):'b');
    if (rc)
	goto leave;

    /* Write the signatures */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_signature_packets (ctrl, sk_list, out, mfx.md,
				  opt.textmode? 0x01 : 0x00,
				  0, duration, 'S', NULL);
    if( rc )
        goto leave;


  leave:
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out);
        write_status( STATUS_END_ENCRYPTION );
    }
    iobuf_close(inp);
    release_sk_list( sk_list );
    gcry_md_close( mfx.md );
    xfree(cfx.dek);
    xfree(s2k);
    release_progress_context (pfx);
    release_armor_context (afx);
    return rc;
}


/****************
 * Create a v4 signature in *RET_SIG.
 *
 * PK is the primary key to sign (required for all sigs)
 * UID is the user id to sign (required for 0x10..0x13, 0x30)
 * SUBPK is subkey to sign (required for 0x18, 0x19, 0x28)
 *
 * PKSK is the signing key
 *
 * SIGCLASS is the type of signature to create.
 *
 * DIGEST_ALGO is the digest algorithm.  If it is 0 the function
 * selects an appropriate one.
 *
 * TIMESTAMP is the timestamp to use for the signature. 0 means "now"
 *
 * DURATION is the amount of time (in seconds) until the signature
 * expires.
 *
 * This function creates the following subpackets: issuer, created,
 * and expire (if duration is not 0).  Additional subpackets can be
 * added using MKSUBPKT, which is called after these subpackets are
 * added and before the signature is generated.  OPAQUE is passed to
 * MKSUBPKT.
 */
int
make_keysig_packet (ctrl_t ctrl,
                    PKT_signature **ret_sig, PKT_public_key *pk,
		    PKT_user_id *uid, PKT_public_key *subpk,
		    PKT_public_key *pksk,
		    int sigclass, int digest_algo,
                    u32 timestamp, u32 duration,
		    int (*mksubpkt)(PKT_signature *, void *), void *opaque,
                    const char *cache_nonce)
{
    PKT_signature *sig;
    int rc=0;
    int sigversion;
    gcry_md_hd_t md;
    u32 pk_keyid[2], pksk_keyid[2];
    unsigned int signhints;

    log_assert ((sigclass >= 0x10 && sigclass <= 0x13) || sigclass == 0x1F
                || sigclass == 0x20 || sigclass == 0x18 || sigclass == 0x19
                || sigclass == 0x30 || sigclass == 0x28 );

    sigversion = 4;
    if (sigversion < pksk->version)
        sigversion = pksk->version;

    if( !digest_algo )
      {
	/* Basically, this means use SHA1 always unless the user
	   specified something (use whatever they said), or it's DSA
	   (use the best match).  They still can't pick an
	   inappropriate hash for DSA or the signature will fail.
	   Note that this still allows the caller of
	   make_keysig_packet to override the user setting if it
	   must. */

	if(opt.cert_digest_algo)
	  digest_algo=opt.cert_digest_algo;
	else if(pksk->pubkey_algo == PUBKEY_ALGO_DSA)
	  digest_algo = match_dsa_hash (gcry_mpi_get_nbits (pksk->pkey[1])/8);
        else if (pksk->pubkey_algo == PUBKEY_ALGO_ECDSA
                 || pksk->pubkey_algo == PUBKEY_ALGO_EDDSA)
          {
            if (openpgp_oid_is_ed25519 (pksk->pkey[0]))
              digest_algo = DIGEST_ALGO_SHA256;
            else
              digest_algo = match_dsa_hash
                (ecdsa_qbits_from_Q (gcry_mpi_get_nbits (pksk->pkey[1]))/8);
          }
	else
	  digest_algo = DEFAULT_DIGEST_ALGO;
      }

    signhints = SIGNHINT_KEYSIG;
    keyid_from_pk (pk, pk_keyid);
    keyid_from_pk (pksk, pksk_keyid);
    if (pk_keyid[0] == pksk_keyid[0] && pk_keyid[1] == pksk_keyid[1])
      signhints |= SIGNHINT_SELFSIG;

    if ( gcry_md_open (&md, digest_algo, 0 ) )
      BUG ();

    /* Hash the public key certificate. */
    hash_public_key( md, pk );

    if( sigclass == 0x18 || sigclass == 0x19 || sigclass == 0x28 )
      {
	/* hash the subkey binding/backsig/revocation */
	hash_public_key( md, subpk );
      }
    else if( sigclass != 0x1F && sigclass != 0x20 )
      {
	/* hash the user id */
        hash_uid (md, sigversion, uid);
      }
    /* and make the signature packet */
    sig = xmalloc_clear( sizeof *sig );
    sig->version = sigversion;
    sig->flags.exportable=1;
    sig->flags.revocable=1;
    keyid_from_pk (pksk, sig->keyid);
    sig->pubkey_algo = pksk->pubkey_algo;
    sig->digest_algo = digest_algo;
    if(timestamp)
      sig->timestamp=timestamp;
    else
      sig->timestamp=make_timestamp();
    if(duration)
      sig->expiredate=sig->timestamp+duration;
    sig->sig_class = sigclass;

    build_sig_subpkt_from_sig (sig, pksk);
    mk_notation_policy_etc (sig, pk, pksk);

    /* Crucial that the call to mksubpkt comes LAST before the calls
       to finalize the sig as that makes it possible for the mksubpkt
       function to get a reliable pointer to the subpacket area. */
    if (mksubpkt)
	rc = (*mksubpkt)( sig, opaque );

    if( !rc ) {
        hash_sigversion_to_magic (md, sig);
	gcry_md_final (md);

	rc = complete_sig (ctrl, sig, pksk, md, cache_nonce, signhints);
    }

    gcry_md_close (md);
    if( rc )
	free_seckey_enc( sig );
    else
	*ret_sig = sig;
    return rc;
}



/****************
 * Create a new signature packet based on an existing one.
 * Only user ID signatures are supported for now.
 * PK is the public key to work on.
 * PKSK is the key used to make the signature.
 *
 * TODO: Merge this with make_keysig_packet.
 */
gpg_error_t
update_keysig_packet (ctrl_t ctrl,
                      PKT_signature **ret_sig,
                      PKT_signature *orig_sig,
                      PKT_public_key *pk,
                      PKT_user_id *uid,
                      PKT_public_key *subpk,
                      PKT_public_key *pksk,
                      int (*mksubpkt)(PKT_signature *, void *),
                      void *opaque)
{
    PKT_signature *sig;
    gpg_error_t rc = 0;
    int digest_algo;
    gcry_md_hd_t md;
    u32 pk_keyid[2], pksk_keyid[2];
    unsigned int signhints;

    if ((!orig_sig || !pk || !pksk)
	|| (orig_sig->sig_class >= 0x10 && orig_sig->sig_class <= 0x13 && !uid)
	|| (orig_sig->sig_class == 0x18 && !subpk))
      return GPG_ERR_GENERAL;

    if ( opt.cert_digest_algo )
      digest_algo = opt.cert_digest_algo;
    else if (pksk->pubkey_algo == PUBKEY_ALGO_DSA
             || pksk->pubkey_algo == PUBKEY_ALGO_ECDSA
             || pksk->pubkey_algo == PUBKEY_ALGO_EDDSA)
      digest_algo = orig_sig->digest_algo;
    else if (orig_sig->digest_algo == DIGEST_ALGO_SHA1
             || orig_sig->digest_algo == DIGEST_ALGO_RMD160)
      digest_algo = DEFAULT_DIGEST_ALGO;
    else
      digest_algo = orig_sig->digest_algo;

    signhints = SIGNHINT_KEYSIG;
    keyid_from_pk (pk, pk_keyid);
    keyid_from_pk (pksk, pksk_keyid);
    if (pk_keyid[0] == pksk_keyid[0] && pk_keyid[1] == pksk_keyid[1])
      signhints |= SIGNHINT_SELFSIG;

    if ( gcry_md_open (&md, digest_algo, 0 ) )
      BUG ();

    /* Hash the public key certificate and the user id. */
    hash_public_key( md, pk );

    if( orig_sig->sig_class == 0x18 )
      hash_public_key( md, subpk );
    else
      hash_uid (md, orig_sig->version, uid);

    /* create a new signature packet */
    sig = copy_signature (NULL, orig_sig);

    sig->digest_algo=digest_algo;

    /* We need to create a new timestamp so that new sig expiration
       calculations are done correctly... */
    sig->timestamp=make_timestamp();

    /* ... but we won't make a timestamp earlier than the existing
       one. */
    {
      int tmout = 0;
      while(sig->timestamp<=orig_sig->timestamp)
        {
          if (++tmout > 5 && !opt.ignore_time_conflict)
            {
              rc = gpg_error (GPG_ERR_TIME_CONFLICT);
              goto leave;
            }
          gnupg_sleep (1);
          sig->timestamp=make_timestamp();
        }
    }

    /* Note that already expired sigs will remain expired (with a
       duration of 1) since build-packet.c:build_sig_subpkt_from_sig
       detects this case. */

    /* Put the updated timestamp into the sig.  Note that this will
       automagically lower any sig expiration dates to correctly
       correspond to the differences in the timestamps (i.e. the
       duration will shrink).  */
    build_sig_subpkt_from_sig (sig, pksk);

    if (mksubpkt)
      rc = (*mksubpkt)(sig, opaque);

    if (!rc) {
        hash_sigversion_to_magic (md, sig);
	gcry_md_final (md);

	rc = complete_sig (ctrl, sig, pksk, md, NULL, signhints);
    }

 leave:
    gcry_md_close (md);
    if( rc )
	free_seckey_enc (sig);
    else
	*ret_sig = sig;
    return rc;
}
