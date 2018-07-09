/* key-clean.c - Functions to clean a keyblock
 * Copyright (C) 1998-2008, 2010-2011 Free Software Foundation, Inc.
 * Copyright (C) 2014, 2016-2018  Werner Koch
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
#include "keydb.h"
#include "../common/util.h"
#include "../common/host2net.h"
#include "../common/i18n.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "key-clean.h"


/*
 * Mark the signature of the given UID which are used to certify it.
 * To do this, we first revmove all signatures which are not valid and
 * from the remain ones we look for the latest one.  If this is not a
 * certification revocation signature we mark the signature by setting
 * node flag bit 8.  Revocations are marked with flag 11, and sigs
 * from unavailable keys are marked with flag 12.  Note that flag bits
 * 9 and 10 are used for internal purposes.
 */
void
mark_usable_uid_certs (ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode,
                       u32 *main_kid, struct key_item *klist,
                       u32 curtime, u32 *next_expire)
{
  kbnode_t node;
  PKT_signature *sig;

  /* First check all signatures.  */
  for (node=uidnode->next; node; node = node->next)
    {
      int rc;

      node->flag &= ~(1<<8 | 1<<9 | 1<<10 | 1<<11 | 1<<12);
      if (node->pkt->pkttype == PKT_USER_ID
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY)
        break; /* ready */
      if (node->pkt->pkttype != PKT_SIGNATURE)
        continue;
      sig = node->pkt->pkt.signature;
      if (main_kid
	  && sig->keyid[0] == main_kid[0] && sig->keyid[1] == main_kid[1])
        continue; /* ignore self-signatures if we pass in a main_kid */
      if (!IS_UID_SIG(sig) && !IS_UID_REV(sig))
        continue; /* we only look at these signature classes */
      if(sig->sig_class>=0x11 && sig->sig_class<=0x13 &&
	 sig->sig_class-0x10<opt.min_cert_level)
	continue; /* treat anything under our min_cert_level as an
		     invalid signature */
      if (klist && !is_in_klist (klist, sig))
        continue;  /* no need to check it then */
      if ((rc=check_key_signature (ctrl, keyblock, node, NULL)))
	{
	  /* we ignore anything that won't verify, but tag the
	     no_pubkey case */
	  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY)
            node->flag |= 1<<12;
          continue;
        }
      node->flag |= 1<<9;
    }
  /* Reset the remaining flags. */
  for (; node; node = node->next)
    node->flag &= ~(1<<8 | 1<<9 | 1<<10 | 1<<11 | 1<<12);

  /* kbnode flag usage: bit 9 is here set for signatures to consider,
   * bit 10 will be set by the loop to keep track of keyIDs already
   * processed, bit 8 will be set for the usable signatures, and bit
   * 11 will be set for usable revocations. */

  /* For each cert figure out the latest valid one.  */
  for (node=uidnode->next; node; node = node->next)
    {
      KBNODE n, signode;
      u32 kid[2];
      u32 sigdate;

      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY)
        break;
      if ( !(node->flag & (1<<9)) )
        continue; /* not a node to look at */
      if ( (node->flag & (1<<10)) )
        continue; /* signature with a keyID already processed */
      node->flag |= (1<<10); /* mark this node as processed */
      sig = node->pkt->pkt.signature;
      signode = node;
      sigdate = sig->timestamp;
      kid[0] = sig->keyid[0]; kid[1] = sig->keyid[1];

      /* Now find the latest and greatest signature */
      for (n=uidnode->next; n; n = n->next)
        {
          if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || n->pkt->pkttype == PKT_SECRET_SUBKEY)
            break;
          if ( !(n->flag & (1<<9)) )
            continue;
          if ( (n->flag & (1<<10)) )
            continue; /* shortcut already processed signatures */
          sig = n->pkt->pkt.signature;
          if (kid[0] != sig->keyid[0] || kid[1] != sig->keyid[1])
            continue;
          n->flag |= (1<<10); /* mark this node as processed */

	  /* If signode is nonrevocable and unexpired and n isn't,
             then take signode (skip).  It doesn't matter which is
             older: if signode was older then we don't want to take n
             as signode is nonrevocable.  If n was older then we're
             automatically fine. */

	  if(((IS_UID_SIG(signode->pkt->pkt.signature) &&
	       !signode->pkt->pkt.signature->flags.revocable &&
	       (signode->pkt->pkt.signature->expiredate==0 ||
		signode->pkt->pkt.signature->expiredate>curtime))) &&
	     (!(IS_UID_SIG(n->pkt->pkt.signature) &&
		!n->pkt->pkt.signature->flags.revocable &&
		(n->pkt->pkt.signature->expiredate==0 ||
		 n->pkt->pkt.signature->expiredate>curtime))))
	    continue;

	  /* If n is nonrevocable and unexpired and signode isn't,
             then take n.  Again, it doesn't matter which is older: if
             n was older then we don't want to take signode as n is
             nonrevocable.  If signode was older then we're
             automatically fine. */

	  if((!(IS_UID_SIG(signode->pkt->pkt.signature) &&
		!signode->pkt->pkt.signature->flags.revocable &&
		(signode->pkt->pkt.signature->expiredate==0 ||
		 signode->pkt->pkt.signature->expiredate>curtime))) &&
	     ((IS_UID_SIG(n->pkt->pkt.signature) &&
	       !n->pkt->pkt.signature->flags.revocable &&
	       (n->pkt->pkt.signature->expiredate==0 ||
		n->pkt->pkt.signature->expiredate>curtime))))
            {
              signode = n;
              sigdate = sig->timestamp;
	      continue;
            }

	  /* At this point, if it's newer, it goes in as the only
             remaining possibilities are signode and n are both either
             revocable or expired or both nonrevocable and unexpired.
             If the timestamps are equal take the later ordered
             packet, presuming that the key packets are hopefully in
             their original order. */

          if (sig->timestamp >= sigdate)
            {
              signode = n;
              sigdate = sig->timestamp;
            }
        }

      sig = signode->pkt->pkt.signature;
      if (IS_UID_SIG (sig))
        { /* this seems to be a usable one which is not revoked.
           * Just need to check whether there is an expiration time,
           * We do the expired certification after finding a suitable
           * certification, the assumption is that a signator does not
           * want that after the expiration of his certificate the
           * system falls back to an older certification which has a
           * different expiration time */
          const byte *p;
          u32 expire;

          p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_SIG_EXPIRE, NULL );
          expire = p? sig->timestamp + buf32_to_u32(p) : 0;

          if (expire==0 || expire > curtime )
            {
              signode->flag |= (1<<8); /* yeah, found a good cert */
              if (next_expire && expire && expire < *next_expire)
                *next_expire = expire;
            }
        }
      else
	signode->flag |= (1<<11);
    }
}


static int
clean_sigs_from_uid (ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode,
                     int noisy, int self_only)
{
  int deleted = 0;
  kbnode_t node;
  u32 keyid[2];

  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY
              || keyblock->pkt->pkttype == PKT_SECRET_KEY);

  keyid_from_pk (keyblock->pkt->pkt.public_key, keyid);

  /* Passing in a 0 for current time here means that we'll never weed
     out an expired sig.  This is correct behavior since we want to
     keep the most recent expired sig in a series. */
  mark_usable_uid_certs (ctrl, keyblock, uidnode, NULL, NULL, 0, NULL);

  /* What we want to do here is remove signatures that are not
     considered as part of the trust calculations.  Thus, all invalid
     signatures are out, as are any signatures that aren't the last of
     a series of uid sigs or revocations It breaks down like this:
     coming out of mark_usable_uid_certs, if a sig is unflagged, it is
     not even a candidate.  If a sig has flag 9 or 10, that means it
     was selected as a candidate and vetted.  If a sig has flag 8 it
     is a usable signature.  If a sig has flag 11 it is a usable
     revocation.  If a sig has flag 12 it was issued by an unavailable
     key.  "Usable" here means the most recent valid
     signature/revocation in a series from a particular signer.

     Delete everything that isn't a usable uid sig (which might be
     expired), a usable revocation, or a sig from an unavailable
     key. */

  for (node=uidnode->next;
       node && node->pkt->pkttype==PKT_SIGNATURE;
       node=node->next)
    {
      int keep;

      keep = self_only? (node->pkt->pkt.signature->keyid[0] == keyid[0]
                         && node->pkt->pkt.signature->keyid[1] == keyid[1]) : 1;

      /* Keep usable uid sigs ... */
      if ((node->flag & (1<<8)) && keep)
	continue;

      /* ... and usable revocations... */
      if ((node->flag & (1<<11)) && keep)
	continue;

      /* ... and sigs from unavailable keys. */
      /* disabled for now since more people seem to want sigs from
	 unavailable keys removed altogether.  */
      /*
	if(node->flag & (1<<12))
	continue;
      */

      /* Everything else we delete */

      /* At this point, if 12 is set, the signing key was unavailable.
	 If 9 or 10 is set, it's superseded.  Otherwise, it's
	 invalid. */

      if (noisy)
	log_info ("removing signature from key %s on user ID \"%s\": %s\n",
                  keystr (node->pkt->pkt.signature->keyid),
                  uidnode->pkt->pkt.user_id->name,
                  node->flag&(1<<12)? "key unavailable":
                  node->flag&(1<<9)?  "signature superseded"
                  /* */               :"invalid signature"  );

      delete_kbnode (node);
      deleted++;
    }

  return deleted;
}


/* This is substantially easier than clean_sigs_from_uid since we just
   have to establish if the uid has a valid self-sig, is not revoked,
   and is not expired.  Note that this does not take into account
   whether the uid has a trust path to it - just whether the keyholder
   themselves has certified the uid.  Returns true if the uid was
   compacted.  To "compact" a user ID, we simply remove ALL signatures
   except the self-sig that caused the user ID to be remove-worthy.
   We don't actually remove the user ID packet itself since it might
   be resurrected in a later merge.  Note that this function requires
   that the caller has already done a merge_keys_and_selfsig().

   TODO: change the import code to allow importing a uid with only a
   revocation if the uid already exists on the keyring. */

static int
clean_uid_from_key (kbnode_t keyblock, kbnode_t uidnode, int noisy)
{
  kbnode_t node;
  PKT_user_id *uid = uidnode->pkt->pkt.user_id;
  int deleted = 0;

  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY
              || keyblock->pkt->pkttype == PKT_SECRET_KEY);
  log_assert (uidnode->pkt->pkttype==PKT_USER_ID);

  /* Skip valid user IDs, compacted user IDs, and non-self-signed user
     IDs if --allow-non-selfsigned-uid is set. */
  if (uid->created
      || uid->flags.compacted
      || (!uid->flags.expired && !uid->flags.revoked && opt.allow_non_selfsigned_uid))
    return 0;

  for (node=uidnode->next;
       node && node->pkt->pkttype == PKT_SIGNATURE;
      node=node->next)
    {
      if (!node->pkt->pkt.signature->flags.chosen_selfsig)
        {
          delete_kbnode (node);
          deleted = 1;
          uidnode->pkt->pkt.user_id->flags.compacted = 1;
        }
    }

  if (noisy)
    {
      const char *reason;
      char *user = utf8_to_native (uid->name, uid->len, 0);

      if (uid->flags.revoked)
	reason = _("revoked");
      else if (uid->flags.expired)
	reason = _("expired");
      else
	reason = _("invalid");

      log_info ("compacting user ID \"%s\" on key %s: %s\n",
                user, keystr_from_pk (keyblock->pkt->pkt.public_key),
                reason);

      xfree (user);
    }

  return deleted;
}


/* Needs to be called after a merge_keys_and_selfsig() */
void
clean_one_uid (ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode,
               int noisy, int self_only, int *uids_cleaned, int *sigs_cleaned)
{
  int dummy = 0;

  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY
              || keyblock->pkt->pkttype == PKT_SECRET_KEY);
  log_assert (uidnode->pkt->pkttype==PKT_USER_ID);

  if (!uids_cleaned)
    uids_cleaned = &dummy;

  if (!sigs_cleaned)
    sigs_cleaned = &dummy;

  /* Do clean_uid_from_key first since if it fires off, we don't have
     to bother with the other.  */
  *uids_cleaned += clean_uid_from_key (keyblock, uidnode, noisy);
  if (!uidnode->pkt->pkt.user_id->flags.compacted)
    *sigs_cleaned += clean_sigs_from_uid (ctrl, keyblock, uidnode,
                                          noisy, self_only);
}


/* NB: This function marks the deleted nodes only and the caller is
 * responsible to skip or remove them.  Needs to be called after a
 * merge_keys_and_selfsig().  */
void
clean_all_uids (ctrl_t ctrl, kbnode_t keyblock, int noisy, int self_only,
                int *uids_cleaned, int *sigs_cleaned)
{
  kbnode_t node;

  for (node = keyblock->next;
       node && !(node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                    || node->pkt->pkttype == PKT_SECRET_SUBKEY);
       node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        clean_one_uid (ctrl, keyblock, node, noisy, self_only,
                       uids_cleaned, sigs_cleaned);
    }

  /* Remove bogus subkey binding signatures: The only signatures
   * allowed are of class 0x18 and 0x28.  */
  log_assert (!node || (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                        || node->pkt->pkttype == PKT_SECRET_SUBKEY));
}


/* Helper for clean_all_subkeys.  */
static int
clean_one_subkey (ctrl_t ctrl, kbnode_t subkeynode, int noisy, int clean_level)
{
  kbnode_t node;
  PKT_public_key *pk = subkeynode->pkt->pkt.public_key;
  unsigned int use = pk->pubkey_usage;
  int do_clean = 0;

  (void)ctrl;
  (void)noisy;

  log_assert (subkeynode->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || subkeynode->pkt->pkttype == PKT_SECRET_SUBKEY);

  if (DBG_LOOKUP)
    log_debug ("\tchecking subkey %08lX [%c%c%c%c%c]\n",
               (ulong) keyid_from_pk (pk, NULL),
               (use & PUBKEY_USAGE_ENC)? 'e':'-',
               (use & PUBKEY_USAGE_SIG)? 's':'-',
               (use & PUBKEY_USAGE_CERT)? 'c':'-',
               (use & PUBKEY_USAGE_AUTH)? 'a':'-',
               (use & PUBKEY_USAGE_UNKNOWN)? '?':'-');

  if (!pk->flags.valid)
    {
      if (DBG_LOOKUP)
        log_debug ("\tsubkey not valid\n");
      if (clean_level == KEY_CLEAN_INVALID)
        do_clean = 1;
    }
  if (pk->has_expired)
    {
      if (DBG_LOOKUP)
        log_debug ("\tsubkey has expired\n");
      if (clean_level == KEY_CLEAN_ALL)
        do_clean = 1;
      else if (clean_level == KEY_CLEAN_AUTHENCR
               && (use & (PUBKEY_USAGE_ENC | PUBKEY_USAGE_AUTH))
               && !(use & (PUBKEY_USAGE_SIG | PUBKEY_USAGE_CERT)))
        do_clean = 1;
      else if (clean_level == KEY_CLEAN_ENCR
               && (use & PUBKEY_USAGE_ENC)
               && !(use & (PUBKEY_USAGE_SIG | PUBKEY_USAGE_CERT
                           | PUBKEY_USAGE_AUTH)))
        do_clean = 1;
    }
  if (pk->flags.revoked)
    {
      if (DBG_LOOKUP)
        log_debug ("\tsubkey has been revoked (keeping)\n");
      /* Avoid any cleaning because revocations are important.  */
      do_clean = 0;
    }
  if (!do_clean)
    return 0;

  if (DBG_LOOKUP)
    log_debug ("\t=> removing this subkey\n");

  delete_kbnode (subkeynode);
  for (node = subkeynode->next;
       node && !(node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                 || node->pkt->pkttype == PKT_SECRET_SUBKEY);
       node = node->next)
    delete_kbnode (node);

  return 1;
}


/* Helper for clean_all_subkeys.  Here duplicate signatures from a
 * subkey are removed.  This should in general not happen because
 * import takes care of that.  However, sometimes other tools are used
 * to manage a keyring or key has been imported a long time ago.  */
static int
clean_one_subkey_dupsigs (ctrl_t ctrl, kbnode_t subkeynode)
{
  kbnode_t node;
  PKT_public_key *pk = subkeynode->pkt->pkt.public_key;
  int any_choosen = 0;
  int count = 0;

  (void)ctrl;

  log_assert (subkeynode->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || subkeynode->pkt->pkttype == PKT_SECRET_SUBKEY);

  if (DBG_LOOKUP)
    log_debug ("\tchecking subkey %08lX for dupsigs\n",
               (ulong) keyid_from_pk (pk, NULL));

  /* First check that the choosen flag has been set.  Note that we
   * only look at plain signatures so to keep all revocation
   * signatures which may carry important information.  */
  for (node = subkeynode->next;
       node && !(node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                 || node->pkt->pkttype == PKT_SECRET_SUBKEY);
       node = node->next)
    {
      if (!is_deleted_kbnode (node)
          && node->pkt->pkttype == PKT_SIGNATURE
          && IS_SUBKEY_SIG (node->pkt->pkt.signature)
          && node->pkt->pkt.signature->flags.chosen_selfsig)
        {
          any_choosen = 1;
          break;
        }
    }

  if (!any_choosen)
    return 0; /* Ooops no choosen flag set - we can't decide.  */

  for (node = subkeynode->next;
       node && !(node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                 || node->pkt->pkttype == PKT_SECRET_SUBKEY);
       node = node->next)
    {
      if (!is_deleted_kbnode (node)
          && node->pkt->pkttype == PKT_SIGNATURE
          && IS_SUBKEY_SIG (node->pkt->pkt.signature)
          && !node->pkt->pkt.signature->flags.chosen_selfsig)
        {
          delete_kbnode (node);
          count++;
        }
    }

  return count;
}


/* This function only marks the deleted nodes and the caller is
 * responsible to skip or remove them.  Needs to be called after a
 * merge_keys_and_selfsig.  CLEAN_LEVEL is one of the KEY_CLEAN_*
 * values.   */
void
clean_all_subkeys (ctrl_t ctrl, kbnode_t keyblock, int noisy, int clean_level,
                   int *subkeys_cleaned, int *sigs_cleaned)
{
  kbnode_t first_subkey, node;
  int n;

  if (DBG_LOOKUP)
    log_debug ("clean_all_subkeys: checking key %08lX\n",
	       (ulong) keyid_from_pk (keyblock->pkt->pkt.public_key, NULL));

  for (node = keyblock->next; node; node = node->next)
    if (!is_deleted_kbnode (node)
        && (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
            || node->pkt->pkttype == PKT_SECRET_SUBKEY))
      break;
  first_subkey = node;

  /* Remove bogus subkey binding signatures: The only signatures
   * allowed are of class 0x18 and 0x28.  */
  for (node = first_subkey; node; node = node->next)
    {
      if (is_deleted_kbnode (node))
        continue;
      if (node->pkt->pkttype == PKT_SIGNATURE
          && !(IS_SUBKEY_SIG (node->pkt->pkt.signature)
                || IS_SUBKEY_REV (node->pkt->pkt.signature)))
        {
          delete_kbnode (node);
          if (sigs_cleaned)
            ++*sigs_cleaned;
        }
    }

  /* Do the selected cleaning.  */
  if (clean_level > KEY_CLEAN_NONE)
    {
      /* Clean enitre subkeys.  */
      for (node = first_subkey; node; node = node->next)
        {
          if (is_deleted_kbnode (node))
            continue;
          if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || node->pkt->pkttype == PKT_SECRET_SUBKEY)
            {
              if (clean_one_subkey (ctrl, node, noisy, clean_level))
                {
                  if (subkeys_cleaned)
                    ++*subkeys_cleaned;
                }
            }
        }

      /* Clean duplicate signatures from a subkey.  */
      for (node = first_subkey; node; node = node->next)
        {
          if (is_deleted_kbnode (node))
            continue;
          if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || node->pkt->pkttype == PKT_SECRET_SUBKEY)
            {
              n = clean_one_subkey_dupsigs (ctrl, node);
              if (sigs_cleaned)
                *sigs_cleaned += n;
            }
        }
    }
}
