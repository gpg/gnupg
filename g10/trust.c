/* trust.c - High level trust functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
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
#include "keydb.h"
#include "../common/util.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "../common/i18n.h"
#include "trustdb.h"
#include "../common/host2net.h"


/* Return true if key is disabled.  Note that this is usually used via
   the pk_is_disabled macro.  */
int
cache_disabled_value (ctrl_t ctrl, PKT_public_key *pk)
{
#ifdef NO_TRUST_MODELS
  (void)pk;
  return 0;
#else
  return tdb_cache_disabled_value (ctrl, pk);
#endif
}


void
register_trusted_keyid (u32 *keyid)
{
#ifdef NO_TRUST_MODELS
  (void)keyid;
#else
  tdb_register_trusted_keyid (keyid);
#endif
}


void
register_trusted_key (const char *string)
{
#ifdef NO_TRUST_MODELS
  (void)string;
#else
  tdb_register_trusted_key (string);
#endif
}



/*
 * This function returns a letter for a trust value.  Trust flags
 * are ignored.
 */
static int
trust_letter (unsigned int value)
{
  switch( (value & TRUST_MASK) )
    {
    case TRUST_UNKNOWN:   return '-';
    case TRUST_EXPIRED:   return 'e';
    case TRUST_UNDEFINED: return 'q';
    case TRUST_NEVER:     return 'n';
    case TRUST_MARGINAL:  return 'm';
    case TRUST_FULLY:     return 'f';
    case TRUST_ULTIMATE:  return 'u';
    default:              return '?';
    }
}


/* The strings here are similar to those in
   pkclist.c:do_edit_ownertrust() */
const char *
trust_value_to_string (unsigned int value)
{
  switch ((value & TRUST_MASK))
    {
    case TRUST_UNKNOWN:   return _("unknown");
    case TRUST_EXPIRED:   return _("expired");
    case TRUST_UNDEFINED: return _("undefined");
    case TRUST_NEVER:     return _("never");
    case TRUST_MARGINAL:  return _("marginal");
    case TRUST_FULLY:     return _("full");
    case TRUST_ULTIMATE:  return _("ultimate");
    default:              return "err";
    }
}


int
string_to_trust_value (const char *str)
{
  if (!ascii_strcasecmp (str, "undefined"))
    return TRUST_UNDEFINED;
  else if (!ascii_strcasecmp (str, "never"))
    return TRUST_NEVER;
  else if (!ascii_strcasecmp (str, "marginal"))
    return TRUST_MARGINAL;
  else if (!ascii_strcasecmp (str, "full"))
    return TRUST_FULLY;
  else if (!ascii_strcasecmp(str, "ultimate"))
    return TRUST_ULTIMATE;
  else
    return -1;
}


const char *
uid_trust_string_fixed (ctrl_t ctrl, PKT_public_key *key, PKT_user_id *uid)
{
  if (!key && !uid)
    {
      /* TRANSLATORS: these strings are similar to those in
         trust_value_to_string(), but are a fixed length.  This is needed to
         make attractive information listings where columns line up
         properly.  The value "10" should be the length of the strings you
         choose to translate to.  This is the length in printable columns.
         It gets passed to atoi() so everything after the number is
         essentially a comment and need not be translated.  Either key and
         uid are both NULL, or neither are NULL. */
      return _("10 translator see trust.c:uid_trust_string_fixed");
    }
  else if(uid->flags.revoked || (key && key->flags.revoked))
    return                         _("[ revoked]");
  else if(uid->flags.expired)
    return                         _("[ expired]");
  else if(key)
    {
      switch (get_validity (ctrl, NULL, key, uid, NULL, 0) & TRUST_MASK)
        {
        case TRUST_UNKNOWN:   return _("[ unknown]");
        case TRUST_EXPIRED:   return _("[ expired]");
        case TRUST_UNDEFINED: return _("[  undef ]");
        case TRUST_NEVER:     return _("[  never ]");
        case TRUST_MARGINAL:  return _("[marginal]");
        case TRUST_FULLY:     return _("[  full  ]");
        case TRUST_ULTIMATE:  return _("[ultimate]");
        }
    }

  return "err";
}



/*
 * Return the assigned ownertrust value for the given public key.
 * The key should be the primary key.
 */
unsigned int
get_ownertrust (ctrl_t ctrl, PKT_public_key *pk)
{
#ifdef NO_TRUST_MODELS
  (void)pk;
  return TRUST_UNKNOWN;
#else
  return tdb_get_ownertrust (ctrl, pk, 0);
#endif
}


/*
 * Same as get_ownertrust but this takes the minimum ownertrust value
 * into account, and will bump up the value as needed.  NO_CREATE
 * inhibits creation of a trustdb it that does not yet exists.
 */
static int
get_ownertrust_with_min (ctrl_t ctrl, PKT_public_key *pk, int no_create)
{
#ifdef NO_TRUST_MODELS
  (void)pk;
  return TRUST_UNKNOWN;
#else
  unsigned int otrust, otrust_min;

  /* Shortcut instead of doing the same twice in the two tdb_get
   * functions: If the caller asked not to create a trustdb we call
   * init_trustdb directly and allow it to fail with an error code for
   * a non-existing trustdb.  */
  if (no_create && init_trustdb (ctrl, 1))
    return TRUST_UNKNOWN;

  otrust = (tdb_get_ownertrust (ctrl, pk, no_create) & TRUST_MASK);
  otrust_min = tdb_get_min_ownertrust (ctrl, pk, no_create);
  if (otrust < otrust_min)
    {
      /* If the trust that the user has set is less than the trust
	 that was calculated from a trust signature chain, use the
	 higher of the two.  We do this here and not in
	 get_ownertrust since the underlying ownertrust should not
	 really be set - just the appearance of the ownertrust. */

      otrust = otrust_min;
    }

  return otrust;
#endif
}


/*
 * Same as get_ownertrust but return a trust letter instead of an
 * value.  This takes the minimum ownertrust value into account.  If
 * NO_CREATE is set, no efforts for creating a trustdb will be taken.
 */
int
get_ownertrust_info (ctrl_t ctrl, PKT_public_key *pk, int no_create)
{
  return trust_letter (get_ownertrust_with_min (ctrl, pk, no_create));
}


/*
 * Same as get_ownertrust but return a trust string instead of an
 * value.  This takes the minimum ownertrust value into account.  If
 * NO_CREATE is set, no efforts for creating a trustdb will be taken.
 */
const char *
get_ownertrust_string (ctrl_t ctrl, PKT_public_key *pk, int no_create)
{
  return trust_value_to_string (get_ownertrust_with_min (ctrl, pk, no_create));
}


/*
 * Set the trust value of the given public key to the new value.
 * The key should be a primary one.
 */
void
update_ownertrust (ctrl_t ctrl, PKT_public_key *pk, unsigned int new_trust)
{
#ifdef NO_TRUST_MODELS
  (void)pk;
  (void)new_trust;
#else
  tdb_update_ownertrust (ctrl, pk, new_trust);
#endif
}


int
clear_ownertrusts (ctrl_t ctrl, PKT_public_key *pk)
{
#ifdef NO_TRUST_MODELS
  (void)pk;
  return 0;
#else
  return tdb_clear_ownertrusts (ctrl, pk);
#endif
}


void
revalidation_mark (ctrl_t ctrl)
{
#ifndef NO_TRUST_MODELS
  tdb_revalidation_mark (ctrl);
#endif
}


void
check_trustdb_stale (ctrl_t ctrl)
{
#ifndef NO_TRUST_MODELS
  tdb_check_trustdb_stale (ctrl);
#else
  (void)ctrl;
#endif
}


void
check_or_update_trustdb (ctrl_t ctrl)
{
#ifndef NO_TRUST_MODELS
  tdb_check_or_update (ctrl);
#else
  (void)ctrl;
#endif
}


/*
 * Return the validity information for KB/PK (at least one must be
 * non-NULL).  If the namehash is not NULL, the validity of the
 * corresponding user ID is returned, otherwise, a reasonable value
 * for the entire key is returned.
 */
unsigned int
get_validity (ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk, PKT_user_id *uid,
              PKT_signature *sig, int may_ask)
{
  int rc;
  unsigned int validity;
  u32 kid[2];
  PKT_public_key *main_pk;

  if (kb && pk)
    log_assert (keyid_cmp (pk_main_keyid (pk),
                           pk_main_keyid (kb->pkt->pkt.public_key)) == 0);

  if (! pk)
    {
      log_assert (kb);
      pk = kb->pkt->pkt.public_key;
    }

  if (uid)
    namehash_from_uid (uid);

  keyid_from_pk (pk, kid);
  if (pk->main_keyid[0] != kid[0] || pk->main_keyid[1] != kid[1])
    {
      /* This is a subkey - get the mainkey. */
      if (kb)
        main_pk = kb->pkt->pkt.public_key;
      else
        {
          main_pk = xmalloc_clear (sizeof *main_pk);
          rc = get_pubkey (ctrl, main_pk, pk->main_keyid);
          if (rc)
            {
              char *tempkeystr = xstrdup (keystr (pk->main_keyid));
              log_error ("error getting main key %s of subkey %s: %s\n",
                         tempkeystr, keystr (kid), gpg_strerror (rc));
              xfree (tempkeystr);
              validity = TRUST_UNKNOWN;
              goto leave;
            }
        }
    }
  else
    main_pk = pk;

#ifdef NO_TRUST_MODELS
  validity = TRUST_UNKNOWN;
#else
  validity = tdb_get_validity_core (ctrl, kb, pk, uid, main_pk, sig, may_ask);
#endif

 leave:
  /* Set some flags direct from the key */
  if (main_pk->flags.revoked)
    validity |= TRUST_FLAG_REVOKED;
  if (main_pk != pk && pk->flags.revoked)
    validity |= TRUST_FLAG_SUB_REVOKED;
  /* Note: expiration is a trust value and not a flag - don't know why
   * I initially designed it that way.  */
  if (main_pk->has_expired || pk->has_expired)
    validity = ((validity & (~TRUST_MASK | TRUST_FLAG_PENDING_CHECK))
                | TRUST_EXPIRED);

  if (main_pk != pk && !kb)
    free_public_key (main_pk);
  return validity;
}


int
get_validity_info (ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk,
                   PKT_user_id *uid)
{
  int trustlevel;

  if (kb && pk)
    log_assert (keyid_cmp (pk_main_keyid (pk),
                           pk_main_keyid (kb->pkt->pkt.public_key)) == 0);

  if (! pk && kb)
    pk = kb->pkt->pkt.public_key;
  if (!pk)
    return '?';  /* Just in case a NULL PK is passed.  */

  trustlevel = get_validity (ctrl, kb, pk, uid, NULL, 0);
  if ((trustlevel & TRUST_FLAG_REVOKED))
    return 'r';
  return trust_letter (trustlevel);
}


const char *
get_validity_string (ctrl_t ctrl, PKT_public_key *pk, PKT_user_id *uid)
{
  int trustlevel;

  if (!pk)
    return "err";  /* Just in case a NULL PK is passed.  */

  trustlevel = get_validity (ctrl, NULL, pk, uid, NULL, 0);
  if ((trustlevel & TRUST_FLAG_REVOKED))
    return _("revoked");
  return trust_value_to_string (trustlevel);
}



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
 * responsible to skip or remove them.  */
void
clean_key (ctrl_t ctrl, kbnode_t keyblock, int noisy, int self_only,
           int *uids_cleaned, int *sigs_cleaned)
{
  kbnode_t node;

  merge_keys_and_selfsig (ctrl, keyblock);

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
  for (; node; node = node->next)
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
}
