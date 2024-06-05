/* getkey.c -  Get a key from the database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2008, 2010  Free Software Foundation, Inc.
 * Copyright (C) 2015, 2016 g10 Code GmbH
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
#include <ctype.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/iobuf.h"
#include "keydb.h"
#include "options.h"
#include "main.h"
#include "trustdb.h"
#include "../common/i18n.h"
#include "keyserver-internal.h"
#include "call-agent.h"
#include "../common/host2net.h"
#include "../common/mbox-util.h"
#include "../common/status.h"

#define MAX_PK_CACHE_ENTRIES   PK_UID_CACHE_SIZE
#define MAX_UID_CACHE_ENTRIES  PK_UID_CACHE_SIZE

#if MAX_PK_CACHE_ENTRIES < 2
#error We need the cache for key creation
#endif

/* Flags values returned by the lookup code.  Note that the values are
 * directly used by the KEY_CONSIDERED status line.  */
#define LOOKUP_NOT_SELECTED        (1<<0)
#define LOOKUP_ALL_SUBKEYS_EXPIRED (1<<1)  /* or revoked */


/* A context object used by the lookup functions.  */
struct getkey_ctx_s
{
  /* Part of the search criteria: whether the search is an exact
     search or not.  A search that is exact requires that a key or
     subkey meet all of the specified criteria.  A search that is not
     exact allows selecting a different key or subkey from the
     keyblock that matched the critera.  Further, an exact search
     returns the key or subkey that matched whereas a non-exact search
     typically returns the primary key.  See finish_lookup for
     details.  */
  int exact;

  /* Allow returning an ADSK key.  */
  int allow_adsk;

  /* Part of the search criteria: Whether the caller only wants keys
     with an available secret key.  This is used by getkey_next to get
     the next result with the same initial criteria.  */
  int want_secret;

  /* Part of the search criteria: The type of the requested key.  A
     mask of PUBKEY_USAGE_SIG, PUBKEY_USAGE_ENC and PUBKEY_USAGE_CERT.
     If non-zero, then for a key to match, it must implement one of
     the required uses.  */
  int req_usage;

  /* The database handle.  */
  KEYDB_HANDLE kr_handle;

  /* Whether we should call xfree() on the context when the context is
     released using getkey_end()).  */
  int not_allocated;

  /* This variable is used as backing store for strings which have
     their address used in ITEMS.  */
  strlist_t extra_list;

  /* Hack to return the mechanism (AKL_foo) used to find the key.  */
  int found_via_akl;

  /* Part of the search criteria: The low-level search specification
     as passed to keydb_search.  */
  int nitems;
  /* This must be the last element in the structure.  When we allocate
     the structure, we allocate it so that ITEMS can hold NITEMS.  */
  KEYDB_SEARCH_DESC items[1];
};

#if 0
static struct
{
  int any;
  int okay_count;
  int nokey_count;
  int error_count;
} lkup_stats[21];
#endif

typedef struct keyid_list
{
  struct keyid_list *next;
  char fpr[MAX_FINGERPRINT_LEN];
  u32 keyid[2];
} *keyid_list_t;


#if MAX_PK_CACHE_ENTRIES
typedef struct pk_cache_entry
{
  struct pk_cache_entry *next;
  u32 keyid[2];
  PKT_public_key *pk;
} *pk_cache_entry_t;
static pk_cache_entry_t pk_cache;
static int pk_cache_entries;	/* Number of entries in pk cache.  */
static int pk_cache_disabled;
#endif

#if MAX_UID_CACHE_ENTRIES < 5
#error we really need the userid cache
#endif
typedef struct user_id_db
{
  struct user_id_db *next;
  keyid_list_t keyids;
  int len;
  char name[1];
} *user_id_db_t;
static user_id_db_t user_id_db;
static int uid_cache_entries;	/* Number of entries in uid cache. */

static void merge_selfsigs (ctrl_t ctrl, kbnode_t keyblock);
static int lookup (ctrl_t ctrl, getkey_ctx_t ctx, int want_secret,
		   kbnode_t *ret_keyblock, kbnode_t *ret_found_key);
static kbnode_t finish_lookup (kbnode_t keyblock,
                               unsigned int req_usage, int want_exact,
                               int want_secret, int allow_adsk,
                               unsigned int *r_flags);
static void print_status_key_considered (kbnode_t keyblock, unsigned int flags);


#if 0
static void
print_stats ()
{
  int i;
  for (i = 0; i < DIM (lkup_stats); i++)
    {
      if (lkup_stats[i].any)
	es_fprintf (es_stderr,
		 "lookup stats: mode=%-2d  ok=%-6d  nokey=%-6d  err=%-6d\n",
		 i,
		 lkup_stats[i].okay_count,
		 lkup_stats[i].nokey_count, lkup_stats[i].error_count);
    }
}
#endif


/* Cache a copy of a public key in the public key cache.  PK is not
 * cached if caching is disabled (via getkey_disable_caches), if
 * PK->FLAGS.DONT_CACHE is set, we don't know how to derive a key id
 * from the public key (e.g., unsupported algorithm), or a key with
 * the key id is already in the cache.
 *
 * The public key packet is copied into the cache using
 * copy_public_key.  Thus, any secret parts are not copied, for
 * instance.
 *
 * This cache is filled by get_pubkey and is read by get_pubkey and
 * get_pubkey_fast.  */
void
cache_public_key (PKT_public_key * pk)
{
#if MAX_PK_CACHE_ENTRIES
  pk_cache_entry_t ce, ce2;
  u32 keyid[2];

  if (pk_cache_disabled)
    return;

  if (pk->flags.dont_cache)
    return;

  if (is_ELGAMAL (pk->pubkey_algo)
      || pk->pubkey_algo == PUBKEY_ALGO_DSA
      || pk->pubkey_algo == PUBKEY_ALGO_ECDSA
      || pk->pubkey_algo == PUBKEY_ALGO_EDDSA
      || pk->pubkey_algo == PUBKEY_ALGO_ECDH
      || is_RSA (pk->pubkey_algo))
    {
      keyid_from_pk (pk, keyid);
    }
  else
    return; /* Don't know how to get the keyid.  */

  for (ce = pk_cache; ce; ce = ce->next)
    if (ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1])
      {
	if (DBG_CACHE)
	  log_debug ("cache_public_key: already in cache\n");
	return;
      }

  if (pk_cache_entries >= MAX_PK_CACHE_ENTRIES)
    {
      int n;

      /* Remove the last 50% of the entries.  */
      for (ce = pk_cache, n = 0; ce && n < pk_cache_entries/2; n++)
        ce = ce->next;
      if (ce && ce != pk_cache && ce->next)
        {
          ce2 = ce->next;
          ce->next = NULL;
          ce = ce2;
          for (; ce; ce = ce2)
            {
              ce2 = ce->next;
              free_public_key (ce->pk);
              xfree (ce);
              pk_cache_entries--;
            }
        }
      log_assert (pk_cache_entries < MAX_PK_CACHE_ENTRIES);
    }
  pk_cache_entries++;
  ce = xmalloc (sizeof *ce);
  ce->next = pk_cache;
  pk_cache = ce;
  ce->pk = copy_public_key (NULL, pk);
  ce->keyid[0] = keyid[0];
  ce->keyid[1] = keyid[1];
#endif
}


/* Return a const utf-8 string with the text "[User ID not found]".
   This function is required so that we don't need to switch gettext's
   encoding temporary.  */
static const char *
user_id_not_found_utf8 (void)
{
  static char *text;

  if (!text)
    text = native_to_utf8 (_("[User ID not found]"));
  return text;
}



/* Return the user ID from the given keyblock.
 * We use the primary uid flag which has been set by the merge_selfsigs
 * function.  The returned value is only valid as long as the given
 * keyblock is not changed.  */
static const char *
get_primary_uid (KBNODE keyblock, size_t * uidlen)
{
  KBNODE k;
  const char *s;

  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID
	  && !k->pkt->pkt.user_id->attrib_data
	  && k->pkt->pkt.user_id->flags.primary)
	{
	  *uidlen = k->pkt->pkt.user_id->len;
	  return k->pkt->pkt.user_id->name;
	}
    }
  s = user_id_not_found_utf8 ();
  *uidlen = strlen (s);
  return s;
}


static void
release_keyid_list (keyid_list_t k)
{
  while (k)
    {
      keyid_list_t k2 = k->next;
      xfree (k);
      k = k2;
    }
}

/****************
 * Store the association of keyid and userid
 * Feed only public keys to this function.
 */
static void
cache_user_id (KBNODE keyblock)
{
  user_id_db_t r;
  const char *uid;
  size_t uidlen;
  keyid_list_t keyids = NULL;
  KBNODE k;

  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_PUBLIC_KEY
	  || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  keyid_list_t a = xmalloc_clear (sizeof *a);
	  /* Hmmm: For a long list of keyids it might be an advantage
	   * to append the keys.  */
          fingerprint_from_pk (k->pkt->pkt.public_key, a->fpr, NULL);
	  keyid_from_pk (k->pkt->pkt.public_key, a->keyid);
	  /* First check for duplicates.  */
	  for (r = user_id_db; r; r = r->next)
	    {
	      keyid_list_t b;

	      for (b = r->keyids; b; b = b->next)
		{
		  if (!memcmp (b->fpr, a->fpr, MAX_FINGERPRINT_LEN))
		    {
		      if (DBG_CACHE)
			log_debug ("cache_user_id: already in cache\n");
		      release_keyid_list (keyids);
		      xfree (a);
		      return;
		    }
		}
	    }
	  /* Now put it into the cache.  */
	  a->next = keyids;
	  keyids = a;
	}
    }
  if (!keyids)
    BUG (); /* No key no fun.  */


  uid = get_primary_uid (keyblock, &uidlen);

  if (uid_cache_entries >= MAX_UID_CACHE_ENTRIES)
    {
      /* fixme: use another algorithm to free some cache slots */
      r = user_id_db;
      user_id_db = r->next;
      release_keyid_list (r->keyids);
      xfree (r);
      uid_cache_entries--;
    }
  r = xmalloc (sizeof *r + uidlen - 1);
  r->keyids = keyids;
  r->len = uidlen;
  memcpy (r->name, uid, r->len);
  r->next = user_id_db;
  user_id_db = r;
  uid_cache_entries++;
}


/* Disable and drop the public key cache (which is filled by
   cache_public_key and get_pubkey).  Note: there is currently no way
   to re-enable this cache.  */
void
getkey_disable_caches ()
{
#if MAX_PK_CACHE_ENTRIES
  {
    pk_cache_entry_t ce, ce2;

    for (ce = pk_cache; ce; ce = ce2)
      {
	ce2 = ce->next;
	free_public_key (ce->pk);
	xfree (ce);
      }
    pk_cache_disabled = 1;
    pk_cache_entries = 0;
    pk_cache = NULL;
  }
#endif
  /* fixme: disable user id cache ? */
}


/* Free a list of pubkey_t objects.  */
void
pubkeys_free (pubkey_t keys)
{
  while (keys)
    {
      pubkey_t next = keys->next;
      xfree (keys->pk);
      release_kbnode (keys->keyblock);
      xfree (keys);
      keys = next;
    }
}


static void
pk_from_block (PKT_public_key *pk, kbnode_t keyblock, kbnode_t found_key)
{
  kbnode_t a = found_key ? found_key : keyblock;

  log_assert (a->pkt->pkttype == PKT_PUBLIC_KEY
              || a->pkt->pkttype == PKT_PUBLIC_SUBKEY);

  copy_public_key (pk, a->pkt->pkt.public_key);
}


/* Specialized version of get_pubkey which retrieves the key based on
 * information in SIG.  In contrast to get_pubkey PK is required.  IF
 * FORCED_PK is not NULL, this public key is used and copied to PK. */
gpg_error_t
get_pubkey_for_sig (ctrl_t ctrl, PKT_public_key *pk, PKT_signature *sig,
                    PKT_public_key *forced_pk)
{
  const byte *fpr;
  size_t fprlen;

  if (forced_pk)
    {
      copy_public_key (pk, forced_pk);
      return 0;
    }

  /* First try the new ISSUER_FPR info.  */
  fpr = issuer_fpr_raw (sig, &fprlen);
  if (fpr && !get_pubkey_byfprint (ctrl, pk, NULL, fpr, fprlen))
    return 0;

  /* Fallback to use the ISSUER_KEYID.  */
  return get_pubkey (ctrl, pk, sig->keyid);
}


/* Return the public key with the key id KEYID and store it at PK.
 * The resources in *PK should be released using
 * release_public_key_parts().  This function also stores a copy of
 * the public key in the user id cache (see cache_public_key).
 *
 * If PK is NULL, this function just stores the public key in the
 * cache and returns the usual return code.
 *
 * PK->REQ_USAGE (which is a mask of PUBKEY_USAGE_SIG,
 * PUBKEY_USAGE_ENC and PUBKEY_USAGE_CERT) is passed through to the
 * lookup function.  If this is non-zero, only keys with the specified
 * usage will be returned.  As such, it is essential that
 * PK->REQ_USAGE be correctly initialized!
 *
 * Returns 0 on success, GPG_ERR_NO_PUBKEY if there is no public key
 * with the specified key id, or another error code if an error
 * occurs.
 *
 * If the data was not read from the cache, then the self-signed data
 * has definitely been merged into the public key using
 * merge_selfsigs.  */
int
get_pubkey (ctrl_t ctrl, PKT_public_key * pk, u32 * keyid)
{
  int internal = 0;
  int rc = 0;

#if MAX_PK_CACHE_ENTRIES
  if (pk)
    {
      /* Try to get it from the cache.  We don't do this when pk is
         NULL as it does not guarantee that the user IDs are
         cached. */
      pk_cache_entry_t ce;
      for (ce = pk_cache; ce; ce = ce->next)
	{
	  if (ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1])
	    /* XXX: We don't check PK->REQ_USAGE here, but if we don't
	       read from the cache, we do check it!  */
	    {
	      copy_public_key (pk, ce->pk);
	      return 0;
	    }
	}
    }
#endif
  /* More init stuff.  */
  if (!pk)
    {
      internal++;
      pk = xtrycalloc (1, sizeof *pk);
      if (!pk)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
    }


  /* Do a lookup.  */
  {
    struct getkey_ctx_s ctx;
    kbnode_t kb = NULL;
    kbnode_t found_key = NULL;

    memset (&ctx, 0, sizeof ctx);
    ctx.exact = 1; /* Use the key ID exactly as given.  */
    ctx.not_allocated = 1;

    if (ctrl && ctrl->cached_getkey_kdb)
      {
        ctx.kr_handle = ctrl->cached_getkey_kdb;
        ctrl->cached_getkey_kdb = NULL;
        keydb_search_reset (ctx.kr_handle);
      }
    else
      {
        ctx.kr_handle = keydb_new ();
        if (!ctx.kr_handle)
          {
            rc = gpg_error_from_syserror ();
            goto leave;
          }
      }
    ctx.nitems = 1;
    ctx.items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
    ctx.items[0].u.kid[0] = keyid[0];
    ctx.items[0].u.kid[1] = keyid[1];
    ctx.req_usage = pk->req_usage;
    rc = lookup (ctrl, &ctx, 0, &kb, &found_key);
    if (!rc)
      {
	pk_from_block (pk, kb, found_key);
      }
    getkey_end (ctrl, &ctx);
    release_kbnode (kb);
  }
  if (!rc)
    goto leave;

  rc = GPG_ERR_NO_PUBKEY;

leave:
  if (!rc)
    cache_public_key (pk);
  if (internal)
    free_public_key (pk);
  return rc;
}


/* Same as get_pubkey but if the key was not found the function tries
 * to import it from LDAP.  FIXME: We should not need this but swicth
 * to a fingerprint lookup.  */
gpg_error_t
get_pubkey_with_ldap_fallback (ctrl_t ctrl, PKT_public_key *pk, u32 *keyid)
{
  gpg_error_t err;

  err = get_pubkey (ctrl, pk, keyid);
  if (!err)
    return 0;

  if (gpg_err_code (err) != GPG_ERR_NO_PUBKEY)
    return err;

  /* Note that this code does not handle the case for two readers
   * having both openpgp encryption keys.  Only one will be tried.  */
  if (opt.debug)
    log_debug ("using LDAP to find a public key\n");
  err = keyserver_import_keyid (ctrl, keyid,
                                opt.keyserver, KEYSERVER_IMPORT_FLAG_LDAP);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA
      || gpg_err_code (err) == GPG_ERR_NO_KEYSERVER)
    {
      /* Dirmngr returns NO DATA is the selected keyserver
       * does not have the requested key.  It returns NO
       * KEYSERVER if no LDAP keyservers are configured.  */
      err = gpg_error (GPG_ERR_NO_PUBKEY);
    }
  if (err)
    return err;

  return get_pubkey (ctrl, pk, keyid);
}


/* Similar to get_pubkey, but it does not take PK->REQ_USAGE into
 * account nor does it merge in the self-signed data.  This function
 * also only considers primary keys.  It is intended to be used as a
 * quick check of the key to avoid recursion.  It should only be used
 * in very certain cases.  Like get_pubkey and unlike any of the other
 * lookup functions, this function also consults the user id cache
 * (see cache_public_key).
 *
 * Return the public key in *PK.  The resources in *PK should be
 * released using release_public_key_parts().  */
int
get_pubkey_fast (PKT_public_key * pk, u32 * keyid)
{
  int rc = 0;
  KEYDB_HANDLE hd;
  KBNODE keyblock;
  u32 pkid[2];

  log_assert (pk);
#if MAX_PK_CACHE_ENTRIES
  {
    /* Try to get it from the cache */
    pk_cache_entry_t ce;

    for (ce = pk_cache; ce; ce = ce->next)
      {
	if (ce->keyid[0] == keyid[0] && ce->keyid[1] == keyid[1]
	    /* Only consider primary keys.  */
	    && ce->pk->keyid[0] == ce->pk->main_keyid[0]
	    && ce->pk->keyid[1] == ce->pk->main_keyid[1])
	  {
	    if (pk)
	      copy_public_key (pk, ce->pk);
	    return 0;
	  }
      }
  }
#endif

  hd = keydb_new ();
  if (!hd)
    return gpg_error_from_syserror ();
  rc = keydb_search_kid (hd, keyid);
  if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
    {
      keydb_release (hd);
      return GPG_ERR_NO_PUBKEY;
    }
  rc = keydb_get_keyblock (hd, &keyblock);
  keydb_release (hd);
  if (rc)
    {
      log_error ("keydb_get_keyblock failed: %s\n", gpg_strerror (rc));
      return GPG_ERR_NO_PUBKEY;
    }

  log_assert (keyblock && keyblock->pkt
              && keyblock->pkt->pkttype == PKT_PUBLIC_KEY);

  /* We return the primary key.  If KEYID matched a subkey, then we
     return an error.  */
  keyid_from_pk (keyblock->pkt->pkt.public_key, pkid);
  if (keyid[0] == pkid[0] && keyid[1] == pkid[1])
    copy_public_key (pk, keyblock->pkt->pkt.public_key);
  else
    rc = GPG_ERR_NO_PUBKEY;

  release_kbnode (keyblock);

  /* Not caching key here since it won't have all of the fields
     properly set. */

  return rc;
}


/* Return the entire keyblock used to create SIG.  This is a
 * specialized version of get_pubkeyblock.
 *
 * FIXME: This is a hack because get_pubkey_for_sig was already called
 * and it could have used a cache to hold the key.  */
kbnode_t
get_pubkeyblock_for_sig (ctrl_t ctrl, PKT_signature *sig)
{
  const byte *fpr;
  size_t fprlen;
  kbnode_t keyblock;

  /* First try the new ISSUER_FPR info.  */
  fpr = issuer_fpr_raw (sig, &fprlen);
  if (fpr && !get_pubkey_byfprint (ctrl, NULL, &keyblock, fpr, fprlen))
    return keyblock;

  /* Fallback to use the ISSUER_KEYID.  */
  return get_pubkeyblock (ctrl, sig->keyid);
}


/* Return the key block for the key with key id KEYID or NULL, if an
 * error occurs.  Use release_kbnode() to release the key block.
 *
 * The self-signed data has already been merged into the public key
 * using merge_selfsigs.  */
kbnode_t
get_pubkeyblock_ext (ctrl_t ctrl, u32 * keyid, unsigned int flags)
{
  struct getkey_ctx_s ctx;
  int rc = 0;
  KBNODE keyblock = NULL;

  memset (&ctx, 0, sizeof ctx);
  /* No need to set exact here because we want the entire block.  */
  ctx.not_allocated = 1;
  ctx.kr_handle = keydb_new ();
  if (!ctx.kr_handle)
    return NULL;
  ctx.nitems = 1;
  ctx.items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
  ctx.items[0].u.kid[0] = keyid[0];
  ctx.items[0].u.kid[1] = keyid[1];
  ctx.allow_adsk = !!(flags & GET_PUBKEYBLOCK_FLAG_ADSK);
  rc = lookup (ctrl, &ctx, 0, &keyblock, NULL);
  getkey_end (ctrl, &ctx);

  return rc ? NULL : keyblock;
}


kbnode_t
get_pubkeyblock (ctrl_t ctrl, u32 * keyid)
{
  return get_pubkeyblock_ext (ctrl, keyid, 0);
}

/* Return the public key with the key id KEYID iff the secret key is
 * available and store it at PK.  The resources should be released
 * using release_public_key_parts().
 *
 * Unlike other lookup functions, PK may not be NULL.  PK->REQ_USAGE
 * is passed through to the lookup function and is a mask of
 * PUBKEY_USAGE_SIG, PUBKEY_USAGE_ENC and PUBKEY_USAGE_CERT.  Thus, it
 * must be valid!  If this is non-zero, only keys with the specified
 * usage will be returned.
 *
 * Returns 0 on success.  If a public key with the specified key id is
 * not found or a secret key is not available for that public key, an
 * error code is returned.  Note: this function ignores legacy keys.
 * An error code is also return if an error occurs.
 *
 * The self-signed data has already been merged into the public key
 * using merge_selfsigs.  */
gpg_error_t
get_seckey (ctrl_t ctrl, PKT_public_key *pk, u32 *keyid)
{
  gpg_error_t err;
  struct getkey_ctx_s ctx;
  kbnode_t keyblock = NULL;
  kbnode_t found_key = NULL;

  memset (&ctx, 0, sizeof ctx);
  ctx.exact = 1; /* Use the key ID exactly as given.  */
  ctx.not_allocated = 1;
  ctx.kr_handle = keydb_new ();
  if (!ctx.kr_handle)
    return gpg_error_from_syserror ();
  ctx.nitems = 1;
  ctx.items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
  ctx.items[0].u.kid[0] = keyid[0];
  ctx.items[0].u.kid[1] = keyid[1];
  ctx.req_usage = pk->req_usage;
  err = lookup (ctrl, &ctx, 1, &keyblock, &found_key);
  if (!err)
    {
      pk_from_block (pk, keyblock, found_key);
    }
  getkey_end (ctrl, &ctx);
  release_kbnode (keyblock);

  if (!err)
    {
      if (!agent_probe_secret_key (/*ctrl*/NULL, pk))
        {
          release_public_key_parts (pk);
          err = gpg_error (GPG_ERR_NO_SECKEY);
        }
    }

  return err;
}


/* Skip unusable keys.  A key is unusable if it is revoked, expired or
   disabled or if the selected user id is revoked or expired.  */
static int
skip_unusable (void *opaque, u32 * keyid, int uid_no)
{
  ctrl_t ctrl = opaque;
  int unusable = 0;
  KBNODE keyblock;
  PKT_public_key *pk;

  keyblock = get_pubkeyblock (ctrl, keyid);
  if (!keyblock)
    {
      log_error ("error checking usability status of %s\n", keystr (keyid));
      goto leave;
    }

  pk = keyblock->pkt->pkt.public_key;

  /* Is the key revoked or expired?  */
  if (pk->flags.revoked || pk->has_expired)
    unusable = 1;

  /* Is the user ID in question revoked or expired? */
  if (!unusable && uid_no)
    {
      KBNODE node;
      int uids_seen = 0;

      for (node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_USER_ID)
	    {
	      PKT_user_id *user_id = node->pkt->pkt.user_id;

	      uids_seen ++;
	      if (uids_seen != uid_no)
		continue;

	      if (user_id->flags.revoked || user_id->flags.expired)
		unusable = 1;

	      break;
	    }
	}

      /* If UID_NO is non-zero, then the keyblock better have at least
	 that many UIDs.  */
      log_assert (uids_seen == uid_no);
    }

  if (!unusable)
    unusable = pk_is_disabled (pk);

leave:
  release_kbnode (keyblock);
  return unusable;
}


/* Search for keys matching some criteria.

   If RETCTX is not NULL, then the constructed context is returned in
   *RETCTX so that getpubkey_next can be used to get subsequent
   results.  In this case, getkey_end() must be used to free the
   search context.  If RETCTX is not NULL, then RET_KDBHD must be
   NULL.

   If NAMELIST is not NULL, then a search query is constructed using
   classify_user_id on each of the strings in the list.  (Recall: the
   database does an OR of the terms, not an AND.)  If NAMELIST is
   NULL, then all results are returned.

   If PK is not NULL, the public key of the first result is returned
   in *PK.  Note: PK->REQ_USAGE must be valid!!!  If PK->REQ_USAGE is
   set, it is used to filter the search results.  See the
   documentation for finish_lookup to understand exactly how this is
   used.  Note: The self-signed data has already been merged into the
   public key using merge_selfsigs.  Free *PK by calling
   release_public_key_parts (or, if PK was allocated using xfree, you
   can use free_public_key, which calls release_public_key_parts(PK)
   and then xfree(PK)).

   If WANT_SECRET is set, then only keys with an available secret key
   (either locally or via key registered on a smartcard) are returned.

   If INCLUDE_UNUSABLE is set, then unusable keys (see the
   documentation for skip_unusable for an exact definition) are
   skipped unless they are looked up by key id or by fingerprint.

   If RET_KB is not NULL, the keyblock is returned in *RET_KB.  This
   should be freed using release_kbnode().

   If RET_KDBHD is not NULL, then the new database handle used to
   conduct the search is returned in *RET_KDBHD.  This can be used to
   get subsequent results using keydb_search_next.  Note: in this
   case, no advanced filtering is done for subsequent results (e.g.,
   WANT_SECRET and PK->REQ_USAGE are not respected).

   This function returns 0 on success.  Otherwise, an error code is
   returned.  In particular, GPG_ERR_NO_PUBKEY or GPG_ERR_NO_SECKEY
   (if want_secret is set) is returned if the key is not found.  */
static int
key_byname (ctrl_t ctrl, GETKEY_CTX *retctx, strlist_t namelist,
	    PKT_public_key *pk,
	    int want_secret, int include_unusable,
	    KBNODE * ret_kb, KEYDB_HANDLE * ret_kdbhd)
{
  int rc = 0;
  int n;
  strlist_t r;
  GETKEY_CTX ctx;
  KBNODE help_kb = NULL;
  KBNODE found_key = NULL;

  if (retctx)
    {
      /* Reset the returned context in case of error.  */
      log_assert (!ret_kdbhd); /* Not allowed because the handle is stored
                                  in the context.  */
      *retctx = NULL;
    }
  if (ret_kdbhd)
    *ret_kdbhd = NULL;

  if (!namelist)
    /* No search terms: iterate over the whole DB.  */
    {
      ctx = xmalloc_clear (sizeof *ctx);
      ctx->nitems = 1;
      ctx->items[0].mode = KEYDB_SEARCH_MODE_FIRST;
      if (!include_unusable)
        {
          ctx->items[0].skipfnc = skip_unusable;
          ctx->items[0].skipfncvalue = ctrl;
        }
    }
  else
    {
      /* Build the search context.  */
      for (n = 0, r = namelist; r; r = r->next)
	n++;

      /* CTX has space for a single search term at the end.  Thus, we
	 need to allocate sizeof *CTX plus (n - 1) sizeof
	 CTX->ITEMS.  */
      ctx = xmalloc_clear (sizeof *ctx + (n - 1) * sizeof ctx->items);
      ctx->nitems = n;

      for (n = 0, r = namelist; r; r = r->next, n++)
	{
	  gpg_error_t err;

	  err = classify_user_id (r->d, &ctx->items[n], 1);

	  if (ctx->items[n].exact)
	    ctx->exact = 1;
	  if (err)
	    {
	      xfree (ctx);
	      return gpg_err_code (err); /* FIXME: remove gpg_err_code.  */
	    }
	  if (!include_unusable
	      && ctx->items[n].mode != KEYDB_SEARCH_MODE_SHORT_KID
	      && ctx->items[n].mode != KEYDB_SEARCH_MODE_LONG_KID
	      && ctx->items[n].mode != KEYDB_SEARCH_MODE_FPR16
	      && ctx->items[n].mode != KEYDB_SEARCH_MODE_FPR20
	      && ctx->items[n].mode != KEYDB_SEARCH_MODE_FPR)
            {
              ctx->items[n].skipfnc = skip_unusable;
              ctx->items[n].skipfncvalue = ctrl;
            }
	}
    }

  ctx->want_secret = want_secret;
  ctx->kr_handle = keydb_new ();
  if (!ctx->kr_handle)
    {
      rc = gpg_error_from_syserror ();
      getkey_end (ctrl, ctx);
      return rc;
    }

  if (!ret_kb)
    ret_kb = &help_kb;

  if (pk)
    {
      ctx->req_usage = pk->req_usage;
    }

  rc = lookup (ctrl, ctx, want_secret, ret_kb, &found_key);
  if (!rc && pk)
    {
      pk_from_block (pk, *ret_kb, found_key);
    }

  release_kbnode (help_kb);

  if (retctx) /* Caller wants the context.  */
    *retctx = ctx;
  else
    {
      if (ret_kdbhd)
	{
	  *ret_kdbhd = ctx->kr_handle;
	  ctx->kr_handle = NULL;
	}
      getkey_end (ctrl, ctx);
    }

  return rc;
}


/* Find a public key identified by NAME.
 *
 * If name appears to be a valid RFC822 mailbox (i.e., email address)
 * and auto key lookup is enabled (mode != GET_PUBKEY_NO_AKL), then
 * the specified auto key lookup methods (--auto-key-lookup) are used
 * to import the key into the local keyring.  Otherwise, just the
 * local keyring is consulted.
 *
 * MODE can be one of:
 *    GET_PUBKEY_NORMAL   - The standard mode
 *    GET_PUBKEY_NO_AKL   - The auto key locate functionality is
 *                          disabled and only the local key ring is
 *                          considered.  Note: the local key ring is
 *                          consulted even if local is not in the
 *                          auto-key-locate option list!
 *    GET_PUBKEY_NO_LOCAL - Only the auto key locate functionaly is
 *                          used and no local search is done.
 *
 * If RETCTX is not NULL, then the constructed context is returned in
 * *RETCTX so that getpubkey_next can be used to get subsequent
 * results.  In this case, getkey_end() must be used to free the
 * search context.  If RETCTX is not NULL, then RET_KDBHD must be
 * NULL.
 *
 * If PK is not NULL, the public key of the first result is returned
 * in *PK.  Note: PK->REQ_USAGE must be valid!!!  PK->REQ_USAGE is
 * passed through to the lookup function and is a mask of
 * PUBKEY_USAGE_SIG, PUBKEY_USAGE_ENC and PUBKEY_USAGE_CERT.  If this
 * is non-zero, only keys with the specified usage will be returned.
 * Note: The self-signed data has already been merged into the public
 * key using merge_selfsigs.  Free *PK by calling
 * release_public_key_parts (or, if PK was allocated using xfree, you
 * can use free_public_key, which calls release_public_key_parts(PK)
 * and then xfree(PK)).
 *
 * NAME is a string, which is turned into a search query using
 * classify_user_id.
 *
 * If RET_KEYBLOCK is not NULL, the keyblock is returned in
 * *RET_KEYBLOCK.  This should be freed using release_kbnode().
 *
 * If RET_KDBHD is not NULL, then the new database handle used to
 * conduct the search is returned in *RET_KDBHD.  This can be used to
 * get subsequent results using keydb_search_next or to modify the
 * returned record.  Note: in this case, no advanced filtering is done
 * for subsequent results (e.g., PK->REQ_USAGE is not respected).
 * Unlike RETCTX, this is always returned.
 *
 * If INCLUDE_UNUSABLE is set, then unusable keys (see the
 * documentation for skip_unusable for an exact definition) are
 * skipped unless they are looked up by key id or by fingerprint.
 *
 * This function returns 0 on success.  Otherwise, an error code is
 * returned.  In particular, GPG_ERR_NO_PUBKEY or GPG_ERR_NO_SECKEY
 * (if want_secret is set) is returned if the key is not found.  */
int
get_pubkey_byname (ctrl_t ctrl, enum get_pubkey_modes mode,
                   GETKEY_CTX * retctx, PKT_public_key * pk,
		   const char *name, KBNODE * ret_keyblock,
		   KEYDB_HANDLE * ret_kdbhd, int include_unusable)
{
  int rc;
  strlist_t namelist = NULL;
  struct akl *akl;
  int is_mbox, is_fpr;
  KEYDB_SEARCH_DESC fprbuf;
  int nodefault = 0;
  int anylocalfirst = 0;
  int mechanism_type = AKL_NODEFAULT;
  size_t fprbuf_fprlen = 0;

  /* If RETCTX is not NULL, then RET_KDBHD must be NULL.  */
  log_assert (retctx == NULL || ret_kdbhd == NULL);

  if (retctx)
    *retctx = NULL;

  /* Does NAME appear to be a mailbox (mail address)?  */
  is_mbox = is_valid_mailbox (name);
  if (!is_mbox && *name == '<' && name[1] && name[strlen(name)-1]=='>'
      && name[1] != '>'
      && is_valid_mailbox_mem (name+1, strlen (name)-2))
    {
      /* The mailbox is in the form "<foo@example.org>" which is not
       * detected by is_valid_mailbox.  Set the flag but keep name as
       * it is because the bracketed name is actual the better
       * specification for a local search and the other methods
       * extract the mail address anyway.  */
      is_mbox = 1;
    }

  /* If we are called due to --locate-external-key Check whether NAME
   * is a fingerprint and then try to lookup that key by configured
   * method which support lookup by fingerprint.  FPRBUF carries the
   * parsed fingerpint iff IS_FPR is true.  */
  is_fpr = 0;
  if (!is_mbox && mode == GET_PUBKEY_NO_LOCAL)
    {
      if (!classify_user_id (name, &fprbuf, 1)
          && (fprbuf.mode == KEYDB_SEARCH_MODE_FPR16
              || fprbuf.mode == KEYDB_SEARCH_MODE_FPR20
              || fprbuf.mode == KEYDB_SEARCH_MODE_FPR))
        {
          /* Note: We should get rid of the FPR16 because we don't
           * support v3 keys anymore.  However, in 2.3 the fingerprint
           * code has already been reworked and thus it is
           * questionable whether we should really tackle this here.  */
          if (fprbuf.mode == KEYDB_SEARCH_MODE_FPR16)
            fprbuf_fprlen = 16;
          else
            fprbuf_fprlen = 20;
          is_fpr = 1;
        }
    }

  /* The auto-key-locate feature works as follows: there are a number
   * of methods to look up keys.  By default, the local keyring is
   * tried first.  Then, each method listed in the --auto-key-locate is
   * tried in the order it appears.
   *
   * This can be changed as follows:
   *
   *   - if nodefault appears anywhere in the list of options, then
   *     the local keyring is not tried first, or,
   *
   *   - if local appears anywhere in the list of options, then the
   *     local keyring is not tried first, but in the order in which
   *     it was listed in the --auto-key-locate option.
   *
   * Note: we only save the search context in RETCTX if the local
   * method is the first method tried (either explicitly or
   * implicitly).  */
  if (mode == GET_PUBKEY_NO_LOCAL)
    nodefault = 1;  /* Auto-key-locate but ignore "local".  */
  else if (mode != GET_PUBKEY_NO_AKL)
    {
      /* auto-key-locate is enabled.  */

      /* nodefault is true if "nodefault" or "local" appear.  */
      for (akl = opt.auto_key_locate; akl; akl = akl->next)
	if (akl->type == AKL_NODEFAULT || akl->type == AKL_LOCAL)
	  {
	    nodefault = 1;
	    break;
	  }
      /* anylocalfirst is true if "local" appears before any other
	 search methods (except "nodefault").  */
      for (akl = opt.auto_key_locate; akl; akl = akl->next)
	if (akl->type != AKL_NODEFAULT)
	  {
	    if (akl->type == AKL_LOCAL)
	      anylocalfirst = 1;
	    break;
	  }
    }

  if (!nodefault)
    {
      /* "nodefault" didn't occur.  Thus, "local" is implicitly the
       *  first method to try.  */
      anylocalfirst = 1;
    }

  if (mode == GET_PUBKEY_NO_LOCAL)
    {
      /* Force using the AKL.  If IS_MBOX is not set this is the final
       * error code.  */
      rc = GPG_ERR_NO_PUBKEY;
    }
  else if (nodefault && is_mbox)
    {
      /* Either "nodefault" or "local" (explicitly) appeared in the
       * auto key locate list and NAME appears to be an email address.
       * Don't try the local keyring.  */
      rc = GPG_ERR_NO_PUBKEY;
    }
  else
    {
      /* Either "nodefault" and "local" don't appear in the auto key
       * locate list (in which case we try the local keyring first) or
       * NAME does not appear to be an email address (in which case we
       * only try the local keyring).  In this case, lookup NAME in
       * the local keyring.  */
      add_to_strlist (&namelist, name);
      rc = key_byname (ctrl, retctx, namelist, pk, 0,
		       include_unusable, ret_keyblock, ret_kdbhd);
    }

  /* If the requested name resembles a valid mailbox and automatic
     retrieval has been enabled, we try to import the key. */
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
      && mode != GET_PUBKEY_NO_AKL
      && (is_mbox || is_fpr))
    {
      /* NAME wasn't present in the local keyring (or we didn't try
       * the local keyring).  Since the auto key locate feature is
       * enabled and NAME appears to be an email address, try the auto
       * locate feature.  */
      for (akl = opt.auto_key_locate; akl; akl = akl->next)
	{
	  unsigned char *fpr = NULL;
	  size_t fpr_len;
	  int did_akl_local = 0;
	  int no_fingerprint = 0;
	  const char *mechanism_string = "?";

          mechanism_type = akl->type;
	  switch (mechanism_type)
	    {
	    case AKL_NODEFAULT:
	      /* This is a dummy mechanism.  */
	      mechanism_string = "";
	      rc = GPG_ERR_NO_PUBKEY;
	      break;

	    case AKL_LOCAL:
              if (mode == GET_PUBKEY_NO_LOCAL)
                {
                  /* Note that we get here in is_fpr more, so there is
                   * no extra check for it required.  */
                  mechanism_string = "";
                  rc = GPG_ERR_NO_PUBKEY;
                }
              else
                {
                  mechanism_string = "Local";
                  did_akl_local = 1;
                  if (retctx)
                    {
                      getkey_end (ctrl, *retctx);
                      *retctx = NULL;
                    }
                  add_to_strlist (&namelist, name);
                  rc = key_byname (ctrl, anylocalfirst ? retctx : NULL,
                                   namelist, pk, 0,
                                   include_unusable, ret_keyblock, ret_kdbhd);
                }
	      break;

	    case AKL_CERT:
              if (is_fpr)
                {
                  mechanism_string = "";
                  rc = GPG_ERR_NO_PUBKEY;
                }
              else
                {
                  mechanism_string = "DNS CERT";
                  glo_ctrl.in_auto_key_retrieve++;
                  rc = keyserver_import_cert (ctrl, name, 0, &fpr, &fpr_len);
                  glo_ctrl.in_auto_key_retrieve--;
                }
              break;

	    case AKL_PKA:
              if (is_fpr)
                {
                  mechanism_string = "";
                  rc = GPG_ERR_NO_PUBKEY;
                }
              else
                {
                  mechanism_string = "PKA";
                  glo_ctrl.in_auto_key_retrieve++;
                  rc = keyserver_import_pka (ctrl, name, &fpr, &fpr_len);
                  glo_ctrl.in_auto_key_retrieve--;
                }
              break;

	    case AKL_DANE:
              if (is_fpr)
                {
                  mechanism_string = "";
                  rc = GPG_ERR_NO_PUBKEY;
                }
              else
                {
                  mechanism_string = "DANE";
                  glo_ctrl.in_auto_key_retrieve++;
                  rc = keyserver_import_cert (ctrl, name, 1, &fpr, &fpr_len);
                  glo_ctrl.in_auto_key_retrieve--;
                }
	      break;

	    case AKL_WKD:
              if (is_fpr)
                {
                  mechanism_string = "";
                  rc = GPG_ERR_NO_PUBKEY;
                }
              else
                {
                  mechanism_string = "WKD";
                  glo_ctrl.in_auto_key_retrieve++;
                  rc = keyserver_import_wkd (ctrl, name, 0, &fpr, &fpr_len);
                  glo_ctrl.in_auto_key_retrieve--;
                }
	      break;

	    case AKL_LDAP:
              if (is_fpr)
                {
                  mechanism_string = "";
                  rc = GPG_ERR_NO_PUBKEY;
                }
              else
                {
                  mechanism_string = "LDAP";
                  glo_ctrl.in_auto_key_retrieve++;
                  rc = keyserver_import_ldap (ctrl, name, &fpr, &fpr_len);
                  glo_ctrl.in_auto_key_retrieve--;
                }
              break;

	    case AKL_NTDS:
	      mechanism_string = "NTDS";
	      glo_ctrl.in_auto_key_retrieve++;
              if (is_fpr)
                rc = keyserver_import_fprint_ntds (ctrl,
                                                   fprbuf.u.fpr, fprbuf_fprlen);
              else
                rc = keyserver_import_ntds (ctrl, name, &fpr, &fpr_len);
	      glo_ctrl.in_auto_key_retrieve--;
	      break;

	    case AKL_KEYSERVER:
	      /* Strictly speaking, we don't need to only use a valid
	       * mailbox for the getname search, but it helps cut down
	       * on the problem of searching for something like "john"
	       * and getting a whole lot of keys back. */
	      if (keyserver_any_configured (ctrl))
		{
		  mechanism_string = "keyserver";
		  glo_ctrl.in_auto_key_retrieve++;
                  if (is_fpr)
                    {
                      rc = keyserver_import_fprint (ctrl,
                                                    fprbuf.u.fpr, fprbuf_fprlen,
                                                    opt.keyserver,
                                                    KEYSERVER_IMPORT_FLAG_LDAP);
                      /* Map error codes because Dirmngr returns NO
                       * DATA if the keyserver does not have the
                       * requested key.  It returns NO KEYSERVER if no
                       * LDAP keyservers are configured.  */
                      if (gpg_err_code (rc) == GPG_ERR_NO_DATA
                          || gpg_err_code (rc) == GPG_ERR_NO_KEYSERVER)
                        rc = gpg_error (GPG_ERR_NO_PUBKEY);
                    }
                  else
                    {
                      rc = keyserver_import_mbox (ctrl, name, &fpr, &fpr_len,
                                                  opt.keyserver);
                    }
		  glo_ctrl.in_auto_key_retrieve--;
		}
	      else
		{
		  mechanism_string = "Unconfigured keyserver";
		  rc = GPG_ERR_NO_PUBKEY;
		}
	      break;

	    case AKL_SPEC:
	      {
		struct keyserver_spec *keyserver;

		mechanism_string = akl->spec->uri;
		keyserver = keyserver_match (akl->spec);
		glo_ctrl.in_auto_key_retrieve++;
                if (is_fpr)
                  {
                    rc = keyserver_import_fprint (ctrl,
                                                  fprbuf.u.fpr, fprbuf_fprlen,
                                                  opt.keyserver,
                                                  KEYSERVER_IMPORT_FLAG_LDAP);
                    if (gpg_err_code (rc) == GPG_ERR_NO_DATA
                        || gpg_err_code (rc) == GPG_ERR_NO_KEYSERVER)
                      rc = gpg_error (GPG_ERR_NO_PUBKEY);
                  }
                else
                  {
                    rc = keyserver_import_mbox (ctrl, name,
                                                &fpr, &fpr_len, keyserver);
                  }
		glo_ctrl.in_auto_key_retrieve--;
	      }
	      break;
	    }

	  /* Use the fingerprint of the key that we actually fetched.
	   * This helps prevent problems where the key that we fetched
	   * doesn't have the same name that we used to fetch it.  In
	   * the case of CERT and PKA, this is an actual security
	   * requirement as the URL might point to a key put in by an
	   * attacker.  By forcing the use of the fingerprint, we
	   * won't use the attacker's key here. */
	  if (!rc && (fpr || is_fpr))
	    {
	      char fpr_string[MAX_FINGERPRINT_LEN * 2 + 1];

              if (is_fpr)
                {
                  log_assert (fprbuf_fprlen <= MAX_FINGERPRINT_LEN);
                  bin2hex (fprbuf.u.fpr, fprbuf_fprlen, fpr_string);
                }
              else
                {
                  log_assert (fpr_len <= MAX_FINGERPRINT_LEN);
                  bin2hex (fpr, fpr_len, fpr_string);
                }

	      if (opt.verbose)
		log_info ("auto-key-locate found fingerprint %s\n",
			  fpr_string);

	      free_strlist (namelist);
	      namelist = NULL;
	      add_to_strlist (&namelist, fpr_string);
	    }
	  else if (!rc && !fpr && !did_akl_local)
            { /* The acquisition method said no failure occurred, but
               * it didn't return a fingerprint.  That's a failure.  */
              no_fingerprint = 1;
	      rc = GPG_ERR_NO_PUBKEY;
	    }
	  xfree (fpr);
	  fpr = NULL;

	  if (!rc && !did_akl_local)
            { /* There was no error and we didn't do a local lookup.
	       * This means that we imported a key into the local
	       * keyring.  Try to read the imported key from the
	       * keyring.  */
	      if (retctx)
		{
		  getkey_end (ctrl, *retctx);
		  *retctx = NULL;
		}
	      rc = key_byname (ctrl, anylocalfirst ? retctx : NULL,
			       namelist, pk, 0,
			       include_unusable, ret_keyblock, ret_kdbhd);
	    }
	  if (!rc)
	    {
	      /* Key found.  */
              if (opt.verbose)
                log_info (_("automatically retrieved '%s' via %s\n"),
                          name, mechanism_string);
	      break;
	    }
	  if ((gpg_err_code (rc) != GPG_ERR_NO_PUBKEY
               || opt.verbose || no_fingerprint) && *mechanism_string)
	    log_info (_("error retrieving '%s' via %s: %s\n"),
		      name, mechanism_string,
		      no_fingerprint ? _("No fingerprint") : gpg_strerror (rc));
	}
    }

  if (rc && retctx)
    {
      getkey_end (ctrl, *retctx);
      *retctx = NULL;
    }

  if (retctx && *retctx)
    {
      log_assert (!(*retctx)->extra_list);
      (*retctx)->extra_list = namelist;
      (*retctx)->found_via_akl = mechanism_type;
    }
  else
    free_strlist (namelist);

  return rc;
}




/* Comparison machinery for get_best_pubkey_byname.  */

/* First we have a struct to cache computed information about the key
 * in question.  */
struct pubkey_cmp_cookie
{
  int valid;			/* Is this cookie valid?  */
  PKT_public_key key;		/* The key.  */
  PKT_user_id *uid;		/* The matching UID packet.  */
  unsigned int validity;	/* Computed validity of (KEY, UID).  */
  u32 creation_time;		/* Creation time of the newest subkey
                                   capable of encryption.  */
};


/* Then we have a series of helper functions.  */
static int
key_is_ok (const PKT_public_key *key)
{
  return (! key->has_expired && ! key->flags.revoked
          && key->flags.valid && ! key->flags.disabled);
}


static int
uid_is_ok (const PKT_public_key *key, const PKT_user_id *uid)
{
  return key_is_ok (key) && ! uid->flags.revoked;
}


static int
subkey_is_ok (const PKT_public_key *sub)
{
  return ! sub->flags.revoked && sub->flags.valid && ! sub->flags.disabled;
}

/* Return true if KEYBLOCK has only expired encryption subkyes.  Note
 * that the function returns false if the key has no encryption
 * subkeys at all or the subkeys are revoked.  */
static int
only_expired_enc_subkeys (kbnode_t keyblock)
{
  kbnode_t node;
  PKT_public_key *sub;
  int any = 0;

  for (node = find_next_kbnode (keyblock, PKT_PUBLIC_SUBKEY);
       node; node = find_next_kbnode (node, PKT_PUBLIC_SUBKEY))
    {
      sub = node->pkt->pkt.public_key;

      if (!(sub->pubkey_usage & PUBKEY_USAGE_ENC))
        continue;

      if (!subkey_is_ok (sub))
        continue;

      any = 1;
      if (!sub->has_expired)
        return 0;
    }

  return any? 1 : 0;
}

/* Finally this function compares a NEW key to the former candidate
 * OLD.  Returns < 0 if the old key is worse, > 0 if the old key is
 * better, == 0 if it is a tie.  */
static int
pubkey_cmp (ctrl_t ctrl, const char *name, struct pubkey_cmp_cookie *old,
            struct pubkey_cmp_cookie *new, KBNODE new_keyblock)
{
  kbnode_t n;

  new->creation_time = 0;
  for (n = find_next_kbnode (new_keyblock, PKT_PUBLIC_SUBKEY);
       n; n = find_next_kbnode (n, PKT_PUBLIC_SUBKEY))
    {
      PKT_public_key *sub = n->pkt->pkt.public_key;

      if ((sub->pubkey_usage & PUBKEY_USAGE_ENC) == 0)
        continue;

      if (! subkey_is_ok (sub))
        continue;

      if (sub->timestamp > new->creation_time)
        new->creation_time = sub->timestamp;
    }

  for (n = find_next_kbnode (new_keyblock, PKT_USER_ID);
       n; n = find_next_kbnode (n, PKT_USER_ID))
    {
      PKT_user_id *uid = n->pkt->pkt.user_id;
      char *mbox = mailbox_from_userid (uid->name);
      int match = mbox ? strcasecmp (name, mbox) == 0 : 0;

      xfree (mbox);
      if (! match)
        continue;

      new->uid = scopy_user_id (uid);
      new->validity =
        get_validity (ctrl, new_keyblock, &new->key, uid, NULL, 0) & TRUST_MASK;
      new->valid = 1;

      if (! old->valid)
        return -1;	/* No OLD key.  */

      if (! uid_is_ok (&old->key, old->uid) && uid_is_ok (&new->key, uid))
        return -1;	/* Validity of the NEW key is better.  */

      if (old->validity < new->validity)
        return -1;	/* Validity of the NEW key is better.  */

      if (old->validity == new->validity && uid_is_ok (&new->key, uid)
          && old->creation_time < new->creation_time)
        return -1;	/* Both keys are of the same validity, but the
                           NEW key is newer.  */
    }

  /* Stick with the OLD key.  */
  return 1;
}


/* This function works like get_pubkey_byname, but if the name
 * resembles a mail address, the results are ranked and only the best
 * result is returned.  */
gpg_error_t
get_best_pubkey_byname (ctrl_t ctrl, enum get_pubkey_modes mode,
                        GETKEY_CTX *retctx, PKT_public_key *pk,
                        const char *name, KBNODE *ret_keyblock,
                        int include_unusable)
{
  gpg_error_t err;
  struct getkey_ctx_s *ctx = NULL;
  int is_mbox;
  int wkd_tried = 0;

  if (retctx)
    *retctx = NULL;

  is_mbox = is_valid_mailbox (name);
  if (!is_mbox && *name == '<' && name[1] && name[strlen(name)-1]=='>'
      && name[1] != '>'
      && is_valid_mailbox_mem (name+1, strlen (name)-2))
    {
      /* The mailbox is in the form "<foo@example.org>" which is not
       * detected by is_valid_mailbox.  Set the flag but keep name as
       * it is because get_pubkey_byname does an is_valid_mailbox_mem
       * itself.  */
      is_mbox = 1;
    }

 start_over:
  if (ctx)  /* Clear  in case of a start over.  */
    {
      if (ret_keyblock)
        {
          release_kbnode (*ret_keyblock);
          *ret_keyblock = NULL;
        }
      getkey_end (ctrl, ctx);
      ctx = NULL;
    }
  err = get_pubkey_byname (ctrl, mode,
                           &ctx, pk, name, ret_keyblock,
                           NULL, include_unusable);
  if (err)
    {
      goto leave;
    }

  /* If the keyblock was retrieved from the local database and the key
   * has expired, do further checks.  However, we can do this only if
   * the caller requested a keyblock.  */
  if (is_mbox && ctx && ctx->found_via_akl == AKL_LOCAL && ret_keyblock)
    {
      u32 now = make_timestamp ();
      PKT_public_key *pk2 = (*ret_keyblock)->pkt->pkt.public_key;
      int found;

      /* If the key has expired and its origin was the WKD then try to
       * get a fresh key from the WKD.  We also try this if the key
       * has any only expired encryption subkeys.  In case we checked
       * for a fresh copy in the last 3 hours we won't do that again.
       * Unfortunately that does not yet work because KEYUPDATE is
       * only updated during import iff the key has actually changed
       * (see import.c:import_one).  */
      if (!wkd_tried && pk2->keyorg == KEYORG_WKD
          && (pk2->keyupdate + 3*3600) < now
          && (pk2->has_expired || only_expired_enc_subkeys (*ret_keyblock)))
        {
          if (opt.verbose)
            log_info (_("checking for a fresh copy of an expired key via %s\n"),
                      "WKD");
          wkd_tried = 1;
          glo_ctrl.in_auto_key_retrieve++;
          found = !keyserver_import_wkd (ctrl, name, 0, NULL, NULL);
          glo_ctrl.in_auto_key_retrieve--;
          if (found)
            goto start_over;
        }
    }

  if (is_mbox && ctx)
    {
      /* Rank results and return only the most relevant key.  */
      struct pubkey_cmp_cookie best = { 0 };
      struct pubkey_cmp_cookie new = { 0 };
      kbnode_t new_keyblock;

      while (getkey_next (ctrl, ctx, &new.key, &new_keyblock) == 0)
        {
          int diff = pubkey_cmp (ctrl, name, &best, &new, new_keyblock);
          release_kbnode (new_keyblock);
          if (diff < 0)
            {
              /* New key is better.  */
              release_public_key_parts (&best.key);
              free_user_id (best.uid);
              best = new;
            }
          else if (diff > 0)
            {
              /* Old key is better.  */
              release_public_key_parts (&new.key);
              free_user_id (new.uid);
            }
          else
            {
              /* A tie.  Keep the old key.  */
              release_public_key_parts (&new.key);
              free_user_id (new.uid);
            }
          new.uid = NULL;
        }
      getkey_end (ctrl, ctx);
      ctx = NULL;
      free_user_id (best.uid);
      best.uid = NULL;

      if (best.valid)
        {
          if (retctx || ret_keyblock)
            {
              ctx = xtrycalloc (1, sizeof **retctx);
              if (! ctx)
                err = gpg_error_from_syserror ();
              else
                {
                  ctx->kr_handle = keydb_new ();
                  if (! ctx->kr_handle)
                    {
                      err = gpg_error_from_syserror ();
                      xfree (ctx);
                      ctx = NULL;
                      if (retctx)
                        *retctx = NULL;
                    }
                  else
                    {
                      u32 *keyid = pk_keyid (&best.key);
                      ctx->exact = 1;
                      ctx->nitems = 1;
                      ctx->items[0].mode = KEYDB_SEARCH_MODE_LONG_KID;
                      ctx->items[0].u.kid[0] = keyid[0];
                      ctx->items[0].u.kid[1] = keyid[1];

                      if (ret_keyblock)
                        {
                          release_kbnode (*ret_keyblock);
                          *ret_keyblock = NULL;
                          err = getkey_next (ctrl, ctx, NULL, ret_keyblock);
                        }
                    }
                }
            }

          if (pk)
            {
              release_public_key_parts (pk);
              *pk = best.key;
            }
          else
            release_public_key_parts (&best.key);
        }
    }

  if (err && ctx)
    {
      getkey_end (ctrl, ctx);
      ctx = NULL;
    }

  if (retctx && ctx)
    {
      *retctx = ctx;
      ctx = NULL;
    }

 leave:
  getkey_end (ctrl, ctx);
  return err;
}



/* Get a public key from a file.
 *
 * PK is the buffer to store the key.  The caller needs to make sure
 * that PK->REQ_USAGE is valid.  PK->REQ_USAGE is passed through to
 * the lookup function and is a mask of PUBKEY_USAGE_SIG,
 * PUBKEY_USAGE_ENC and PUBKEY_USAGE_CERT.  If this is non-zero, only
 * keys with the specified usage will be returned.
 *
 * FNAME is the file name.  That file should contain exactly one
 * keyblock.
 *
 * This function returns 0 on success.  Otherwise, an error code is
 * returned.  In particular, GPG_ERR_NO_PUBKEY is returned if the key
 * is not found.  If R_KEYBLOCK is not NULL and a key was found the
 * keyblock is stored there; otherwiese NULL is stored there.
 *
 * The self-signed data has already been merged into the public key
 * using merge_selfsigs.  The caller must release the content of PK by
 * calling release_public_key_parts (or, if PK was malloced, using
 * free_public_key).
 */
gpg_error_t
get_pubkey_fromfile (ctrl_t ctrl, PKT_public_key *pk, const char *fname,
                     kbnode_t *r_keyblock)
{
  gpg_error_t err;
  kbnode_t keyblock;
  kbnode_t found_key;
  unsigned int infoflags;

  if (r_keyblock)
    *r_keyblock = NULL;

  err = read_key_from_file_or_buffer (ctrl, fname, NULL, 0, &keyblock);
  if (!err)
    {
      /* Warning: node flag bits 0 and 1 should be preserved by
       * merge_selfsigs.  FIXME: Check whether this still holds. */
      merge_selfsigs (ctrl, keyblock);
      found_key = finish_lookup (keyblock, pk->req_usage, 0, 0, 0, &infoflags);
      print_status_key_considered (keyblock, infoflags);
      if (found_key)
        pk_from_block (pk, keyblock, found_key);
      else
        err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
    }

  if (!err && r_keyblock)
    *r_keyblock = keyblock;
  else
    release_kbnode (keyblock);
  return err;
}


/* Return a public key from the buffer (BUFFER, BUFLEN).  The key is
 * onlyretruned if it matches the keyid given in WANT_KEYID. On
 * success the key is stored at the caller provided PKBUF structure.
 * The caller must release the content of PK by calling
 * release_public_key_parts (or, if PKBUF was malloced, using
 * free_public_key).  If R_KEYBLOCK is not NULL the full keyblock is
 * also stored there.  */
gpg_error_t
get_pubkey_from_buffer (ctrl_t ctrl, PKT_public_key *pkbuf,
                        const void *buffer, size_t buflen, u32 *want_keyid,
                        kbnode_t *r_keyblock)
{
  gpg_error_t err;
  kbnode_t keyblock;
  kbnode_t node;
  PKT_public_key *pk;

  if (r_keyblock)
    *r_keyblock = NULL;

  err = read_key_from_file_or_buffer (ctrl, NULL, buffer, buflen, &keyblock);
  if (!err)
    {
      merge_selfsigs (ctrl, keyblock);
      for (node = keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_PUBLIC_KEY
              || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
            {
              pk = node->pkt->pkt.public_key;
              keyid_from_pk (pk, NULL);
              if (pk->keyid[0] == want_keyid[0]
                  && pk->keyid[1] == want_keyid[1])
                break;
            }
        }
      if (node)
        copy_public_key (pkbuf, pk);
      else
        err = gpg_error (GPG_ERR_NO_PUBKEY);
    }

  if (!err && r_keyblock)
    *r_keyblock = keyblock;
  else
    release_kbnode (keyblock);
  return err;
}


/* Lookup a key with the specified fingerprint.
 *
 * If PK is not NULL, the public key of the first result is returned
 * in *PK.  Note: this function does an exact search and thus the
 * returned public key may be a subkey rather than the primary key.
 * Note: The self-signed data has already been merged into the public
 * key using merge_selfsigs.  Free *PK by calling
 * release_public_key_parts (or, if PK was allocated using xmalloc, you
 * can use free_public_key, which calls release_public_key_parts(PK)
 * and then xfree(PK)).
 *
 * If PK->REQ_USAGE is set, it is used to filter the search results.
 * Thus, if PK is not NULL, PK->REQ_USAGE must be valid!  See the
 * documentation for finish_lookup to understand exactly how this is
 * used.
 *
 * If R_KEYBLOCK is not NULL, then the first result's keyblock is
 * returned in *R_KEYBLOCK.  This should be freed using
 * release_kbnode().
 *
 * FPRINT is a byte array whose contents is the fingerprint to use as
 * the search term.  FPRINT_LEN specifies the length of the
 * fingerprint (in bytes).  Currently, only 16 and 20-byte
 * fingerprints are supported.
 *
 * FIXME: We should replace this with the _byname function.  This can
 * be done by creating a userID conforming to the unified fingerprint
 * style.  */
int
get_pubkey_byfprint (ctrl_t ctrl, PKT_public_key *pk, kbnode_t *r_keyblock,
		     const byte * fprint, size_t fprint_len)
{
  int rc;

  if (r_keyblock)
    *r_keyblock = NULL;

  if (fprint_len == 20 || fprint_len == 16)
    {
      struct getkey_ctx_s ctx;
      KBNODE kb = NULL;
      KBNODE found_key = NULL;

      memset (&ctx, 0, sizeof ctx);
      ctx.exact = 1;
      ctx.not_allocated = 1;
      /* FIXME: We should get the handle from the cache like we do in
       * get_pubkey.  */
      ctx.kr_handle = keydb_new ();
      if (!ctx.kr_handle)
        return gpg_error_from_syserror ();

      ctx.nitems = 1;
      ctx.items[0].mode = fprint_len == 16 ? KEYDB_SEARCH_MODE_FPR16
	: KEYDB_SEARCH_MODE_FPR20;
      memcpy (ctx.items[0].u.fpr, fprint, fprint_len);
      if (pk)
        ctx.req_usage = pk->req_usage;
      rc = lookup (ctrl, &ctx, 0, &kb, &found_key);
      if (!rc && pk)
	pk_from_block (pk, kb, found_key);
      if (!rc && r_keyblock)
	{
	  *r_keyblock = kb;
	  kb = NULL;
	}
      release_kbnode (kb);
      getkey_end (ctrl, &ctx);
    }
  else
    rc = GPG_ERR_GENERAL; /* Oops */
  return rc;
}


/* This function is similar to get_pubkey_byfprint, but it doesn't
 * merge the self-signed data into the public key and subkeys or into
 * the user ids.  It also doesn't add the key to the user id cache.
 * Further, this function ignores PK->REQ_USAGE.
 *
 * This function is intended to avoid recursion and, as such, should
 * only be used in very specific situations.
 *
 * Like get_pubkey_byfprint, PK may be NULL.  In that case, this
 * function effectively just checks for the existence of the key.  */
gpg_error_t
get_pubkey_byfprint_fast (PKT_public_key * pk,
			  const byte * fprint, size_t fprint_len)
{
  gpg_error_t err;
  KBNODE keyblock;

  err = get_keyblock_byfprint_fast (&keyblock, NULL, fprint, fprint_len, 0);
  if (!err)
    {
      if (pk)
        copy_public_key (pk, keyblock->pkt->pkt.public_key);
      release_kbnode (keyblock);
    }

  return err;
}


/* This function is similar to get_pubkey_byfprint_fast but returns a
 * keydb handle at R_HD and the keyblock at R_KEYBLOCK.  R_KEYBLOCK or
 * R_HD may be NULL.  If LOCK is set the handle has been opend in
 * locked mode and keydb_disable_caching () has been called.  On error
 * R_KEYBLOCK is set to NULL but R_HD must be released by the caller;
 * it may have a value of NULL, though.  This allows to do an insert
 * operation on a locked keydb handle.  */
gpg_error_t
get_keyblock_byfprint_fast (kbnode_t *r_keyblock, KEYDB_HANDLE *r_hd,
                            const byte *fprint, size_t fprint_len, int lock)
{
  gpg_error_t err;
  KEYDB_HANDLE hd;
  kbnode_t keyblock;
  byte fprbuf[MAX_FINGERPRINT_LEN];
  int i;

  if (r_keyblock)
    *r_keyblock = NULL;
  if (r_hd)
    *r_hd = NULL;

  for (i = 0; i < MAX_FINGERPRINT_LEN && i < fprint_len; i++)
    fprbuf[i] = fprint[i];
  while (i < MAX_FINGERPRINT_LEN)
    fprbuf[i++] = 0;

  hd = keydb_new ();
  if (!hd)
    return gpg_error_from_syserror ();

  if (lock)
    {
      err = keydb_lock (hd);
      if (err)
        {
          /* If locking did not work, we better don't return a handle
           * at all - there was a reason that locking has been
           * requested.  */
          keydb_release (hd);
          return err;
        }
      keydb_disable_caching (hd);
    }

  /* Fo all other errors we return the handle.  */
  if (r_hd)
    *r_hd = hd;

  err = keydb_search_fpr (hd, fprbuf);
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    {
      if (!r_hd)
        keydb_release (hd);
      return gpg_error (GPG_ERR_NO_PUBKEY);
    }
  err = keydb_get_keyblock (hd, &keyblock);
  if (err)
    {
      log_error ("keydb_get_keyblock failed: %s\n", gpg_strerror (err));
      if (!r_hd)
        keydb_release (hd);
      return gpg_error (GPG_ERR_NO_PUBKEY);
    }

  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY
              || keyblock->pkt->pkttype == PKT_PUBLIC_SUBKEY);

  /* Not caching key here since it won't have all of the fields
     properly set. */

  if (r_keyblock)
    *r_keyblock = keyblock;
  else
    release_kbnode (keyblock);

  if (!r_hd)
    keydb_release (hd);

  return 0;
}


const char *
parse_def_secret_key (ctrl_t ctrl)
{
  KEYDB_HANDLE hd = NULL;
  strlist_t t;
  static int warned;

  for (t = opt.def_secret_key; t; t = t->next)
    {
      gpg_error_t err;
      KEYDB_SEARCH_DESC desc;
      KBNODE kb;
      KBNODE node;

      err = classify_user_id (t->d, &desc, 1);
      if (err)
        {
          log_error (_("secret key \"%s\" not found: %s\n"),
                     t->d, gpg_strerror (err));
          if (!opt.quiet)
            log_info (_("(check argument of option '%s')\n"), "--default-key");
          continue;
        }

      if (! hd)
        {
          hd = keydb_new ();
          if (!hd)
            return NULL;
        }
      else
        keydb_search_reset (hd);


      err = keydb_search (hd, &desc, 1, NULL);
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
        continue;

      if (err)
        {
          log_error (_("key \"%s\" not found: %s\n"), t->d, gpg_strerror (err));
          t = NULL;
          break;
        }

      err = keydb_get_keyblock (hd, &kb);
      if (err)
        {
          log_error (_("error reading keyblock: %s\n"),
                     gpg_strerror (err));
          continue;
        }

      merge_selfsigs (ctrl, kb);

      err = gpg_error (GPG_ERR_NO_SECKEY);
      node = kb;
      do
        {
          PKT_public_key *pk = node->pkt->pkt.public_key;

          /* Check if the key is valid.  */
          if (pk->flags.revoked)
            {
              if (DBG_LOOKUP)
                log_debug ("not using %s as default key, %s",
                           keystr_from_pk (pk), "revoked");
              continue;
            }
          if (pk->has_expired)
            {
              if (DBG_LOOKUP)
                log_debug ("not using %s as default key, %s",
                           keystr_from_pk (pk), "expired");
              continue;
            }
          if (pk_is_disabled (pk))
            {
              if (DBG_LOOKUP)
                log_debug ("not using %s as default key, %s",
                           keystr_from_pk (pk), "disabled");
              continue;
            }

          if (agent_probe_secret_key (ctrl, pk))
            {
              /* This is a valid key.  */
              err = 0;
              break;
            }
        }
      while ((node = find_next_kbnode (node, PKT_PUBLIC_SUBKEY)));

      release_kbnode (kb);
      if (err)
        {
          if (! warned && ! opt.quiet)
            {
              log_info (_("Warning: not using '%s' as default key: %s\n"),
                        t->d, gpg_strerror (GPG_ERR_NO_SECKEY));
              print_reported_error (err, GPG_ERR_NO_SECKEY);
            }
        }
      else
        {
          if (! warned && ! opt.quiet)
            log_info (_("using \"%s\" as default secret key for signing\n"),
                      t->d);
          break;
        }
    }

  if (! warned && opt.def_secret_key && ! t)
    log_info (_("all values passed to '%s' ignored\n"),
              "--default-key");

  warned = 1;

  if (hd)
    keydb_release (hd);

  if (t)
    return t->d;
  return NULL;
}


/* Look up a secret key.
 *
 * If PK is not NULL, the public key of the first result is returned
 * in *PK.  Note: PK->REQ_USAGE must be valid!!!  If PK->REQ_USAGE is
 * set, it is used to filter the search results.  See the
 * documentation for finish_lookup to understand exactly how this is
 * used.  Note: The self-signed data has already been merged into the
 * public key using merge_selfsigs.  Free *PK by calling
 * release_public_key_parts (or, if PK was allocated using xfree, you
 * can use free_public_key, which calls release_public_key_parts(PK)
 * and then xfree(PK)).
 *
 * If --default-key was set, then the specified key is looked up.  (In
 * this case, the default key is returned even if it is considered
 * unusable.  See the documentation for skip_unusable for exactly what
 * this means.)
 *
 * Otherwise, this initiates a DB scan that returns all keys that are
 * usable (see previous paragraph for exactly what usable means) and
 * for which a secret key is available.
 *
 * This function returns the first match.  Additional results can be
 * returned using getkey_next.  */
gpg_error_t
get_seckey_default (ctrl_t ctrl, PKT_public_key *pk)
{
  gpg_error_t err;
  strlist_t namelist = NULL;
  int include_unusable = 1;


  const char *def_secret_key = parse_def_secret_key (ctrl);
  if (def_secret_key)
    add_to_strlist (&namelist, def_secret_key);
  else
    include_unusable = 0;

  err = key_byname (ctrl, NULL, namelist, pk, 1, include_unusable, NULL, NULL);

  free_strlist (namelist);

  return err;
}



/* Search for keys matching some criteria.
 *
 * If RETCTX is not NULL, then the constructed context is returned in
 * *RETCTX so that getpubkey_next can be used to get subsequent
 * results.  In this case, getkey_end() must be used to free the
 * search context.  If RETCTX is not NULL, then RET_KDBHD must be
 * NULL.
 *
 * If PK is not NULL, the public key of the first result is returned
 * in *PK.  Note: PK->REQ_USAGE must be valid!!!  If PK->REQ_USAGE is
 * set, it is used to filter the search results.  See the
 * documentation for finish_lookup to understand exactly how this is
 * used.  Note: The self-signed data has already been merged into the
 * public key using merge_selfsigs.  Free *PK by calling
 * release_public_key_parts (or, if PK was allocated using xfree, you
 * can use free_public_key, which calls release_public_key_parts(PK)
 * and then xfree(PK)).
 *
 * If NAMES is not NULL, then a search query is constructed using
 * classify_user_id on each of the strings in the list.  (Recall: the
 * database does an OR of the terms, not an AND.)  If NAMES is
 * NULL, then all results are returned.
 *
 * If WANT_SECRET is set, then only keys with an available secret key
 * (either locally or via key registered on a smartcard) are returned.
 *
 * This function does not skip unusable keys (see the documentation
 * for skip_unusable for an exact definition).
 *
 * If RET_KEYBLOCK is not NULL, the keyblock is returned in
 * *RET_KEYBLOCK.  This should be freed using release_kbnode().
 *
 * This function returns 0 on success.  Otherwise, an error code is
 * returned.  In particular, GPG_ERR_NO_PUBKEY or GPG_ERR_NO_SECKEY
 * (if want_secret is set) is returned if the key is not found.  */
gpg_error_t
getkey_bynames (ctrl_t ctrl, getkey_ctx_t *retctx, PKT_public_key *pk,
                strlist_t names, int want_secret, kbnode_t *ret_keyblock)
{
  return key_byname (ctrl, retctx, names, pk, want_secret, 1,
                     ret_keyblock, NULL);
}


/* Search for one key matching some criteria.
 *
 * If RETCTX is not NULL, then the constructed context is returned in
 * *RETCTX so that getpubkey_next can be used to get subsequent
 * results.  In this case, getkey_end() must be used to free the
 * search context.  If RETCTX is not NULL, then RET_KDBHD must be
 * NULL.
 *
 * If PK is not NULL, the public key of the first result is returned
 * in *PK.  Note: PK->REQ_USAGE must be valid!!!  If PK->REQ_USAGE is
 * set, it is used to filter the search results.  See the
 * documentation for finish_lookup to understand exactly how this is
 * used.  Note: The self-signed data has already been merged into the
 * public key using merge_selfsigs.  Free *PK by calling
 * release_public_key_parts (or, if PK was allocated using xfree, you
 * can use free_public_key, which calls release_public_key_parts(PK)
 * and then xfree(PK)).
 *
 * If NAME is not NULL, then a search query is constructed using
 * classify_user_id on the string.  In this case, even unusable keys
 * (see the documentation for skip_unusable for an exact definition of
 * unusable) are returned.  Otherwise, if --default-key was set, then
 * that key is returned (even if it is unusable).  If neither of these
 * conditions holds, then the first usable key is returned.
 *
 * If WANT_SECRET is set, then only keys with an available secret key
 * (either locally or via key registered on a smartcard) are returned.
 *
 * This function does not skip unusable keys (see the documentation
 * for skip_unusable for an exact definition).
 *
 * If RET_KEYBLOCK is not NULL, the keyblock is returned in
 * *RET_KEYBLOCK.  This should be freed using release_kbnode().
 *
 * This function returns 0 on success.  Otherwise, an error code is
 * returned.  In particular, GPG_ERR_NO_PUBKEY or GPG_ERR_NO_SECKEY
 * (if want_secret is set) is returned if the key is not found.
 *
 * FIXME: We also have the get_pubkey_byname function which has a
 * different semantic.  Should be merged with this one.  */
gpg_error_t
getkey_byname (ctrl_t ctrl, getkey_ctx_t *retctx, PKT_public_key *pk,
               const char *name, int want_secret, kbnode_t *ret_keyblock)
{
  gpg_error_t err;
  strlist_t namelist = NULL;
  int with_unusable = 1;
  const char *def_secret_key = NULL;

  if (want_secret && !name)
    def_secret_key = parse_def_secret_key (ctrl);

  if (want_secret && !name && def_secret_key)
    add_to_strlist (&namelist, def_secret_key);
  else if (name)
    add_to_strlist (&namelist, name);
  else
    with_unusable = 0;

  err = key_byname (ctrl, retctx, namelist, pk, want_secret, with_unusable,
                    ret_keyblock, NULL);

  /* FIXME: Check that we really return GPG_ERR_NO_SECKEY if
     WANT_SECRET has been used.  */

  free_strlist (namelist);

  return err;
}


/* Return the next search result.
 *
 * If PK is not NULL, the public key of the next result is returned in
 * *PK.  Note: The self-signed data has already been merged into the
 * public key using merge_selfsigs.  Free *PK by calling
 * release_public_key_parts (or, if PK was allocated using xmalloc, you
 * can use free_public_key, which calls release_public_key_parts(PK)
 * and then xfree(PK)).
 *
 * RET_KEYBLOCK can be given as NULL; if it is not NULL it the entire
 * found keyblock is returned which must be released with
 * release_kbnode.  If the function returns an error NULL is stored at
 * RET_KEYBLOCK.
 *
 * The self-signed data has already been merged into the public key
 * using merge_selfsigs.  */
gpg_error_t
getkey_next (ctrl_t ctrl, getkey_ctx_t ctx,
             PKT_public_key *pk, kbnode_t *ret_keyblock)
{
  int rc; /* Fixme:  Make sure this is proper gpg_error */
  KBNODE keyblock = NULL;
  KBNODE found_key = NULL;

  /* We need to disable the caching so that for an exact key search we
     won't get the result back from the cache and thus end up in an
     endless loop.  The endless loop can occur, because the cache is
     used without respecting the current file pointer!  */
  keydb_disable_caching (ctx->kr_handle);

  /* FOUND_KEY is only valid as long as RET_KEYBLOCK is.  If the
   * caller wants PK, but not RET_KEYBLOCK, we need hand in our own
   * keyblock.  */
  if (pk && ret_keyblock == NULL)
      ret_keyblock = &keyblock;

  rc = lookup (ctrl, ctx, ctx->want_secret,
               ret_keyblock, pk ? &found_key : NULL);
  if (!rc && pk)
    {
      log_assert (found_key);
      pk_from_block (pk, NULL, found_key);
      release_kbnode (keyblock);
    }

  return rc;
}


/* Release any resources used by a key listing context.  This must be
 * called on the context returned by, e.g., getkey_byname.  */
void
getkey_end (ctrl_t ctrl, getkey_ctx_t ctx)
{
  if (ctx)
    {
#ifdef HAVE_W32_SYSTEM

      /* FIXME: This creates a big regression for Windows because the
       * keyring is only released after the global ctrl is released.
       * So if an operation does a getkey and then tries to modify the
       * keyring it will fail on Windows with a sharing violation.  We
       * need to modify all keyring write operations to also take the
       * ctrl and close the cached_getkey_kdb handle to make writing
       * work.  See: GnuPG-bug-id: 3097  */
      (void)ctrl;
      keydb_release (ctx->kr_handle);

#else /*!HAVE_W32_SYSTEM*/

      if (ctrl && !ctrl->cached_getkey_kdb)
        ctrl->cached_getkey_kdb = ctx->kr_handle;
      else
        keydb_release (ctx->kr_handle);

#endif /*!HAVE_W32_SYSTEM*/

      free_strlist (ctx->extra_list);
      if (!ctx->not_allocated)
	xfree (ctx);
    }
}



/************************************************
 ************* Merging stuff ********************
 ************************************************/

/* Set the mainkey_id fields for all keys in KEYBLOCK.  This is
 * usually done by merge_selfsigs but at some places we only need the
 * main_kid not a full merge.  The function also guarantees that all
 * pk->keyids are computed.  */
void
setup_main_keyids (kbnode_t keyblock)
{
  u32 kid[2], mainkid[2];
  kbnode_t kbctx, node;
  PKT_public_key *pk;

  if (keyblock->pkt->pkttype != PKT_PUBLIC_KEY)
    BUG ();
  pk = keyblock->pkt->pkt.public_key;

  keyid_from_pk (pk, mainkid);
  for (kbctx=NULL; (node = walk_kbnode (keyblock, &kbctx, 0)); )
    {
      if (!(node->pkt->pkttype == PKT_PUBLIC_KEY
            || node->pkt->pkttype == PKT_PUBLIC_SUBKEY))
        continue;
      pk = node->pkt->pkt.public_key;
      keyid_from_pk (pk, kid); /* Make sure pk->keyid is set.  */
      if (!pk->main_keyid[0] && !pk->main_keyid[1])
        {
          pk->main_keyid[0] = mainkid[0];
          pk->main_keyid[1] = mainkid[1];
        }
    }
}


/* KEYBLOCK corresponds to a public key block.  This function merges
 * much of the information from the self-signed data into the public
 * key, public subkey and user id data structures.  If you use the
 * high-level search API (e.g., get_pubkey) for looking up key blocks,
 * then you don't need to call this function.  This function is
 * useful, however, if you change the keyblock, e.g., by adding or
 * removing a self-signed data packet.  */
void
merge_keys_and_selfsig (ctrl_t ctrl, kbnode_t keyblock)
{
  if (!keyblock)
    ;
  else if (keyblock->pkt->pkttype == PKT_PUBLIC_KEY)
    merge_selfsigs (ctrl, keyblock);
  else
    log_debug ("FIXME: merging secret key blocks is not anymore available\n");
}


/* This function parses the key flags and returns PUBKEY_USAGE_ flags.  */
unsigned int
parse_key_usage (PKT_signature * sig)
{
  int key_usage = 0;
  const byte *p;
  size_t n;
  byte flags;

  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_FLAGS, &n);
  if (p && n)
    {
      /* First octet of the keyflags.  */
      flags = *p;

      if (flags & 1)
	{
	  key_usage |= PUBKEY_USAGE_CERT;
	  flags &= ~1;
	}

      if (flags & 2)
	{
	  key_usage |= PUBKEY_USAGE_SIG;
	  flags &= ~2;
	}

      /* We do not distinguish between encrypting communications and
         encrypting storage. */
      if (flags & (0x04 | 0x08))
	{
	  key_usage |= PUBKEY_USAGE_ENC;
	  flags &= ~(0x04 | 0x08);
	}

      if (flags & 0x20)
	{
	  key_usage |= PUBKEY_USAGE_AUTH;
	  flags &= ~0x20;
	}

      if ((flags & 0x80))
	{
	  key_usage |= PUBKEY_USAGE_GROUP;
	  flags &= ~0x80;
	}

      if (flags)
	key_usage |= PUBKEY_USAGE_UNKNOWN;

      n--;
      p++;
      if (n)
        {
          flags = *p;
          if ((flags & 0x04))
            key_usage |= PUBKEY_USAGE_RENC;
          if ((flags & 0x08))
            key_usage |= PUBKEY_USAGE_TIME;
        }

      if (!key_usage)
	key_usage |= PUBKEY_USAGE_NONE;

    }
  else if (p) /* Key flags of length zero.  */
    key_usage |= PUBKEY_USAGE_NONE;

  /* We set PUBKEY_USAGE_UNKNOWN to indicate that this key has a
     capability that we do not handle.  This serves to distinguish
     between a zero key usage which we handle as the default
     capabilities for that algorithm, and a usage that we do not
     handle.  Likewise we use PUBKEY_USAGE_NONE to indicate that
     key_flags have been given but they do not specify any usage.  */

  return key_usage;
}


/* Apply information from SIGNODE (which is the valid self-signature
 * associated with that UID) to the UIDNODE:
 * - wether the UID has been revoked
 * - assumed creation date of the UID
 * - temporary store the keyflags here
 * - temporary store the key expiration time here
 * - mark whether the primary user ID flag hat been set.
 * - store the preferences
 */
static void
fixup_uidnode (KBNODE uidnode, KBNODE signode, u32 keycreated)
{
  PKT_user_id *uid = uidnode->pkt->pkt.user_id;
  PKT_signature *sig = signode->pkt->pkt.signature;
  const byte *p, *sym, *aead, *hash, *zip;
  size_t n, nsym, naead, nhash, nzip;

  sig->flags.chosen_selfsig = 1;/* We chose this one. */
  uid->created = 0;		/* Not created == invalid. */
  if (IS_UID_REV (sig))
    {
      uid->flags.revoked = 1;
      return; /* Has been revoked.  */
    }
  else
    uid->flags.revoked = 0;

  uid->expiredate = sig->expiredate;

  if (sig->flags.expired)
    {
      uid->flags.expired = 1;
      return; /* Has expired.  */
    }
  else
    uid->flags.expired = 0;

  uid->created = sig->timestamp; /* This one is okay. */
  uid->selfsigversion = sig->version;
  /* If we got this far, it's not expired :) */
  uid->flags.expired = 0;

  /* Store the key flags in the helper variable for later processing.  */
  uid->help_key_usage = parse_key_usage (sig);

  /* Ditto for the key expiration.  */
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
  if (p && buf32_to_u32 (p))
    uid->help_key_expire = keycreated + buf32_to_u32 (p);
  else
    uid->help_key_expire = 0;

  /* Set the primary user ID flag - we will later wipe out some
   * of them to only have one in our keyblock.  */
  uid->flags.primary = 0;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PRIMARY_UID, NULL);
  if (p && *p)
    uid->flags.primary = 2;

  /* We could also query this from the unhashed area if it is not in
   * the hased area and then later try to decide which is the better
   * there should be no security problem with this.
   * For now we only look at the hashed one.  */

  /* Now build the preferences list.  These must come from the
     hashed section so nobody can modify the ciphers a key is
     willing to accept.  */
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_SYM, &n);
  sym = p;
  nsym = p ? n : 0;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_AEAD, &n);
  aead = p;
  naead = p ? n : 0;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_HASH, &n);
  hash = p;
  nhash = p ? n : 0;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_COMPR, &n);
  zip = p;
  nzip = p ? n : 0;
  if (uid->prefs)
    xfree (uid->prefs);
  n = nsym + naead + nhash + nzip;
  if (!n)
    uid->prefs = NULL;
  else
    {
      uid->prefs = xmalloc (sizeof (*uid->prefs) * (n + 1));
      n = 0;
      for (; nsym; nsym--, n++)
	{
	  uid->prefs[n].type = PREFTYPE_SYM;
	  uid->prefs[n].value = *sym++;
	}
      for (; naead; naead--, n++)
	{
	  uid->prefs[n].type = PREFTYPE_AEAD;
	  uid->prefs[n].value = *aead++;
	}
      for (; nhash; nhash--, n++)
	{
	  uid->prefs[n].type = PREFTYPE_HASH;
	  uid->prefs[n].value = *hash++;
	}
      for (; nzip; nzip--, n++)
	{
	  uid->prefs[n].type = PREFTYPE_ZIP;
	  uid->prefs[n].value = *zip++;
	}
      uid->prefs[n].type = PREFTYPE_NONE; /* End of list marker  */
      uid->prefs[n].value = 0;
    }

  /* See whether we have the MDC feature.  */
  uid->flags.mdc = 0;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES, &n);
  if (p && n && (p[0] & 0x01))
    uid->flags.mdc = 1;

  /* See whether we have the AEAD feature.  */
  uid->flags.aead = 0;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES, &n);
  if (p && n && (p[0] & 0x02))
    uid->flags.aead = 1;

  /* And the keyserver modify flag.  */
  uid->flags.ks_modify = 1;
  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KS_FLAGS, &n);
  if (p && n && (p[0] & 0x80))
    uid->flags.ks_modify = 0;
}

static void
sig_to_revoke_info (PKT_signature * sig, struct revoke_info *rinfo)
{
  rinfo->date = sig->timestamp;
  rinfo->algo = sig->pubkey_algo;
  rinfo->keyid[0] = sig->keyid[0];
  rinfo->keyid[1] = sig->keyid[1];
}


/* Given a keyblock, parse the key block and extract various pieces of
 * information and save them with the primary key packet and the user
 * id packets.  For instance, some information is stored in signature
 * packets.  We find the latest such valid packet (since the user can
 * change that information) and copy its contents into the
 * PKT_public_key.
 *
 * Note that R_REVOKED may be set to 0, 1 or 2.
 *
 * This function fills in the following fields in the primary key's
 * keyblock:
 *
 *   main_keyid          (computed)
 *   revkey / numrevkeys (derived from self signed key data)
 *   flags.valid         (whether we have at least 1 self-sig)
 *   flags.maybe_revoked (whether a designed revoked the key, but
 *                        we are missing the key to check the sig)
 *   selfsigversion      (highest version of any valid self-sig)
 *   pubkey_usage        (derived from most recent self-sig or most
 *                        recent user id)
 *   has_expired         (various sources)
 *   expiredate          (various sources)
 *
 * See the documentation for fixup_uidnode for how the user id packets
 * are modified.  In addition to that the primary user id's is_primary
 * field is set to 1 and the other user id's is_primary are set to 0.
 */
static void
merge_selfsigs_main (ctrl_t ctrl, kbnode_t keyblock, int *r_revoked,
		     struct revoke_info *rinfo)
{
  PKT_public_key *pk = NULL;
  KBNODE k;
  u32 kid[2];
  u32 sigdate, uiddate, uiddate2;
  KBNODE signode, uidnode, uidnode2;
  u32 curtime = make_timestamp ();
  unsigned int key_usage = 0;
  u32 keytimestamp = 0;  /* Creation time of the key.  */
  u32 key_expire = 0;
  int key_expire_seen = 0;
  byte sigversion = 0;

  *r_revoked = 0;
  memset (rinfo, 0, sizeof (*rinfo));

  /* Section 11.1 of RFC 4880 determines the order of packets within a
   * message.  There are three sections, which must occur in the
   * following order: the public key, the user ids and user attributes
   * and the subkeys.  Within each section, each primary packet (e.g.,
   * a user id packet) is followed by one or more signature packets,
   * which modify that packet.  */

  /* According to Section 11.1 of RFC 4880, the public key must be the
     first packet.  Note that parse_keyblock_image ensures that the
     first packet is the public key.  */
  if (keyblock->pkt->pkttype != PKT_PUBLIC_KEY)
    BUG ();
  pk = keyblock->pkt->pkt.public_key;
  keytimestamp = pk->timestamp;

  keyid_from_pk (pk, kid);
  pk->main_keyid[0] = kid[0];
  pk->main_keyid[1] = kid[1];

  if (pk->version < 4)
    {
      /* Before v4 the key packet itself contains the expiration date
       * and there was no way to change it, so we start with the one
       * from the key packet.  We do not support v3 keys anymore but
       * we keep the code in case a future key versions introduces a
       * hard expire time again. */
      key_expire = pk->max_expiredate;
      key_expire_seen = 1;
    }

  /* First pass:
   *
   * - Find the latest direct key self-signature.  We assume that the
   *   newest one overrides all others.
   *
   * - Determine whether the key has been revoked.
   *
   * - Gather all revocation keys (unlike other data, we don't just
   *   take them from the latest self-signed packet).
   *
   * - Determine max (sig[...]->version).
   */

  /* Reset this in case this key was already merged. */
  xfree (pk->revkey);
  pk->revkey = NULL;
  pk->numrevkeys = 0;

  signode = NULL;
  sigdate = 0; /* Helper variable to find the latest signature.  */

  /* According to Section 11.1 of RFC 4880, the public key comes first
   * and is immediately followed by any signature packets that modify
   * it.  */
  for (k = keyblock;
       k && k->pkt->pkttype != PKT_USER_ID
	 && k->pkt->pkttype != PKT_ATTRIBUTE
	 && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
       k = k->next)
    {
      if (k->pkt->pkttype == PKT_SIGNATURE)
	{
	  PKT_signature *sig = k->pkt->pkt.signature;
	  if (sig->keyid[0] == kid[0] && sig->keyid[1] == kid[1])
	    { /* Self sig.  */

	      if (check_key_signature (ctrl, keyblock, k, NULL))
		; /* Signature did not verify.  */
	      else if (IS_KEY_REV (sig))
		{
		  /* Key has been revoked - there is no way to
		   * override such a revocation, so we theoretically
		   * can stop now.  We should not cope with expiration
		   * times for revocations here because we have to
		   * assume that an attacker can generate all kinds of
		   * signatures.  However due to the fact that the key
		   * has been revoked it does not harm either and by
		   * continuing we gather some more info on that
		   * key.  */
		  *r_revoked = 1;
		  sig_to_revoke_info (sig, rinfo);
		}
	      else if (IS_KEY_SIG (sig))
		{
		  /* Add the indicated revocations keys from all
		   * signatures not just the latest.  We do this
		   * because you need multiple 1F sigs to properly
		   * handle revocation keys (PGP does it this way, and
		   * a revocation key could be sensitive and hence in
		   * a different signature).  */
		  if (sig->revkey)
		    {
		      int i;

		      pk->revkey =
			xrealloc (pk->revkey, sizeof (struct revocation_key) *
				  (pk->numrevkeys + sig->numrevkeys));

		      for (i = 0; i < sig->numrevkeys; i++)
			memcpy (&pk->revkey[pk->numrevkeys++],
				&sig->revkey[i],
				sizeof (struct revocation_key));
		    }

		  if (sig->timestamp >= sigdate)
		    { /* This is the latest signature so far.  */

		      if (sig->flags.expired)
			; /* Signature has expired - ignore it.  */
		      else
			{
			  sigdate = sig->timestamp;
			  signode = k;
			  if (sig->version > sigversion)
			    sigversion = sig->version;

			}
		    }
		}
	    }
	}
    }

  /* Remove dupes from the revocation keys.  */
  if (pk->revkey)
    {
      int i, j, x, changed = 0;

      for (i = 0; i < pk->numrevkeys; i++)
	{
	  for (j = i + 1; j < pk->numrevkeys; j++)
	    {
	      if (memcmp (&pk->revkey[i], &pk->revkey[j],
			  sizeof (struct revocation_key)) == 0)
		{
		  /* remove j */

		  for (x = j; x < pk->numrevkeys - 1; x++)
		    pk->revkey[x] = pk->revkey[x + 1];

		  pk->numrevkeys--;
		  j--;
		  changed = 1;
		}
	    }
	}

      if (changed)
	pk->revkey = xrealloc (pk->revkey,
			       pk->numrevkeys *
			       sizeof (struct revocation_key));
    }

  /* SIGNODE is the direct key signature packet (sigclass 0x1f) with
   * the latest creation time.  Extract some information from it.  */
  if (signode)
    {
      /* Some information from a direct key signature take precedence
       * over the same information given in UID sigs.  */
      PKT_signature *sig = signode->pkt->pkt.signature;
      const byte *p;

      key_usage = parse_key_usage (sig);

      p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
      if (p && buf32_to_u32 (p))
	{
	  key_expire = keytimestamp + buf32_to_u32 (p);
	  key_expire_seen = 1;
	}

      /* Mark that key as valid: One direct key signature should
       * render a key as valid.  */
      pk->flags.valid = 1;
    }

  /* Pass 1.5: Look for key revocation signatures that were not made
   * by the key (i.e. did a revocation key issue a revocation for
   * us?).  Only bother to do this if there is a revocation key in the
   * first place and we're not revoked already.  */

  if (!*r_revoked && pk->revkey)
    for (k = keyblock; k && k->pkt->pkttype != PKT_USER_ID; k = k->next)
      {
	if (k->pkt->pkttype == PKT_SIGNATURE)
	  {
	    PKT_signature *sig = k->pkt->pkt.signature;

	    if (IS_KEY_REV (sig) &&
		(sig->keyid[0] != kid[0] || sig->keyid[1] != kid[1]))
	      {
		int rc = check_revocation_keys (ctrl, pk, sig);
		if (rc == 0)
		  {
		    *r_revoked = 2;
		    sig_to_revoke_info (sig, rinfo);
		    /* Don't continue checking since we can't be any
		     * more revoked than this.  */
		    break;
		  }
		else if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY)
		  pk->flags.maybe_revoked = 1;

		/* A failure here means the sig did not verify, was
		 * not issued by a revocation key, or a revocation
		 * key loop was broken.  If a revocation key isn't
		 * findable, however, the key might be revoked and
		 * we don't know it.  */

		/* Fixme: In the future handle subkey and cert
		 * revocations?  PGP doesn't, but it's in 2440.  */
	      }
	  }
      }

  /* Second pass: Look at the self-signature of all user IDs.  */

  /* According to RFC 4880 section 11.1, user id and attribute packets
   * are in the second section, after the public key packet and before
   * the subkey packets.  */
  signode = uidnode = NULL;
  sigdate = 0; /* Helper variable to find the latest signature in one UID. */
  for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID || k->pkt->pkttype == PKT_ATTRIBUTE)
	{ /* New user id packet.  */

          /* Apply the data from the most recent self-signed packet to
	   * the preceding user id packet.  */
	  if (uidnode && signode)
	    {
	      fixup_uidnode (uidnode, signode, keytimestamp);
	      pk->flags.valid = 1;
	    }

	  /* Clear SIGNODE.  The only relevant self-signed data for
	   * UIDNODE follows it.  */
	  if (k->pkt->pkttype == PKT_USER_ID)
	    uidnode = k;
	  else
	    uidnode = NULL;

	  signode = NULL;
	  sigdate = 0;
	}
      else if (k->pkt->pkttype == PKT_SIGNATURE && uidnode)
	{
	  PKT_signature *sig = k->pkt->pkt.signature;
	  if (sig->keyid[0] == kid[0] && sig->keyid[1] == kid[1])
	    {
	      if (check_key_signature (ctrl, keyblock, k, NULL))
		;		/* signature did not verify */
	      else if ((IS_UID_SIG (sig) || IS_UID_REV (sig))
		       && sig->timestamp >= sigdate)
		{
		  /* Note: we allow invalidation of cert revocations
		   * by a newer signature.  An attacker can't use this
		   * because a key should be revoked with a key revocation.
		   * The reason why we have to allow for that is that at
		   * one time an email address may become invalid but later
		   * the same email address may become valid again (hired,
		   * fired, hired again).  */

		  sigdate = sig->timestamp;
		  signode = k;
		  signode->pkt->pkt.signature->flags.chosen_selfsig = 0;
		  if (sig->version > sigversion)
		    sigversion = sig->version;
		}
	    }
	}
    }
  if (uidnode && signode)
    {
      fixup_uidnode (uidnode, signode, keytimestamp);
      pk->flags.valid = 1;
    }

  /* If the key isn't valid yet, and we have
   * --allow-non-selfsigned-uid set, then force it valid. */
  if (!pk->flags.valid && opt.allow_non_selfsigned_uid)
    {
      if (opt.verbose)
	log_info (_("Invalid key %s made valid by"
		    " --allow-non-selfsigned-uid\n"), keystr_from_pk (pk));
      pk->flags.valid = 1;
    }

  /* The key STILL isn't valid, so try and find an ultimately
   * trusted signature. */
  if (!pk->flags.valid)
    {
      uidnode = NULL;

      for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
	   k = k->next)
	{
	  if (k->pkt->pkttype == PKT_USER_ID)
	    uidnode = k;
	  else if (k->pkt->pkttype == PKT_SIGNATURE && uidnode)
	    {
	      PKT_signature *sig = k->pkt->pkt.signature;

	      if (sig->keyid[0] != kid[0] || sig->keyid[1] != kid[1])
		{
		  PKT_public_key *ultimate_pk;

		  ultimate_pk = xmalloc_clear (sizeof (*ultimate_pk));

		  /* We don't want to use the full get_pubkey to avoid
		   * infinite recursion in certain cases.  There is no
		   * reason to check that an ultimately trusted key is
		   * still valid - if it has been revoked the user
		   * should also remove the ultimate trust flag.  */
		  if (get_pubkey_fast (ultimate_pk, sig->keyid) == 0
		      && check_key_signature2 (ctrl,
                                               keyblock, k, ultimate_pk,
					       NULL, NULL, NULL, NULL) == 0
		      && get_ownertrust (ctrl, ultimate_pk) == TRUST_ULTIMATE)
		    {
		      free_public_key (ultimate_pk);
		      pk->flags.valid = 1;
		      break;
		    }

		  free_public_key (ultimate_pk);
		}
	    }
	}
    }

  /* Record the highest selfsig version so we know if this is a v3 key
   * through and through, or a v3 key with a v4 selfsig somewhere.
   * This is useful in a few places to know if the key must be treated
   * as PGP2-style or OpenPGP-style.  Note that a selfsig revocation
   * with a higher version number will also raise this value.  This is
   * okay since such a revocation must be issued by the user (i.e. it
   * cannot be issued by someone else to modify the key behavior.) */

  pk->selfsigversion = sigversion;

  /* Now that we had a look at all user IDs we can now get some
   * information from those user IDs.  */

  if (!key_usage)
    {
      /* Find the latest user ID with key flags set. */
      uiddate = 0; /* Helper to find the latest user ID.  */
      for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
	   k = k->next)
	{
	  if (k->pkt->pkttype == PKT_USER_ID)
	    {
	      PKT_user_id *uid = k->pkt->pkt.user_id;

	      if (uid->help_key_usage
                  && (uid->created > uiddate || (!uid->created && !uiddate)))
		{
		  key_usage = uid->help_key_usage;
		  uiddate = uid->created;
		}
	    }
	}
    }

  if (!key_usage)
    {
      /* No key flags at all: get it from the algo.  */
      key_usage = (openpgp_pk_algo_usage (pk->pubkey_algo)
                   & PUBKEY_USAGE_BASIC_MASK);
    }
  else
    {
      /* Check that the usage matches the usage as given by the algo.  */
      int x = openpgp_pk_algo_usage (pk->pubkey_algo);
      if (x) /* Mask it down to the actual allowed usage.  */
	key_usage &= x;
    }

  /* Whatever happens, it's a primary key, so it can certify. */
  pk->pubkey_usage = key_usage | PUBKEY_USAGE_CERT;

  if (!key_expire_seen)
    {
      /* Find the latest valid user ID with a key expiration set.
       * This may be a different one than from usage computation above
       * because some user IDs may have no expiration date set.  */
      uiddate = 0;
      for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
	   k = k->next)
	{
	  if (k->pkt->pkttype == PKT_USER_ID)
	    {
	      PKT_user_id *uid = k->pkt->pkt.user_id;
	      if (uid->help_key_expire
                  && (uid->created > uiddate || (!uid->created && !uiddate)))
		{
		  key_expire = uid->help_key_expire;
		  uiddate = uid->created;
		}
	    }
	}
    }

  /* Currently only the not anymore supported v3 keys have a maximum
   * expiration date, but future key versions may get this feature again. */
  if (key_expire == 0
      || (pk->max_expiredate && key_expire > pk->max_expiredate))
    key_expire = pk->max_expiredate;

  pk->has_expired = key_expire >= curtime ? 0 : key_expire;
  pk->expiredate = key_expire;

  /* Fixme: we should see how to get rid of the expiretime fields but
   * this needs changes at other places too.  */

  /* And now find the real primary user ID and delete all others.  */
  uiddate = uiddate2 = 0;
  uidnode = uidnode2 = NULL;
  for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID && !k->pkt->pkt.user_id->attrib_data)
	{
	  PKT_user_id *uid = k->pkt->pkt.user_id;
	  if (uid->flags.primary)
	    {
	      if (uid->created > uiddate)
		{
		  uiddate = uid->created;
		  uidnode = k;
		}
	      else if (uid->created == uiddate && uidnode)
		{
		  /* The dates are equal, so we need to do a different
		   * (and arbitrary) comparison.  This should rarely,
		   * if ever, happen.  It's good to try and guarantee
		   * that two different GnuPG users with two different
		   * keyrings at least pick the same primary.  */
		  if (cmp_user_ids (uid, uidnode->pkt->pkt.user_id) > 0)
		    uidnode = k;
		}
	    }
	  else
	    {
	      if (uid->created > uiddate2)
		{
		  uiddate2 = uid->created;
		  uidnode2 = k;
		}
	      else if (uid->created == uiddate2 && uidnode2)
		{
		  if (cmp_user_ids (uid, uidnode2->pkt->pkt.user_id) > 0)
		    uidnode2 = k;
		}
	    }
	}
    }
  if (uidnode)
    {
      for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
	   k = k->next)
	{
	  if (k->pkt->pkttype == PKT_USER_ID &&
	      !k->pkt->pkt.user_id->attrib_data)
	    {
	      PKT_user_id *uid = k->pkt->pkt.user_id;
	      if (k != uidnode)
		uid->flags.primary = 0;
	    }
	}
    }
  else if (uidnode2)
    {
      /* None is flagged primary - use the latest user ID we have,
       * and disambiguate with the arbitrary packet comparison. */
      uidnode2->pkt->pkt.user_id->flags.primary = 1;
    }
  else
    {
      /* None of our uids were self-signed, so pick the one that
       * sorts first to be the primary.  This is the best we can do
       * here since there are no self sigs to date the uids. */

      uidnode = NULL;

      for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
	   k = k->next)
	{
	  if (k->pkt->pkttype == PKT_USER_ID
	      && !k->pkt->pkt.user_id->attrib_data)
	    {
	      if (!uidnode)
		{
		  uidnode = k;
		  uidnode->pkt->pkt.user_id->flags.primary = 1;
		  continue;
		}
	      else
		{
		  if (cmp_user_ids (k->pkt->pkt.user_id,
				    uidnode->pkt->pkt.user_id) > 0)
		    {
		      uidnode->pkt->pkt.user_id->flags.primary = 0;
		      uidnode = k;
		      uidnode->pkt->pkt.user_id->flags.primary = 1;
		    }
		  else
                    {
                      /* just to be safe: */
                      k->pkt->pkt.user_id->flags.primary = 0;
                    }
		}
	    }
	}
    }
}


/* Convert a buffer to a signature.  Useful for 0x19 embedded sigs.
 * Caller must free the signature when they are done. */
static PKT_signature *
buf_to_sig (const byte * buf, size_t len)
{
  PKT_signature *sig = xmalloc_clear (sizeof (PKT_signature));
  IOBUF iobuf = iobuf_temp_with_content (buf, len);
  int save_mode = set_packet_list_mode (0);

  if (parse_signature (iobuf, PKT_SIGNATURE, len, sig) != 0)
    {
      free_seckey_enc (sig);
      sig = NULL;
    }

  set_packet_list_mode (save_mode);
  iobuf_close (iobuf);

  return sig;
}


/* Use the self-signed data to fill in various fields in subkeys.
 *
 * KEYBLOCK is the whole keyblock.  SUBNODE is the subkey to fill in.
 *
 * Sets the following fields on the subkey:
 *
 *   main_keyid
 *   flags.valid        if the subkey has a valid self-sig binding
 *   flags.revoked
 *   flags.backsig
 *   pubkey_usage
 *   has_expired
 *   expired_date
 *
 * On this subkey's most revent valid self-signed packet, the
 * following field is set:
 *
 *   flags.chosen_selfsig
 */
static void
merge_selfsigs_subkey (ctrl_t ctrl, kbnode_t keyblock, kbnode_t subnode)
{
  PKT_public_key *mainpk = NULL, *subpk = NULL;
  PKT_signature *sig;
  KBNODE k;
  u32 mainkid[2];
  u32 sigdate = 0;
  KBNODE signode;
  u32 curtime = make_timestamp ();
  unsigned int key_usage = 0;
  u32 keytimestamp = 0;
  u32 key_expire = 0;
  const byte *p;

  if (subnode->pkt->pkttype != PKT_PUBLIC_SUBKEY)
    BUG ();
  mainpk = keyblock->pkt->pkt.public_key;
  if (mainpk->version < 4)
    return;/* (actually this should never happen) */
  keyid_from_pk (mainpk, mainkid);
  subpk = subnode->pkt->pkt.public_key;
  keytimestamp = subpk->timestamp;

  subpk->flags.valid = 0;
  subpk->flags.exact = 0;
  subpk->main_keyid[0] = mainpk->main_keyid[0];
  subpk->main_keyid[1] = mainpk->main_keyid[1];

  /* Find the latest key binding self-signature.  */
  signode = NULL;
  sigdate = 0; /* Helper to find the latest signature.  */
  for (k = subnode->next; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY;
       k = k->next)
    {
      if (k->pkt->pkttype == PKT_SIGNATURE)
	{
	  sig = k->pkt->pkt.signature;
	  if (sig->keyid[0] == mainkid[0] && sig->keyid[1] == mainkid[1])
	    {
	      if (check_key_signature (ctrl, keyblock, k, NULL))
		; /* Signature did not verify.  */
	      else if (IS_SUBKEY_REV (sig))
		{
		  /* Note that this means that the date on a
		   * revocation sig does not matter - even if the
		   * binding sig is dated after the revocation sig,
		   * the subkey is still marked as revoked.  This
		   * seems ok, as it is just as easy to make new
		   * subkeys rather than re-sign old ones as the
		   * problem is in the distribution.  Plus, PGP (7)
		   * does this the same way.  */
		  subpk->flags.revoked = 1;
		  sig_to_revoke_info (sig, &subpk->revoked);
		  /* Although we could stop now, we continue to
		   * figure out other information like the old expiration
		   * time.  */
		}
	      else if (IS_SUBKEY_SIG (sig) && sig->timestamp >= sigdate)
		{
		  if (sig->flags.expired)
		    ; /* Signature has expired - ignore it.  */
		  else
		    {
		      sigdate = sig->timestamp;
		      signode = k;
		      signode->pkt->pkt.signature->flags.chosen_selfsig = 0;
		    }
		}
	    }
	}
    }

  /* No valid key binding.  */
  if (!signode)
    return;

  sig = signode->pkt->pkt.signature;
  sig->flags.chosen_selfsig = 1; /* So we know which selfsig we chose later.  */

  key_usage = parse_key_usage (sig);
  if (!key_usage)
    {
      /* No key flags at all: get it from the algo.  */
      key_usage = (openpgp_pk_algo_usage (subpk->pubkey_algo)
                   & PUBKEY_USAGE_BASIC_MASK);
    }
  else
    {
      /* Check that the usage matches the usage as given by the algo.  */
      int x = openpgp_pk_algo_usage (subpk->pubkey_algo);
      if (x) /* Mask it down to the actual allowed usage.  */
	key_usage &= x;
    }

  subpk->pubkey_usage = key_usage;

  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
  if (p && buf32_to_u32 (p))
    key_expire = keytimestamp + buf32_to_u32 (p);
  else
    key_expire = 0;

  subpk->has_expired = key_expire >= curtime ? 0 : key_expire;
  subpk->expiredate = key_expire;

  /* Algo doesn't exist.  */
  if (openpgp_pk_test_algo (subpk->pubkey_algo))
    return;

  subpk->flags.valid = 1;

  /* Find the most recent 0x19 embedded signature on our self-sig. */
  if (!subpk->flags.backsig)
    {
      int seq = 0;
      size_t n;
      PKT_signature *backsig = NULL;

      sigdate = 0;

      /* We do this while() since there may be other embedded
       * signatures in the future.  We only want 0x19 here. */

      while ((p = enum_sig_subpkt (sig->hashed,
				   SIGSUBPKT_SIGNATURE, &n, &seq, NULL)))
	if (n > 3
	    && ((p[0] == 3 && p[2] == 0x19) || (p[0] == 4 && p[1] == 0x19)))
	  {
	    PKT_signature *tempsig = buf_to_sig (p, n);
	    if (tempsig)
	      {
		if (tempsig->timestamp > sigdate)
		  {
		    if (backsig)
		      free_seckey_enc (backsig);

		    backsig = tempsig;
		    sigdate = backsig->timestamp;
		  }
		else
		  free_seckey_enc (tempsig);
	      }
	  }

      seq = 0;

      /* It is safe to have this in the unhashed area since the 0x19
       * is located on the selfsig for convenience, not security. */

      while ((p = enum_sig_subpkt (sig->unhashed, SIGSUBPKT_SIGNATURE,
				   &n, &seq, NULL)))
	if (n > 3
	    && ((p[0] == 3 && p[2] == 0x19) || (p[0] == 4 && p[1] == 0x19)))
	  {
	    PKT_signature *tempsig = buf_to_sig (p, n);
	    if (tempsig)
	      {
		if (tempsig->timestamp > sigdate)
		  {
		    if (backsig)
		      free_seckey_enc (backsig);

		    backsig = tempsig;
		    sigdate = backsig->timestamp;
		  }
		else
		  free_seckey_enc (tempsig);
	      }
	  }

      if (backsig)
	{
	  /* At this point, backsig contains the most recent 0x19 sig.
	   * Let's see if it is good. */

	  /* 2==valid, 1==invalid, 0==didn't check */
	  if (check_backsig (mainpk, subpk, backsig) == 0)
	    subpk->flags.backsig = 2;
	  else
	    subpk->flags.backsig = 1;

	  free_seckey_enc (backsig);
	}
    }
}


/* Merge information from the self-signatures with the public key,
 * subkeys and user ids to make using them more easy.
 *
 * See documentation for merge_selfsigs_main, merge_selfsigs_subkey
 * and fixup_uidnode for exactly which fields are updated.  */
static void
merge_selfsigs (ctrl_t ctrl, kbnode_t keyblock)
{
  KBNODE k;
  int revoked;
  struct revoke_info rinfo;
  PKT_public_key *main_pk;
  prefitem_t *prefs;
  unsigned int mdc_feature;
  unsigned int aead_feature;

  if (keyblock->pkt->pkttype != PKT_PUBLIC_KEY)
    {
      if (keyblock->pkt->pkttype == PKT_SECRET_KEY)
	{
	  log_error ("expected public key but found secret key "
		     "- must stop\n");
	  /* We better exit here because a public key is expected at
	   * other places too.  FIXME: Figure this out earlier and
	   * don't get to here at all */
	  g10_exit (1);
	}
      BUG ();
    }

  merge_selfsigs_main (ctrl, keyblock, &revoked, &rinfo);

  /* Now merge in the data from each of the subkeys.  */
  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  merge_selfsigs_subkey (ctrl, keyblock, k);
	}
    }

  main_pk = keyblock->pkt->pkt.public_key;
  if (revoked || main_pk->has_expired || !main_pk->flags.valid)
    {
      /* If the primary key is revoked, expired, or invalid we
       * better set the appropriate flags on that key and all
       * subkeys.  */
      for (k = keyblock; k; k = k->next)
	{
	  if (k->pkt->pkttype == PKT_PUBLIC_KEY
	      || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	    {
	      PKT_public_key *pk = k->pkt->pkt.public_key;
	      if (!main_pk->flags.valid)
		pk->flags.valid = 0;
	      if (revoked && !pk->flags.revoked)
		{
		  pk->flags.revoked = revoked;
		  memcpy (&pk->revoked, &rinfo, sizeof (rinfo));
		}
	      if (main_pk->has_expired)
		pk->has_expired = main_pk->has_expired;
	    }
	}
      return;
    }

  /* Set the preference list of all keys to those of the primary real
   * user ID.  Note: we use these preferences when we don't know by
   * which user ID the key has been selected.
   * fixme: we should keep atoms of commonly used preferences or
   * use reference counting to optimize the preference lists storage.
   * FIXME: it might be better to use the intersection of
   * all preferences.
   * Do a similar thing for the MDC feature flag.  */
  prefs = NULL;
  mdc_feature = aead_feature = 0;
  for (k = keyblock; k && k->pkt->pkttype != PKT_PUBLIC_SUBKEY; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID
	  && !k->pkt->pkt.user_id->attrib_data
	  && k->pkt->pkt.user_id->flags.primary)
	{
	  prefs = k->pkt->pkt.user_id->prefs;
	  mdc_feature = k->pkt->pkt.user_id->flags.mdc;
	  aead_feature = k->pkt->pkt.user_id->flags.aead;
	  break;
	}
    }
  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_PUBLIC_KEY
	  || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  PKT_public_key *pk = k->pkt->pkt.public_key;
	  if (pk->prefs)
	    xfree (pk->prefs);
	  pk->prefs = copy_prefs (prefs);
	  pk->flags.mdc = mdc_feature;
	  pk->flags.aead = aead_feature;
	}
    }
}



/* See whether the key satisfies any additional requirements specified
 * in CTX.  If so, return the node of an appropriate key or subkey.
 * Otherwise, return NULL if there was no appropriate key.
 *
 * Note that we do not return a reference, i.e. the result must not be
 * freed using 'release_kbnode'.
 *
 * In case the primary key is not required, select a suitable subkey.
 * We need the primary key if PUBKEY_USAGE_CERT is set in REQ_USAGE or
 * we are in PGP6 or PGP7 mode and PUBKEY_USAGE_SIG is set in
 * REQ_USAGE.
 *
 * If any of PUBKEY_USAGE_SIG, PUBKEY_USAGE_ENC and PUBKEY_USAGE_CERT
 * are set in REQ_USAGE, we filter by the key's function.  Concretely,
 * if PUBKEY_USAGE_SIG and PUBKEY_USAGE_CERT are set, then we only
 * return a key if it is (at least) either a signing or a
 * certification key.
 *
 * If REQ_USAGE is set, then we reject any keys that are not good
 * (i.e., valid, not revoked, not expired, etc.).  This allows the
 * getkey functions to be used for plain key listings.
 *
 * Sets the matched key's user id field (pk->user_id) to the user id
 * that matched the low-level search criteria or NULL.
 *
 * If R_FLAGS is not NULL set certain flags for more detailed error
 * reporting.  Used flags are:
 *
 * - LOOKUP_ALL_SUBKEYS_EXPIRED :: All Subkeys are expired or have
 *                                 been revoked.
 * - LOOKUP_NOT_SELECTED :: No suitable key found
 *
 * This function needs to handle several different cases:
 *
 *  1. No requested usage and no primary key requested
 *     Examples for this case are that we have a keyID to be used
 *     for decrytion or verification.
 *  2. No usage but primary key requested
 *     This is the case for all functions which work on an
 *     entire keyblock, e.g. for editing or listing
 *  3. Usage and primary key requested
 *     FIXME
 *  4. Usage but no primary key requested
 *     FIXME
 *
 */
static kbnode_t
finish_lookup (kbnode_t keyblock, unsigned int req_usage, int want_exact,
               int want_secret, int allow_adsk, unsigned int *r_flags)
{
  kbnode_t k;

  /* If WANT_EXACT is set, the key or subkey that actually matched the
     low-level search criteria.  */
  kbnode_t foundk = NULL;
  /* The user id (if any) that matched the low-level search criteria.  */
  PKT_user_id *foundu = NULL;

  u32 latest_date;
  kbnode_t latest_key;
  PKT_public_key *pk;
  int req_prim;
  u32 curtime = make_timestamp ();

  if (r_flags)
    *r_flags = 0;

#define USAGE_MASK  (PUBKEY_USAGE_SIG|PUBKEY_USAGE_ENC|PUBKEY_USAGE_CERT)
  req_usage &= USAGE_MASK;
  /* In allow ADSK mode make sure both encryption bis are set.  */
  if (allow_adsk && (req_usage & PUBKEY_USAGE_XENC_MASK))
    req_usage |= PUBKEY_USAGE_XENC_MASK;

  /* Request the primary if we're certifying another key, and also if
   * signing data while --pgp6 or --pgp7 is on since pgp 6 and 7 do
   * not understand signatures made by a signing subkey.  PGP 8 does. */
  req_prim = ((req_usage & PUBKEY_USAGE_CERT)
              || ((PGP6 || PGP7) && (req_usage & PUBKEY_USAGE_SIG)));


  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY);

  /* For an exact match mark the primary or subkey that matched the
   * low-level search criteria.  Use this loop also to sort our keys
   * found using an ADSK fingerprint.  */
  for (k = keyblock; k; k = k->next)
    {
      if ((k->flag & 1) && (k->pkt->pkttype == PKT_PUBLIC_KEY
                            || k->pkt->pkttype == PKT_PUBLIC_SUBKEY))
        {
          if (want_exact)
            {
              if (DBG_LOOKUP)
                log_debug ("finish_lookup: exact search requested and found\n");
              foundk = k;
              pk = k->pkt->pkt.public_key;
              pk->flags.exact = 1;
              break;
            }
          else if (!allow_adsk && (k->pkt->pkt.public_key->pubkey_usage
                                   == PUBKEY_USAGE_RENC))
            {
              if (DBG_LOOKUP)
                log_debug ("finish_lookup: found via ADSK - not selected\n");
              if (r_flags)
                *r_flags |= LOOKUP_NOT_SELECTED;
              return NULL; /* Not found.  */
            }
        }
    }

  /* Get the user id that matched that low-level search criteria.  */
  for (k = keyblock; k; k = k->next)
    {
      if ((k->flag & 2))
	{
	  log_assert (k->pkt->pkttype == PKT_USER_ID);
	  foundu = k->pkt->pkt.user_id;
	  break;
	}
    }

  if (DBG_LOOKUP)
    log_debug ("finish_lookup: checking key %08lX (%s)(req_usage=%x)\n",
	       (ulong) keyid_from_pk (keyblock->pkt->pkt.public_key, NULL),
	       foundk ? "one" : "all", req_usage);

  if (!req_usage)
    {
      latest_key = foundk ? foundk : keyblock;
      goto found;
    }

  latest_date = 0;
  latest_key = NULL;
  /* Set LATEST_KEY to the latest (the one with the most recent
   * timestamp) good (valid, not revoked, not expired, etc.) subkey.
   *
   * Don't bother if we are only looking for a primary key or we need
   * an exact match and the exact match is not a subkey.  */
  if (req_prim || (foundk && foundk->pkt->pkttype != PKT_PUBLIC_SUBKEY))
    ;
  else
    {
      kbnode_t nextk;
      int n_subkeys = 0;
      int n_revoked_or_expired = 0;

      /* Either start a loop or check just this one subkey.  */
      for (k = foundk ? foundk : keyblock; k; k = nextk)
	{
	  if (foundk)
            {
              /* If FOUNDK is not NULL, then only consider that exact
                 key, i.e., don't iterate.  */
              nextk = NULL;
            }
	  else
	    nextk = k->next;

	  if (k->pkt->pkttype != PKT_PUBLIC_SUBKEY)
	    continue;

	  pk = k->pkt->pkt.public_key;
	  if (DBG_LOOKUP)
	    log_debug ("\tchecking subkey %08lX\n",
		       (ulong) keyid_from_pk (pk, NULL));

	  if (!pk->flags.valid)
	    {
	      if (DBG_LOOKUP)
		log_debug ("\tsubkey not valid\n");
	      continue;
	    }
	  if (!((pk->pubkey_usage & USAGE_MASK) & req_usage))
	    {
	      if (DBG_LOOKUP)
		log_debug ("\tusage does not match: want=%x have=%x\n",
			   req_usage, pk->pubkey_usage);
	      continue;
	    }

          n_subkeys++;
	  if (pk->flags.revoked)
	    {
	      if (DBG_LOOKUP)
		log_debug ("\tsubkey has been revoked\n");
              n_revoked_or_expired++;
	      continue;
	    }
	  if (pk->has_expired)
	    {
	      if (DBG_LOOKUP)
		log_debug ("\tsubkey has expired\n");
              n_revoked_or_expired++;
	      continue;
	    }
	  if (pk->timestamp > curtime && !opt.ignore_valid_from)
	    {
	      if (DBG_LOOKUP)
		log_debug ("\tsubkey not yet valid\n");
	      continue;
	    }

          if (want_secret && !agent_probe_secret_key (NULL, pk))
            {
              if (DBG_LOOKUP)
                log_debug ("\tno secret key\n");
              continue;
            }

	  if (DBG_LOOKUP)
	    log_debug ("\tsubkey might be fine\n");
	  /* In case a key has a timestamp of 0 set, we make sure
	     that it is used.  A better change would be to compare
	     ">=" but that might also change the selected keys and
	     is as such a more intrusive change.  */
	  if (pk->timestamp > latest_date || (!pk->timestamp && !latest_date))
	    {
	      latest_date = pk->timestamp;
	      latest_key = k;
	    }
	}
      if (n_subkeys == n_revoked_or_expired && r_flags)
        *r_flags |= LOOKUP_ALL_SUBKEYS_EXPIRED;
    }

  /* Check if the primary key is ok (valid, not revoke, not expire,
   * matches requested usage) if:
   *
   *   - we didn't find an appropriate subkey and we're not doing an
   *     exact search,
   *
   *   - we're doing an exact match and the exact match was the
   *     primary key, or,
   *
   *   - we're just considering the primary key.  */
  if ((!latest_key && !want_exact) || foundk == keyblock || req_prim)
    {
      if (DBG_LOOKUP && !foundk && !req_prim)
	log_debug ("\tno suitable subkeys found - trying primary\n");
      pk = keyblock->pkt->pkt.public_key;
      if (!pk->flags.valid)
	{
	  if (DBG_LOOKUP)
	    log_debug ("\tprimary key not valid\n");
	}
      else if (!((pk->pubkey_usage & USAGE_MASK) & req_usage))
	{
	  if (DBG_LOOKUP)
	    log_debug ("\tprimary key usage does not match: "
		       "want=%x have=%x\n", req_usage, pk->pubkey_usage);
	}
      else if (pk->flags.revoked)
	{
	  if (DBG_LOOKUP)
	    log_debug ("\tprimary key has been revoked\n");
	}
      else if (pk->has_expired)
	{
	  if (DBG_LOOKUP)
	    log_debug ("\tprimary key has expired\n");
	}
      else /* Okay.  */
	{
	  if (DBG_LOOKUP)
	    log_debug ("\tprimary key may be used\n");
	  latest_key = keyblock;
	}
    }

  if (!latest_key)
    {
      if (DBG_LOOKUP)
	log_debug ("\tno suitable key found -  giving up\n");
      if (r_flags)
        *r_flags |= LOOKUP_NOT_SELECTED;
      return NULL; /* Not found.  */
    }

 found:
  if (DBG_LOOKUP)
    log_debug ("\tusing key %08lX\n",
	       (ulong) keyid_from_pk (latest_key->pkt->pkt.public_key, NULL));

  if (latest_key)
    {
      pk = latest_key->pkt->pkt.public_key;
      free_user_id (pk->user_id);
      pk->user_id = scopy_user_id (foundu);
    }

  if (latest_key != keyblock && opt.verbose)
    {
      char *tempkeystr =
	xstrdup (keystr_from_pk (latest_key->pkt->pkt.public_key));
      log_info (_("using subkey %s instead of primary key %s\n"),
		tempkeystr, keystr_from_pk (keyblock->pkt->pkt.public_key));
      xfree (tempkeystr);
    }

  cache_user_id (keyblock);

  return latest_key ? latest_key : keyblock; /* Found.  */
}


/* Print a KEY_CONSIDERED status line.  */
static void
print_status_key_considered (kbnode_t keyblock, unsigned int flags)
{
  char hexfpr[2*MAX_FINGERPRINT_LEN + 1];
  kbnode_t node;
  char flagbuf[20];

  if (!is_status_enabled ())
    return;

  for (node=keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_PUBLIC_KEY
        || node->pkt->pkttype == PKT_SECRET_KEY)
      break;
  if (!node)
    {
      log_error ("%s: keyblock w/o primary key\n", __func__);
      return;
    }

  hexfingerprint (node->pkt->pkt.public_key, hexfpr, sizeof hexfpr);
  snprintf (flagbuf, sizeof flagbuf, " %u", flags);
  write_status_strings (STATUS_KEY_CONSIDERED, hexfpr, flagbuf, NULL);
}



/* A high-level function to lookup keys.
 *
 * This function builds on top of the low-level keydb API.  It first
 * searches the database using the description stored in CTX->ITEMS,
 * then it filters the results using CTX and, finally, if WANT_SECRET
 * is set, it ignores any keys for which no secret key is available.
 *
 * Unlike the low-level search functions, this function also merges
 * all of the self-signed data into the keys, subkeys and user id
 * packets (see the merge_selfsigs for details).
 *
 * On success the key's keyblock is stored at *RET_KEYBLOCK, and the
 * specific subkey is stored at *RET_FOUND_KEY.  Note that we do not
 * return a reference in *RET_FOUND_KEY, i.e. the result must not be
 * freed using 'release_kbnode', and it is only valid until
 * *RET_KEYBLOCK is deallocated.  Therefore, if RET_FOUND_KEY is not
 * NULL, then RET_KEYBLOCK must not be NULL.  */
static int
lookup (ctrl_t ctrl, getkey_ctx_t ctx, int want_secret,
        kbnode_t *ret_keyblock, kbnode_t *ret_found_key)
{
  int rc;
  int no_suitable_key = 0;
  KBNODE keyblock = NULL;
  KBNODE found_key = NULL;
  unsigned int infoflags;

  log_assert (ret_found_key == NULL || ret_keyblock != NULL);
  if (ret_keyblock)
    *ret_keyblock = NULL;

  for (;;)
    {
      rc = keydb_search (ctx->kr_handle, ctx->items, ctx->nitems, NULL);
      if (rc)
        break;

      /* If we are iterating over the entire database, then we need to
       * change from KEYDB_SEARCH_MODE_FIRST, which does an implicit
       * reset, to KEYDB_SEARCH_MODE_NEXT, which gets the next record.  */
      if (ctx->nitems && ctx->items->mode == KEYDB_SEARCH_MODE_FIRST)
	ctx->items->mode = KEYDB_SEARCH_MODE_NEXT;

      rc = keydb_get_keyblock (ctx->kr_handle, &keyblock);
      if (rc)
	{
	  log_error ("keydb_get_keyblock failed: %s\n", gpg_strerror (rc));
	  goto skip;
	}

      if (want_secret)
	{
	  rc = agent_probe_any_secret_key (NULL, keyblock);
	  if (gpg_err_code(rc) == GPG_ERR_NO_SECKEY)
	    goto skip; /* No secret key available.  */
	  if (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO)
	    goto skip; /* Not implemented algo - skip.  */
	  if (rc)
	    goto found; /* Unexpected error.  */
	}

      /* Warning: node flag bits 0 and 1 should be preserved by
       * merge_selfsigs.  */
      merge_selfsigs (ctrl, keyblock);
      found_key = finish_lookup (keyblock, ctx->req_usage, ctx->exact,
                                 want_secret, ctx->allow_adsk,
                                 &infoflags);
      print_status_key_considered (keyblock, infoflags);
      if (found_key)
	{
	  no_suitable_key = 0;
	  goto found;
	}
      else
        {
          no_suitable_key = 1;
        }

    skip:
      /* Release resources and continue search. */
      release_kbnode (keyblock);
      keyblock = NULL;
      /* The keyblock cache ignores the current "file position".
       * Thus, if we request the next result and the cache matches
       * (and it will since it is what we just looked for), we'll get
       * the same entry back!  We can avoid this infinite loop by
       * disabling the cache.  */
      keydb_disable_caching (ctx->kr_handle);
    }

 found:
  if (rc && gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));

  if (!rc)
    {
      if (ret_keyblock)
        {
          *ret_keyblock = keyblock; /* Return the keyblock.  */
          keyblock = NULL;
        }
    }
  else if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND && no_suitable_key)
    rc = want_secret? GPG_ERR_UNUSABLE_SECKEY : GPG_ERR_UNUSABLE_PUBKEY;
  else if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
    rc = want_secret? GPG_ERR_NO_SECKEY : GPG_ERR_NO_PUBKEY;

  release_kbnode (keyblock);

  if (ret_found_key)
    {
      if (! rc)
	*ret_found_key = found_key;
      else
	*ret_found_key = NULL;
    }

  return rc;
}


/* If a default key has been specified, return that key.  If a card
 * based key is also available as indicated by FPR_CARD not being
 * NULL, return that key if suitable.  */
gpg_error_t
get_seckey_default_or_card (ctrl_t ctrl, PKT_public_key *pk,
                            const byte *fpr_card, size_t fpr_len)
{
  gpg_error_t err;
  strlist_t namelist = NULL;
  const char *def_secret_key;

  def_secret_key = parse_def_secret_key (ctrl);

  if (def_secret_key)
    add_to_strlist (&namelist, def_secret_key);
  else if (fpr_card)
    {
      err = get_pubkey_byfprint (ctrl, pk, NULL, fpr_card, fpr_len);
      if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
        {
          if (opt.debug)
            log_debug ("using LDAP to find public key for current card\n");
          err = keyserver_import_fprint (ctrl, fpr_card, fpr_len,
                                         opt.keyserver,
                                         KEYSERVER_IMPORT_FLAG_LDAP);
          if (!err)
            err = get_pubkey_byfprint (ctrl, pk, NULL, fpr_card, fpr_len);
          else if (gpg_err_code (err) == GPG_ERR_NO_DATA
                   || gpg_err_code (err) == GPG_ERR_NO_KEYSERVER)
            {
              /* Dirmngr returns NO DATA is the selected keyserver
               * does not have the requested key.  It returns NO
               * KEYSERVER if no LDAP keyservers are configured.  */
              err = gpg_error (GPG_ERR_NO_PUBKEY);
            }
        }

      /* The key on card can be not suitable for requested usage.  */
      if (gpg_err_code (err) == GPG_ERR_UNUSABLE_PUBKEY)
        fpr_card = NULL;        /* Fallthrough as no card.  */
      else
        return err;  /* Success or other error.  */
    }

  if (!fpr_card || (def_secret_key && *def_secret_key
                    && def_secret_key[strlen (def_secret_key)-1] == '!'))
    {
      err = key_byname (ctrl, NULL, namelist, pk, 1, 0, NULL, NULL);
    }
  else
    { /* Default key is specified and card key is also available.  */
      kbnode_t k, keyblock = NULL;

      err = key_byname (ctrl, NULL, namelist, pk, 1, 0, &keyblock, NULL);
      if (err)
        goto leave;
      for (k = keyblock; k; k = k->next)
        {
          PKT_public_key *pk_candidate;
          char fpr[MAX_FINGERPRINT_LEN];

          if (k->pkt->pkttype != PKT_PUBLIC_KEY
              &&k->pkt->pkttype != PKT_PUBLIC_SUBKEY)
            continue;

          pk_candidate = k->pkt->pkt.public_key;
          if (!pk_candidate->flags.valid)
            continue;
          if (!((pk_candidate->pubkey_usage & USAGE_MASK) & pk->req_usage))
            continue;
          fingerprint_from_pk (pk_candidate, fpr, NULL);
          if (!memcmp (fpr_card, fpr, fpr_len))
            {
              release_public_key_parts (pk);
              copy_public_key (pk, pk_candidate);
              break;
            }
        }
      release_kbnode (keyblock);
    }

 leave:
  free_strlist (namelist);
  return err;
}



/*********************************************
 ***********  User ID printing helpers *******
 *********************************************/

/* Return a string with a printable representation of the user_id.
 * this string must be freed by xfree.  If R_NOUID is not NULL it is
 * set to true if a user id was not found; otherwise to false.  */
static char *
get_user_id_string (ctrl_t ctrl, u32 * keyid, int mode, size_t *r_len,
                    int *r_nouid)
{
  user_id_db_t r;
  keyid_list_t a;
  int pass = 0;
  char *p;

  if (r_nouid)
    *r_nouid = 0;

  /* Try it two times; second pass reads from the database.  */
  do
    {
      for (r = user_id_db; r; r = r->next)
	{
	  for (a = r->keyids; a; a = a->next)
	    {
	      if (a->keyid[0] == keyid[0] && a->keyid[1] == keyid[1])
		{
                  if (mode == 2)
                    {
                      /* An empty string as user id is possible.  Make
                         sure that the malloc allocates one byte and
                         does not bail out.  */
                      p = xmalloc (r->len? r->len : 1);
                      memcpy (p, r->name, r->len);
                      if (r_len)
                        *r_len = r->len;
                    }
                  else
                    {
                      if (mode)
                        p = xasprintf ("%08lX%08lX %.*s",
                                       (ulong) keyid[0], (ulong) keyid[1],
                                       r->len, r->name);
                      else
                        p = xasprintf ("%s %.*s", keystr (keyid),
                                       r->len, r->name);
                      if (r_len)
                        *r_len = strlen (p);
                    }

                  return p;
		}
	    }
	}
    }
  while (++pass < 2 && !get_pubkey (ctrl, NULL, keyid));

  if (mode == 2)
    p = xstrdup (user_id_not_found_utf8 ());
  else if (mode)
    p = xasprintf ("%08lX%08lX [?]", (ulong) keyid[0], (ulong) keyid[1]);
  else
    p = xasprintf ("%s [?]", keystr (keyid));

  if (r_nouid)
    *r_nouid = 1;
  if (r_len)
    *r_len = strlen (p);
  return p;
}


char *
get_user_id_string_native (ctrl_t ctrl, u32 * keyid)
{
  char *p = get_user_id_string (ctrl, keyid, 0, NULL, NULL);
  char *p2 = utf8_to_native (p, strlen (p), 0);
  xfree (p);
  return p2;
}


char *
get_long_user_id_string (ctrl_t ctrl, u32 * keyid)
{
  return get_user_id_string (ctrl, keyid, 1, NULL, NULL);
}


/* Please try to use get_user_byfpr instead of this one.  */
char *
get_user_id (ctrl_t ctrl, u32 *keyid, size_t *rn, int *r_nouid)
{
  return get_user_id_string (ctrl, keyid, 2, rn, r_nouid);
}


/* Please try to use get_user_id_byfpr_native instead of this one.  */
char *
get_user_id_native (ctrl_t ctrl, u32 *keyid)
{
  size_t rn;
  char *p = get_user_id (ctrl, keyid, &rn, NULL);
  char *p2 = utf8_to_native (p, rn, 0);
  xfree (p);
  return p2;
}


/* Return the user id for a key designated by its fingerprint, FPR,
   which must be MAX_FINGERPRINT_LEN bytes in size.  Note: the
   returned string, which must be freed using xfree, may not be NUL
   terminated.  To determine the length of the string, you must use
   *RN.  */
char *
get_user_id_byfpr (ctrl_t ctrl, const byte *fpr, size_t *rn)
{
  user_id_db_t r;
  char *p;
  int pass = 0;

  /* Try it two times; second pass reads from the database.  */
  do
    {
      for (r = user_id_db; r; r = r->next)
	{
	  keyid_list_t a;
	  for (a = r->keyids; a; a = a->next)
	    {
	      if (!memcmp (a->fpr, fpr, MAX_FINGERPRINT_LEN))
		{
                  /* An empty string as user id is possible.  Make
                     sure that the malloc allocates one byte and does
                     not bail out.  */
		  p = xmalloc (r->len? r->len : 1);
		  memcpy (p, r->name, r->len);
		  *rn = r->len;
		  return p;
		}
	    }
	}
    }
  while (++pass < 2
	 && !get_pubkey_byfprint (ctrl, NULL, NULL, fpr, MAX_FINGERPRINT_LEN));
  p = xstrdup (user_id_not_found_utf8 ());
  *rn = strlen (p);
  return p;
}

/* Like get_user_id_byfpr, but convert the string to the native
   encoding.  The returned string needs to be freed.  Unlike
   get_user_id_byfpr, the returned string is NUL terminated.  */
char *
get_user_id_byfpr_native (ctrl_t ctrl, const byte *fpr)
{
  size_t rn;
  char *p = get_user_id_byfpr (ctrl, fpr, &rn);
  char *p2 = utf8_to_native (p, rn, 0);
  xfree (p);
  return p2;
}


/* Return the database handle used by this context.  The context still
   owns the handle.  */
KEYDB_HANDLE
get_ctx_handle (GETKEY_CTX ctx)
{
  return ctx->kr_handle;
}

static void
free_akl (struct akl *akl)
{
  if (! akl)
    return;

  if (akl->spec)
    free_keyserver_spec (akl->spec);

  xfree (akl);
}

void
release_akl (void)
{
  while (opt.auto_key_locate)
    {
      struct akl *akl2 = opt.auto_key_locate;
      opt.auto_key_locate = opt.auto_key_locate->next;
      free_akl (akl2);
    }
}


/* Returns true if the AKL is empty or has only the local method
 * active.  */
int
akl_empty_or_only_local (void)
{
  struct akl *akl;
  int any = 0;

  for (akl = opt.auto_key_locate; akl; akl = akl->next)
    if (akl->type != AKL_NODEFAULT && akl->type != AKL_LOCAL)
      {
        any = 1;
        break;
      }

  return !any;
}


/* Returns false on error. */
int
parse_auto_key_locate (const char *options_arg)
{
  char *tok;
  char *options, *options_buf;

  options = options_buf = xstrdup (options_arg);
  while ((tok = optsep (&options)))
    {
      struct akl *akl, *check, *last = NULL;
      int dupe = 0;

      if (tok[0] == '\0')
	continue;

      akl = xmalloc_clear (sizeof (*akl));

      if (ascii_strcasecmp (tok, "clear") == 0)
	{
          xfree (akl);
          free_akl (opt.auto_key_locate);
          opt.auto_key_locate = NULL;
          continue;
        }
      else if (ascii_strcasecmp (tok, "nodefault") == 0)
	akl->type = AKL_NODEFAULT;
      else if (ascii_strcasecmp (tok, "local") == 0)
	akl->type = AKL_LOCAL;
      else if (ascii_strcasecmp (tok, "ldap") == 0)
	akl->type = AKL_LDAP;
      else if (ascii_strcasecmp (tok, "keyserver") == 0)
	akl->type = AKL_KEYSERVER;
      else if (ascii_strcasecmp (tok, "cert") == 0)
	akl->type = AKL_CERT;
      else if (ascii_strcasecmp (tok, "pka") == 0)
	akl->type = AKL_PKA;
      else if (ascii_strcasecmp (tok, "dane") == 0)
	akl->type = AKL_DANE;
      else if (ascii_strcasecmp (tok, "wkd") == 0)
	akl->type = AKL_WKD;
      else if (ascii_strcasecmp (tok, "ntds") == 0)
	akl->type = AKL_NTDS;
      else if ((akl->spec = parse_keyserver_uri (tok, 1)))
	akl->type = AKL_SPEC;
      else
	{
	  free_akl (akl);
          xfree (options_buf);
	  return 0;
	}

      /* We must maintain the order the user gave us */
      for (check = opt.auto_key_locate; check;
	   last = check, check = check->next)
	{
	  /* Check for duplicates */
	  if (check->type == akl->type
	      && (akl->type != AKL_SPEC
		  || (akl->type == AKL_SPEC
		      && strcmp (check->spec->uri, akl->spec->uri) == 0)))
	    {
	      dupe = 1;
	      free_akl (akl);
	      break;
	    }
	}

      if (!dupe)
	{
	  if (last)
	    last->next = akl;
	  else
	    opt.auto_key_locate = akl;
	}
    }

  xfree (options_buf);
  return 1;
}



/* The list of key origins. */
static struct {
  const char *name;
  int origin;
} key_origin_list[] =
  {
    { "self",    KEYORG_SELF    },
    { "file",    KEYORG_FILE    },
    { "url",     KEYORG_URL     },
    { "wkd",     KEYORG_WKD     },
    { "dane",    KEYORG_DANE    },
    { "ks-pref", KEYORG_KS_PREF },
    { "ks",      KEYORG_KS      },
    { "unknown", KEYORG_UNKNOWN }
  };

/* Parse the argument for --key-origin.  Return false on error. */
int
parse_key_origin (char *string)
{
  int i;
  char *comma;

  comma = strchr (string, ',');
  if (comma)
    *comma = 0;

  if (!ascii_strcasecmp (string, "help"))
    {
      log_info (_("valid values for option '%s':\n"), "--key-origin");
      for (i=0; i < DIM (key_origin_list); i++)
        log_info ("  %s\n", key_origin_list[i].name);
      g10_exit (1);
    }

  for (i=0; i < DIM (key_origin_list); i++)
    if (!ascii_strcasecmp (string, key_origin_list[i].name))
      {
        opt.key_origin = key_origin_list[i].origin;
        xfree (opt.key_origin_url);
        opt.key_origin_url = NULL;
        if (comma && comma[1])
          {
            opt.key_origin_url = xstrdup (comma+1);
            trim_spaces (opt.key_origin_url);
          }

        return 1;
      }

  if (comma)
    *comma = ',';
  return 0;
}

/* Return a string or "?" for the key ORIGIN.  */
const char *
key_origin_string (int origin)
{
  int i;

  for (i=0; i < DIM (key_origin_list); i++)
    if (key_origin_list[i].origin == origin)
      return key_origin_list[i].name;
  return "?";
}



/* Returns true if a secret key is available for the public key with
   key id KEYID; returns false if not.  This function ignores legacy
   keys.  Note: this is just a fast check and does not tell us whether
   the secret key is valid; this check merely indicates whether there
   is some secret key with the specified key id.  */
int
have_secret_key_with_kid (u32 *keyid)
{
  gpg_error_t err;
  KEYDB_HANDLE kdbhd;
  KEYDB_SEARCH_DESC desc;
  kbnode_t keyblock;
  kbnode_t node;
  int result = 0;

  kdbhd = keydb_new ();
  if (!kdbhd)
    return 0;
  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0] = keyid[0];
  desc.u.kid[1] = keyid[1];
  while (!result)
    {
      err = keydb_search (kdbhd, &desc, 1, NULL);
      if (err)
        break;

      err = keydb_get_keyblock (kdbhd, &keyblock);
      if (err)
        {
          log_error (_("error reading keyblock: %s\n"), gpg_strerror (err));
          break;
        }

      for (node = keyblock; node; node = node->next)
	{
          /* Bit 0 of the flags is set if the search found the key
             using that key or subkey.  Note: a search will only ever
             match a single key or subkey.  */
	  if ((node->flag & 1))
            {
              log_assert (node->pkt->pkttype == PKT_PUBLIC_KEY
                          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY);

              if (agent_probe_secret_key (NULL, node->pkt->pkt.public_key))
		result = 1; /* Secret key available.  */
	      else
		result = 0;

	      break;
	    }
	}
      release_kbnode (keyblock);
    }

  keydb_release (kdbhd);
  return result;
}


/* Return an error if KEYBLOCK has a primary or subkey with the given
 * fingerprint (FPR,FPRLEN).  */
gpg_error_t
has_key_with_fingerprint (kbnode_t keyblock, const byte *fpr, size_t fprlen)
{
  kbnode_t node;
  PKT_public_key *pk;
  byte pkfpr[MAX_FINGERPRINT_LEN];
  size_t pkfprlen;

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || node->pkt->pkttype == PKT_SECRET_KEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY)
        {
          pk = node->pkt->pkt.public_key;
          fingerprint_from_pk (pk, pkfpr, &pkfprlen);
          if (pkfprlen == fprlen && !memcmp (pkfpr, fpr, fprlen))
            return gpg_error (GPG_ERR_DUP_KEY);
        }
    }
  return 0;
}
