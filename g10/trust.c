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

  /* Some users have conf files with entries like
   *   trusted-key 0x1234567812345678    # foo
   * That is obviously wrong.  Before fixing bug#1206 trailing garbage
   * on a key specification if was ignored.  We detect the above use case
   * here and  cut off the junk-looking-like-a comment.  */
  if (strchr (string, '#'))
    {
      char *buf;

      buf = xtrystrdup (string);
      if (buf)
        {
          *strchr (buf, '#') = 0;
          tdb_register_trusted_key (buf);
          xfree (buf);
          return;
        }
    }

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
