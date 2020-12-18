/* trustdb.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2012 Free Software Foundation, Inc.
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
#include "../common/status.h"
#include "../common/iobuf.h"
#include "../regexp/jimregexp.h"
#include "keydb.h"
#include "../common/util.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "../common/mbox-util.h"
#include "../common/i18n.h"
#include "tdbio.h"
#include "trustdb.h"
#include "tofu.h"
#include "key-clean.h"


typedef struct key_item **KeyHashTable; /* see new_key_hash_table() */

/*
 * Structure to keep track of keys, this is used as an array wherre
 * the item right after the last one has a keyblock set to NULL.
 * Maybe we can drop this thing and replace it by key_item
 */
struct key_array
{
  KBNODE keyblock;
};


/* Control information for the trust DB.  */
static struct
{
  int init;
  int level;
  char *dbname;
  int no_trustdb;
} trustdb_args;

/* Some globals.  */
static struct key_item *user_utk_list; /* temp. used to store --trusted-keys */
static struct key_item *utk_list;      /* all ultimately trusted keys */

static int pending_check_trustdb;

static int validate_keys (ctrl_t ctrl, int interactive);


/**********************************************
 ************* some helpers *******************
 **********************************************/

static struct key_item *
new_key_item (void)
{
  struct key_item *k;

  k = xmalloc_clear (sizeof *k);
  return k;
}

static void
release_key_items (struct key_item *k)
{
  struct key_item *k2;

  for (; k; k = k2)
    {
      k2 = k->next;
      xfree (k->trust_regexp);
      xfree (k);
    }
}

#define KEY_HASH_TABLE_SIZE 1024

/*
 * For fast keylook up we need a hash table.  Each byte of a KeyID
 * should be distributed equally over the 256 possible values (except
 * for v3 keyIDs but we consider them as not important here). So we
 * can just use 10 bits to index a table of KEY_HASH_TABLE_SIZE key items.
 * Possible optimization: Do not use key_items but other hash_table when the
 * duplicates lists get too large.
 */
static KeyHashTable
new_key_hash_table (void)
{
  struct key_item **tbl;

  tbl = xmalloc_clear (KEY_HASH_TABLE_SIZE * sizeof *tbl);
  return tbl;
}

static void
release_key_hash_table (KeyHashTable tbl)
{
  int i;

  if (!tbl)
    return;
  for (i=0; i < KEY_HASH_TABLE_SIZE; i++)
    release_key_items (tbl[i]);
  xfree (tbl);
}

/*
 * Returns: True if the keyID is in the given hash table
 */
static int
test_key_hash_table (KeyHashTable tbl, u32 *kid)
{
  struct key_item *k;

  for (k = tbl[(kid[1] % KEY_HASH_TABLE_SIZE)]; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      return 1;
  return 0;
}

/*
 * Add a new key to the hash table.  The key is identified by its key ID.
 */
static void
add_key_hash_table (KeyHashTable tbl, u32 *kid)
{
  int i = kid[1] % KEY_HASH_TABLE_SIZE;
  struct key_item *k, *kk;

  for (k = tbl[i]; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      return; /* already in table */

  kk = new_key_item ();
  kk->kid[0] = kid[0];
  kk->kid[1] = kid[1];
  kk->next = tbl[i];
  tbl[i] = kk;
}

/*
 * Release a key_array
 */
static void
release_key_array ( struct key_array *keys )
{
    struct key_array *k;

    if (keys) {
        for (k=keys; k->keyblock; k++)
            release_kbnode (k->keyblock);
        xfree (keys);
    }
}


/*********************************************
 **********  Initialization  *****************
 *********************************************/



/*
 * Used to register extra ultimately trusted keys - this has to be done
 * before initializing the validation module.
 * FIXME: Should be replaced by a function to add those keys to the trustdb.
 */
void
tdb_register_trusted_keyid (u32 *keyid)
{
  struct key_item *k;

  k = new_key_item ();
  k->kid[0] = keyid[0];
  k->kid[1] = keyid[1];
  k->next = user_utk_list;
  user_utk_list = k;
}


void
tdb_register_trusted_key (const char *string)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  u32 kid[2];

  err = classify_user_id (string, &desc, 1);
  if (!err)
    {
      if (desc.mode == KEYDB_SEARCH_MODE_LONG_KID)
        {
          register_trusted_keyid (desc.u.kid);
          return;
        }
      if (desc.mode == KEYDB_SEARCH_MODE_FPR
          || desc.mode == KEYDB_SEARCH_MODE_FPR20)
        {
          kid[0] = buf32_to_u32 (desc.u.fpr+12);
          kid[1] = buf32_to_u32 (desc.u.fpr+16);
          register_trusted_keyid (kid);
          return;
        }
    }
  log_error (_("'%s' is not a valid long keyID\n"), string );
}


/*
 * Helper to add a key to the global list of ultimately trusted keys.
 * Returns: true = inserted, false = already in list.
 */
static int
add_utk (u32 *kid)
{
  struct key_item *k;

  if (tdb_keyid_is_utk (kid))
    return 0;

  k = new_key_item ();
  k->kid[0] = kid[0];
  k->kid[1] = kid[1];
  k->ownertrust = TRUST_ULTIMATE;
  k->next = utk_list;
  utk_list = k;
  if( opt.verbose > 1 )
    log_info(_("key %s: accepted as trusted key\n"), keystr(kid));
  return 1;
}


/****************
 * Verify that all our secret keys are usable and put them into the utk_list.
 */
static void
verify_own_keys (ctrl_t ctrl)
{
  TRUSTREC rec;
  ulong recnum;
  int rc;
  struct key_item *k;

  if (utk_list)
    return;

  /* scan the trustdb to find all ultimately trusted keys */
  for (recnum=1; !tdbio_read_record (recnum, &rec, 0); recnum++ )
    {
      if ( rec.rectype == RECTYPE_TRUST
           && (rec.r.trust.ownertrust & TRUST_MASK) == TRUST_ULTIMATE)
        {
            byte *fpr = rec.r.trust.fingerprint;
            int fprlen;
            u32 kid[2];

            /* Problem: We do only use fingerprints in the trustdb but
             * we need the keyID here to indetify the key; we can only
             * use that ugly hack to distinguish between 16 and 20
             * butes fpr - it does not work always so we better change
             * the whole validation code to only work with
             * fingerprints */
            fprlen = (!fpr[16] && !fpr[17] && !fpr[18] && !fpr[19])? 16:20;
            keyid_from_fingerprint (ctrl, fpr, fprlen, kid);
            if (!add_utk (kid))
	      log_info(_("key %s occurs more than once in the trustdb\n"),
		       keystr(kid));
        }
    }

  /* Put any --trusted-key keys into the trustdb */
  for (k = user_utk_list; k; k = k->next)
    {
      if ( add_utk (k->kid) )
        { /* not yet in trustDB as ultimately trusted */
          PKT_public_key pk;

          memset (&pk, 0, sizeof pk);
          rc = get_pubkey (ctrl, &pk, k->kid);
          if (rc)
	    log_info(_("key %s: no public key for trusted key - skipped\n"),
		     keystr(k->kid));
          else
	    {
	      tdb_update_ownertrust
                (ctrl, &pk, ((tdb_get_ownertrust (ctrl, &pk, 0) & ~TRUST_MASK)
                             | TRUST_ULTIMATE ));
	      release_public_key_parts (&pk);
	    }

          if (!opt.quiet)
            log_info (_("key %s marked as ultimately trusted\n"),
                      keystr(k->kid));
        }
    }

  /* release the helper table table */
  release_key_items (user_utk_list);
  user_utk_list = NULL;
  return;
}

/* Returns whether KID is on the list of ultimately trusted keys.  */
int
tdb_keyid_is_utk (u32 *kid)
{
  struct key_item *k;

  for (k = utk_list; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      return 1;

  return 0;
}

/* Return the list of ultimately trusted keys.  */
struct key_item *
tdb_utks (void)
{
  return utk_list;
}

/*********************************************
 *********** TrustDB stuff *******************
 *********************************************/

/*
 * Read a record but die if it does not exist
 */
static void
read_record (ulong recno, TRUSTREC *rec, int rectype )
{
  int rc = tdbio_read_record (recno, rec, rectype);
  if (rc)
    {
      log_error(_("trust record %lu, req type %d: read failed: %s\n"),
                recno, rec->rectype, gpg_strerror (rc) );
      tdbio_invalid();
    }
  if (rectype != rec->rectype)
    {
      log_error(_("trust record %lu is not of requested type %d\n"),
                rec->recnum, rectype);
      tdbio_invalid();
    }
}

/*
 * Write a record and die on error
 */
static void
write_record (ctrl_t ctrl, TRUSTREC *rec)
{
  int rc = tdbio_write_record (ctrl, rec);
  if (rc)
    {
      log_error(_("trust record %lu, type %d: write failed: %s\n"),
			    rec->recnum, rec->rectype, gpg_strerror (rc) );
      tdbio_invalid();
    }
}

/*
 * sync the TrustDb and die on error
 */
static void
do_sync(void)
{
    int rc = tdbio_sync ();
    if(rc)
      {
        log_error (_("trustdb: sync failed: %s\n"), gpg_strerror (rc) );
        g10_exit(2);
      }
}

const char *
trust_model_string (int model)
{
  switch (model)
    {
    case TM_CLASSIC:  return "classic";
    case TM_PGP:      return "pgp";
    case TM_EXTERNAL: return "external";
    case TM_TOFU:     return "tofu";
    case TM_TOFU_PGP: return "tofu+pgp";
    case TM_ALWAYS:   return "always";
    case TM_DIRECT:   return "direct";
    default:          return "unknown";
    }
}

/****************
 * Perform some checks over the trustdb
 *  level 0: only open the db
 *	  1: used for initial program startup
 */
int
setup_trustdb( int level, const char *dbname )
{
    /* just store the args */
    if( trustdb_args.init )
	return 0;
    trustdb_args.level = level;
    trustdb_args.dbname = dbname? xstrdup(dbname): NULL;
    return 0;
}

void
how_to_fix_the_trustdb ()
{
  const char *name = trustdb_args.dbname;

  if (!name)
    name = "trustdb.gpg";

  log_info (_("You may try to re-create the trustdb using the commands:\n"));
  log_info ("  cd %s\n", default_homedir ());
  log_info ("  %s --export-ownertrust > otrust.tmp\n", GPG_NAME);
#ifdef HAVE_W32_SYSTEM
  log_info ("  del %s\n", name);
#else
  log_info ("  rm %s\n", name);
#endif
  log_info ("  %s --import-ownertrust < otrust.tmp\n", GPG_NAME);
  log_info (_("If that does not work, please consult the manual\n"));
}


/* Initialize the trustdb.  With NO_CREATE set a missing trustdb is
 * not an error and the function won't terminate the process on error;
 * in that case 0 is returned if there is a trustdb or an error code
 * if no trustdb is available.  */
gpg_error_t
init_trustdb (ctrl_t ctrl, int no_create)
{
  int level = trustdb_args.level;
  const char* dbname = trustdb_args.dbname;

  if( trustdb_args.init )
    return 0;

  trustdb_args.init = 1;

  if(level==0 || level==1)
    {
      int rc = tdbio_set_dbname (ctrl, dbname, (!no_create && level),
                                 &trustdb_args.no_trustdb);
      if (no_create && trustdb_args.no_trustdb)
        {
          /* No trustdb found and the caller asked us not to create
           * it.  Return an error and set the initialization state
           * back so that we always test for an existing trustdb.  */
          trustdb_args.init = 0;
          return gpg_error (GPG_ERR_ENOENT);
        }
      if (rc)
	log_fatal("can't init trustdb: %s\n", gpg_strerror (rc) );
    }
  else
    BUG();

  if(opt.trust_model==TM_AUTO)
    {
      /* Try and set the trust model off of whatever the trustdb says
	 it is. */
      opt.trust_model=tdbio_read_model();

      /* Sanity check this ;) */
      if(opt.trust_model != TM_CLASSIC
	 && opt.trust_model != TM_PGP
	 && opt.trust_model != TM_TOFU_PGP
	 && opt.trust_model != TM_TOFU
	 && opt.trust_model != TM_EXTERNAL)
	{
	  log_info(_("unable to use unknown trust model (%d) - "
		     "assuming %s trust model\n"),opt.trust_model,"pgp");
	  opt.trust_model = TM_PGP;
	}

      if(opt.verbose)
	log_info(_("using %s trust model\n"),
                 trust_model_string (opt.trust_model));
    }

  if (opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC
      || opt.trust_model == TM_TOFU || opt.trust_model == TM_TOFU_PGP)
    {
      /* Verify the list of ultimately trusted keys and move the
	 --trusted-keys list there as well. */
      if(level==1)
	verify_own_keys (ctrl);

      if(!tdbio_db_matches_options())
	pending_check_trustdb=1;
    }

  return 0;
}


/* Check whether we have a trust database, initializing it if
   necessary if the trust model is not 'always trust'.  Returns true
   if we do have a usable trust database.  */
int
have_trustdb (ctrl_t ctrl)
{
  return !init_trustdb (ctrl, opt.trust_model == TM_ALWAYS);
}


/****************
 * Recreate the WoT but do not ask for new ownertrusts.  Special
 * feature: In batch mode and without a forced yes, this is only done
 * when a check is due.  This can be used to run the check from a crontab
 */
void
check_trustdb (ctrl_t ctrl)
{
  init_trustdb (ctrl, 0);
  if (opt.trust_model == TM_PGP || opt.trust_model == TM_CLASSIC
      || opt.trust_model == TM_TOFU_PGP || opt.trust_model == TM_TOFU)
    {
      if (opt.batch && !opt.answer_yes)
	{
	  ulong scheduled;

	  scheduled = tdbio_read_nextcheck ();
	  if (!scheduled)
	    {
	      log_info (_("no need for a trustdb check\n"));
	      return;
	    }

	  if (scheduled > make_timestamp ())
	    {
	      log_info (_("next trustdb check due at %s\n"),
			strtimestamp (scheduled));
	      return;
	    }
	}

      validate_keys (ctrl, 0);
    }
  else
    log_info (_("no need for a trustdb check with '%s' trust model\n"),
	      trust_model_string(opt.trust_model));
}


/*
 * Recreate the WoT.
 */
void
update_trustdb (ctrl_t ctrl)
{
  init_trustdb (ctrl, 0);
  if (opt.trust_model == TM_PGP || opt.trust_model == TM_CLASSIC
      || opt.trust_model == TM_TOFU_PGP || opt.trust_model == TM_TOFU)
    validate_keys (ctrl, 1);
  else
    log_info (_("no need for a trustdb update with '%s' trust model\n"),
	      trust_model_string(opt.trust_model));
}

void
tdb_revalidation_mark (ctrl_t ctrl)
{
  init_trustdb (ctrl, 0);
  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return;

  /* We simply set the time for the next check to 1 (far back in 1970)
     so that a --update-trustdb will be scheduled.  */
  if (tdbio_write_nextcheck (ctrl, 1))
    do_sync ();
  pending_check_trustdb = 1;
}

int
trustdb_pending_check(void)
{
  return pending_check_trustdb;
}

/* If the trustdb is dirty, and we're interactive, update it.
   Otherwise, check it unless no-auto-check-trustdb is set. */
void
tdb_check_or_update (ctrl_t ctrl)
{
  if (trustdb_pending_check ())
    {
      if (opt.interactive)
	update_trustdb (ctrl);
      else if (!opt.no_auto_check_trustdb)
	check_trustdb (ctrl);
    }
}

void
read_trust_options (ctrl_t ctrl,
                    byte *trust_model, ulong *created, ulong *nextcheck,
		    byte *marginals, byte *completes, byte *cert_depth,
		    byte *min_cert_level)
{
  TRUSTREC opts;

  init_trustdb (ctrl, 0);
  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    memset (&opts, 0, sizeof opts);
  else
    read_record (0, &opts, RECTYPE_VER);

  if(trust_model)
    *trust_model=opts.r.ver.trust_model;
  if(created)
    *created=opts.r.ver.created;
  if(nextcheck)
    *nextcheck=opts.r.ver.nextcheck;
  if(marginals)
    *marginals=opts.r.ver.marginals;
  if(completes)
    *completes=opts.r.ver.completes;
  if(cert_depth)
    *cert_depth=opts.r.ver.cert_depth;
  if(min_cert_level)
    *min_cert_level=opts.r.ver.min_cert_level;
}

/***********************************************
 ***********  Ownertrust et al. ****************
 ***********************************************/

static int
read_trust_record (ctrl_t ctrl, PKT_public_key *pk, TRUSTREC *rec)
{
  int rc;

  init_trustdb (ctrl, 0);
  rc = tdbio_search_trust_bypk (ctrl, pk, rec);
  if (rc)
    {
      if (gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
        log_error ("trustdb: searching trust record failed: %s\n",
                   gpg_strerror (rc));
      return rc;
    }

  if (rec->rectype != RECTYPE_TRUST)
    {
      log_error ("trustdb: record %lu is not a trust record\n",
                 rec->recnum);
      return GPG_ERR_TRUSTDB;
    }

  return 0;
}


/*
 * Return the assigned ownertrust value for the given public key.  The
 * key should be the primary key.  If NO_CREATE is set a missing
 * trustdb will not be created.  This comes for example handy when we
 * want to print status lines (DECRYPTION_KEY) which carry ownertrust
 * values but we usually use --always-trust.
 */
unsigned int
tdb_get_ownertrust (ctrl_t ctrl, PKT_public_key *pk, int no_create)
{
  TRUSTREC rec;
  gpg_error_t err;

  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return TRUST_UNKNOWN;

  /* If the caller asked not to create a trustdb we call init_trustdb
   * directly and allow it to fail with an error code for a
   * non-existing trustdb.  */
  if (no_create && init_trustdb (ctrl, 1))
    return TRUST_UNKNOWN;

  err = read_trust_record (ctrl, pk, &rec);
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    return TRUST_UNKNOWN; /* no record yet */
  if (err)
    {
      tdbio_invalid ();
      return TRUST_UNKNOWN; /* actually never reached */
    }

  return rec.r.trust.ownertrust;
}


unsigned int
tdb_get_min_ownertrust (ctrl_t ctrl, PKT_public_key *pk, int no_create)
{
  TRUSTREC rec;
  gpg_error_t err;

  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return TRUST_UNKNOWN;

  /* If the caller asked not to create a trustdb we call init_trustdb
   * directly and allow it to fail with an error code for a
   * non-existing trustdb.  */
  if (no_create && init_trustdb (ctrl, 1))
    return TRUST_UNKNOWN;

  err = read_trust_record (ctrl, pk, &rec);
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    return TRUST_UNKNOWN; /* no record yet */
  if (err)
    {
      tdbio_invalid ();
      return TRUST_UNKNOWN; /* actually never reached */
    }

  return rec.r.trust.min_ownertrust;
}


/*
 * Set the trust value of the given public key to the new value.
 * The key should be a primary one.
 */
void
tdb_update_ownertrust (ctrl_t ctrl, PKT_public_key *pk, unsigned int new_trust )
{
  TRUSTREC rec;
  gpg_error_t err;

  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return;

  err = read_trust_record (ctrl, pk, &rec);
  if (!err)
    {
      if (DBG_TRUST)
        log_debug ("update ownertrust from %u to %u\n",
                   (unsigned int)rec.r.trust.ownertrust, new_trust );
      if (rec.r.trust.ownertrust != new_trust)
        {
          rec.r.trust.ownertrust = new_trust;
          write_record (ctrl, &rec);
          tdb_revalidation_mark (ctrl);
          do_sync ();
        }
    }
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    { /* no record yet - create a new one */
      size_t dummy;

      if (DBG_TRUST)
        log_debug ("insert ownertrust %u\n", new_trust );

      memset (&rec, 0, sizeof rec);
      rec.recnum = tdbio_new_recnum (ctrl);
      rec.rectype = RECTYPE_TRUST;
      fingerprint_from_pk (pk, rec.r.trust.fingerprint, &dummy);
      rec.r.trust.ownertrust = new_trust;
      write_record (ctrl, &rec);
      tdb_revalidation_mark (ctrl);
      do_sync ();
    }
  else
    {
      tdbio_invalid ();
    }
}

static void
update_min_ownertrust (ctrl_t ctrl, u32 *kid, unsigned int new_trust)
{
  PKT_public_key *pk;
  TRUSTREC rec;
  gpg_error_t err;

  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return;

  pk = xmalloc_clear (sizeof *pk);
  err = get_pubkey (ctrl, pk, kid);
  if (err)
    {
      log_error (_("public key %s not found: %s\n"),
                 keystr (kid), gpg_strerror (err));
      xfree (pk);
      return;
    }

  err = read_trust_record (ctrl, pk, &rec);
  if (!err)
    {
      if (DBG_TRUST)
        log_debug ("key %08lX%08lX: update min_ownertrust from %u to %u\n",
                   (ulong)kid[0],(ulong)kid[1],
		   (unsigned int)rec.r.trust.min_ownertrust,
		   new_trust );
      if (rec.r.trust.min_ownertrust != new_trust)
        {
          rec.r.trust.min_ownertrust = new_trust;
          write_record (ctrl, &rec);
          tdb_revalidation_mark (ctrl);
          do_sync ();
        }
    }
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    { /* no record yet - create a new one */
      size_t dummy;

      if (DBG_TRUST)
        log_debug ("insert min_ownertrust %u\n", new_trust );

      memset (&rec, 0, sizeof rec);
      rec.recnum = tdbio_new_recnum (ctrl);
      rec.rectype = RECTYPE_TRUST;
      fingerprint_from_pk (pk, rec.r.trust.fingerprint, &dummy);
      rec.r.trust.min_ownertrust = new_trust;
      write_record (ctrl, &rec);
      tdb_revalidation_mark (ctrl);
      do_sync ();
    }
  else
    {
      tdbio_invalid ();
    }

  free_public_key (pk);
}


/*
 * Clear the ownertrust and min_ownertrust values.
 *
 * Return: True if a change actually happened.
 */
int
tdb_clear_ownertrusts (ctrl_t ctrl, PKT_public_key *pk)
{
  TRUSTREC rec;
  gpg_error_t err;

  init_trustdb (ctrl, 0);

  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return 0;

  err = read_trust_record (ctrl, pk, &rec);
  if (!err)
    {
      if (DBG_TRUST)
	{
	  log_debug ("clearing ownertrust (old value %u)\n",
		     (unsigned int)rec.r.trust.ownertrust);
	  log_debug ("clearing min_ownertrust (old value %u)\n",
		     (unsigned int)rec.r.trust.min_ownertrust);
	}
      if (rec.r.trust.ownertrust || rec.r.trust.min_ownertrust)
        {
          rec.r.trust.ownertrust = 0;
          rec.r.trust.min_ownertrust = 0;
          write_record (ctrl, &rec);
          tdb_revalidation_mark (ctrl);
          do_sync ();
          return 1;
        }
    }
  else if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    {
      tdbio_invalid ();
    }
  return 0;
}

/*
 * Note: Caller has to do a sync
 */
static void
update_validity (ctrl_t ctrl, PKT_public_key *pk, PKT_user_id *uid,
                 int depth, int validity)
{
  TRUSTREC trec, vrec;
  gpg_error_t err;
  ulong recno;

  namehash_from_uid(uid);

  err = read_trust_record (ctrl, pk, &trec);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    {
      tdbio_invalid ();
      return;
    }
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    {
      /* No record yet - create a new one. */
      size_t dummy;

      memset (&trec, 0, sizeof trec);
      trec.recnum = tdbio_new_recnum (ctrl);
      trec.rectype = RECTYPE_TRUST;
      fingerprint_from_pk (pk, trec.r.trust.fingerprint, &dummy);
      trec.r.trust.ownertrust = 0;
      }

  /* locate an existing one */
  recno = trec.r.trust.validlist;
  while (recno)
    {
      read_record (recno, &vrec, RECTYPE_VALID);
      if ( !memcmp (vrec.r.valid.namehash, uid->namehash, 20) )
        break;
      recno = vrec.r.valid.next;
    }

  if (!recno) /* insert a new validity record */
    {
      memset (&vrec, 0, sizeof vrec);
      vrec.recnum = tdbio_new_recnum (ctrl);
      vrec.rectype = RECTYPE_VALID;
      memcpy (vrec.r.valid.namehash, uid->namehash, 20);
      vrec.r.valid.next = trec.r.trust.validlist;
      trec.r.trust.validlist = vrec.recnum;
    }
  vrec.r.valid.validity = validity;
  vrec.r.valid.full_count = uid->help_full_count;
  vrec.r.valid.marginal_count = uid->help_marginal_count;
  write_record (ctrl, &vrec);
  trec.r.trust.depth = depth;
  write_record (ctrl, &trec);
}


/***********************************************
 *********  Query trustdb values  **************
 ***********************************************/

/* Return true if key is disabled.  Note that this is usually used via
   the pk_is_disabled macro.  */
int
tdb_cache_disabled_value (ctrl_t ctrl, PKT_public_key *pk)
{
  gpg_error_t err;
  TRUSTREC trec;
  int disabled = 0;

  if (pk->flags.disabled_valid)
    return pk->flags.disabled;

  init_trustdb (ctrl, 0);

  if (trustdb_args.no_trustdb)
    return 0;  /* No trustdb => not disabled.  */

  err = read_trust_record (ctrl, pk, &trec);
  if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    {
      tdbio_invalid ();
      goto leave;
    }
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    {
      /* No record found, so assume not disabled.  */
      goto leave;
    }

  if ((trec.r.trust.ownertrust & TRUST_FLAG_DISABLED))
    disabled = 1;

  /* Cache it for later so we don't need to look at the trustdb every
     time */
  pk->flags.disabled = disabled;
  pk->flags.disabled_valid = 1;

 leave:
  return disabled;
}


void
tdb_check_trustdb_stale (ctrl_t ctrl)
{
  static int did_nextcheck=0;

  init_trustdb (ctrl, 0);

  if (trustdb_args.no_trustdb)
    return;  /* No trustdb => can't be stale.  */

  if (!did_nextcheck
      && (opt.trust_model == TM_PGP || opt.trust_model == TM_CLASSIC
          || opt.trust_model == TM_TOFU_PGP || opt.trust_model == TM_TOFU))
    {
      ulong scheduled;

      did_nextcheck = 1;
      scheduled = tdbio_read_nextcheck ();
      if ((scheduled && scheduled <= make_timestamp ())
	  || pending_check_trustdb)
        {
          if (opt.no_auto_check_trustdb)
            {
              pending_check_trustdb = 1;
              if (!opt.quiet)
                log_info (_("please do a --check-trustdb\n"));
            }
          else
            {
              if (!opt.quiet)
                log_info (_("checking the trustdb\n"));
              validate_keys (ctrl, 0);
            }
        }
    }
}

/*
 * Return the validity information for KB/PK (at least one of them
 * must be non-NULL).  This is the core of get_validity.  If SIG is
 * not NULL, then the trust is being evaluated in the context of the
 * provided signature.  This is used by the TOFU code to record
 * statistics.
 */
unsigned int
tdb_get_validity_core (ctrl_t ctrl,
                       kbnode_t kb,
                       PKT_public_key *pk, PKT_user_id *uid,
                       PKT_public_key *main_pk,
		       PKT_signature *sig,
		       int may_ask)
{
  TRUSTREC trec, vrec;
  gpg_error_t err = 0;
  ulong recno;
#ifdef USE_TOFU
  unsigned int tofu_validity = TRUST_UNKNOWN;
  int free_kb = 0;
#endif
  unsigned int validity = TRUST_UNKNOWN;

  if (kb && pk)
    log_assert (keyid_cmp (pk_main_keyid (pk),
                           pk_main_keyid (kb->pkt->pkt.public_key)) == 0);

  if (! pk)
    {
      log_assert (kb);
      pk = kb->pkt->pkt.public_key;
    }

#ifndef USE_TOFU
  (void)sig;
  (void)may_ask;
#endif

  init_trustdb (ctrl, 0);

  /* If we have no trustdb (which also means it has not been created)
     and the trust-model is always, we don't know the validity -
     return immediately.  If we won't do that the tdbio code would try
     to open the trustdb and run into a fatal error.  */
  if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
    return TRUST_UNKNOWN;

  check_trustdb_stale (ctrl);

  if(opt.trust_model==TM_DIRECT)
    {
      /* Note that this happens BEFORE any user ID stuff is checked.
	 The direct trust model applies to keys as a whole. */
      validity = tdb_get_ownertrust (ctrl, main_pk, 0);
      goto leave;
    }

#ifdef USE_TOFU
  if (opt.trust_model == TM_TOFU || opt.trust_model == TM_TOFU_PGP)
    {
      kbnode_t n = NULL;
      strlist_t user_id_list = NULL;
      int done = 0;

      /* If the caller didn't supply a user id then use all uids.  */
      if (! uid)
        {
          if (! kb)
            {
              kb = get_pubkeyblock (ctrl, main_pk->keyid);
              free_kb = 1;
            }
          n = kb;
        }

      if (DBG_TRUST && sig && sig->signers_uid)
        log_debug ("TOFU: only considering user id: '%s'\n",
                   sig->signers_uid);

      while (!done && (uid || (n = find_next_kbnode (n, PKT_USER_ID))))
	{
	  PKT_user_id *user_id;
          int expired = 0;

	  if (uid)
            {
              user_id = uid;
              /* If the caller specified a user id, then we only
                 process the specified user id and are done after the
                 first iteration.  */
              done = 1;
            }
	  else
	    user_id = n->pkt->pkt.user_id;

          if (user_id->attrib_data)
            /* Skip user attributes.  */
            continue;

          if (sig && sig->signers_uid)
            /* Make sure the UID matches.  */
            {
              char *email = mailbox_from_userid (user_id->name);
              if (!email || !*email || strcmp (sig->signers_uid, email) != 0)
                {
                  if (DBG_TRUST)
                    log_debug ("TOFU: skipping user id '%s', which does"
                               " not match the signer's email ('%s')\n",
                               email, sig->signers_uid);
                  xfree (email);
                  continue;
                }
              xfree (email);
            }

          /* If the user id is revoked or expired, then skip it.  */
          if (user_id->flags.revoked || user_id->flags.expired)
            {
              if (DBG_TRUST)
                {
                  char *s;
                  if (user_id->flags.revoked && user_id->flags.expired)
                    s = "revoked and expired";
                  else if (user_id->flags.revoked)
                    s = "revoked";
                  else
                    s = "expire";

                  log_debug ("TOFU: Ignoring %s user id (%s)\n",
                             s, user_id->name);
                }

              if (user_id->flags.revoked)
                continue;

              expired = 1;
            }

          add_to_strlist (&user_id_list, user_id->name);
          user_id_list->flags = expired;
        }

      /* Process the user ids in the order they appear in the key
         block.  */
      strlist_rev (&user_id_list);

      /* It only makes sense to observe any signature before getting
         the validity.  This is because if the current signature
         results in a conflict, then we damn well want to take that
         into account.  */
      if (sig)
        {
          err = tofu_register_signature (ctrl, main_pk, user_id_list,
                                         sig->digest, sig->digest_len,
                                         sig->timestamp, "unknown");
          if (err)
            {
              log_error ("TOFU: error registering signature: %s\n",
                         gpg_strerror (err));

              tofu_validity = TRUST_UNKNOWN;
            }
        }
      if (! err)
        tofu_validity = tofu_get_validity (ctrl, main_pk, user_id_list,
                                           may_ask);

      free_strlist (user_id_list);
      if (free_kb)
        release_kbnode (kb);
    }
#endif /*USE_TOFU*/

  if (opt.trust_model == TM_TOFU_PGP
      || opt.trust_model == TM_CLASSIC
      || opt.trust_model == TM_PGP)
    {
      err = read_trust_record (ctrl, main_pk, &trec);
      if (err && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
	{
	  tdbio_invalid ();
	  return 0;
	}
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
	{
	  /* No record found.  */
	  validity = TRUST_UNKNOWN;
	  goto leave;
	}

      /* Loop over all user IDs */
      recno = trec.r.trust.validlist;
      validity = 0;
      while (recno)
	{
	  read_record (recno, &vrec, RECTYPE_VALID);

	  if(uid)
	    {
	      /* If a user ID is given we return the validity for that
		 user ID ONLY.  If the namehash is not found, then
		 there is no validity at all (i.e. the user ID wasn't
		 signed). */
	      if(memcmp(vrec.r.valid.namehash,uid->namehash,20)==0)
		{
		  validity=(vrec.r.valid.validity & TRUST_MASK);
		  break;
		}
	    }
	  else
	    {
	      /* If no user ID is given, we take the maximum validity
		 over all user IDs */
	      if (validity < (vrec.r.valid.validity & TRUST_MASK))
		validity = (vrec.r.valid.validity & TRUST_MASK);
	    }

	  recno = vrec.r.valid.next;
	}

      if ((trec.r.trust.ownertrust & TRUST_FLAG_DISABLED))
	{
	  validity |= TRUST_FLAG_DISABLED;
	  pk->flags.disabled = 1;
	}
      else
	pk->flags.disabled = 0;
      pk->flags.disabled_valid = 1;
    }

 leave:
#ifdef USE_TOFU
  validity = tofu_wot_trust_combine (tofu_validity, validity);
#else /*!USE_TOFU*/
  validity &= TRUST_MASK;

  if (validity == TRUST_NEVER)
    /* TRUST_NEVER trumps everything else.  */
    validity |= TRUST_NEVER;
  if (validity == TRUST_EXPIRED)
    /* TRUST_EXPIRED trumps everything but TRUST_NEVER.  */
    validity |= TRUST_EXPIRED;
#endif /*!USE_TOFU*/

  if (opt.trust_model != TM_TOFU
      && pending_check_trustdb)
    validity |= TRUST_FLAG_PENDING_CHECK;

  return validity;
}


static void
get_validity_counts (ctrl_t ctrl, PKT_public_key *pk, PKT_user_id *uid)
{
  TRUSTREC trec, vrec;
  ulong recno;

  if(pk==NULL || uid==NULL)
    BUG();

  namehash_from_uid(uid);

  uid->help_marginal_count=uid->help_full_count=0;

  init_trustdb (ctrl, 0);

  if(read_trust_record (ctrl, pk, &trec))
    return;

  /* loop over all user IDs */
  recno = trec.r.trust.validlist;
  while (recno)
    {
      read_record (recno, &vrec, RECTYPE_VALID);

      if(memcmp(vrec.r.valid.namehash,uid->namehash,20)==0)
	{
	  uid->help_marginal_count=vrec.r.valid.marginal_count;
	  uid->help_full_count=vrec.r.valid.full_count;
	  /*  es_printf("Fetched marginal %d, full %d\n",uid->help_marginal_count,uid->help_full_count); */
	  break;
	}

      recno = vrec.r.valid.next;
    }
}

void
list_trust_path( const char *username )
{
  (void)username;
}

/****************
 * Enumerate all keys, which are needed to build all trust paths for
 * the given key.  This function does not return the key itself or
 * the ultimate key (the last point in cerificate chain).  Only
 * certificate chains which ends up at an ultimately trusted key
 * are listed.	If ownertrust or validity is not NULL, the corresponding
 * value for the returned LID is also returned in these variable(s).
 *
 *  1) create a void pointer and initialize it to NULL
 *  2) pass this void pointer by reference to this function.
 *     Set lid to the key you want to enumerate and pass it by reference.
 *  3) call this function as long as it does not return -1
 *     to indicate EOF. LID does contain the next key used to build the web
 *  4) Always call this function a last time with LID set to NULL,
 *     so that it can free its context.
 *
 * Returns: -1 on EOF or the level of the returned LID
 */
int
enum_cert_paths( void **context, ulong *lid,
		 unsigned *ownertrust, unsigned *validity )
{
  (void)context;
  (void)lid;
  (void)ownertrust;
  (void)validity;
  return -1;
}


/****************
 * Print the current path
 */
void
enum_cert_paths_print (void **context, FILE *fp,
                       int refresh, ulong selected_lid)
{
  (void)context;
  (void)fp;
  (void)refresh;
  (void)selected_lid;
}



/****************************************
 *********** NEW NEW NEW ****************
 ****************************************/

static int
ask_ownertrust (ctrl_t ctrl, u32 *kid, int minimum)
{
  PKT_public_key *pk;
  int rc;
  int ot;

  pk = xmalloc_clear (sizeof *pk);
  rc = get_pubkey (ctrl, pk, kid);
  if (rc)
    {
      log_error (_("public key %s not found: %s\n"),
                 keystr(kid), gpg_strerror (rc) );
      return TRUST_UNKNOWN;
    }

  if(opt.force_ownertrust)
    {
      log_info("force trust for key %s to %s\n",
	       keystr(kid),trust_value_to_string(opt.force_ownertrust));
      tdb_update_ownertrust (ctrl, pk, opt.force_ownertrust);
      ot=opt.force_ownertrust;
    }
  else
    {
      ot=edit_ownertrust (ctrl, pk, 0);
      if(ot>0)
	ot = tdb_get_ownertrust (ctrl, pk, 0);
      else if(ot==0)
	ot = minimum?minimum:TRUST_UNDEFINED;
      else
	ot = -1; /* quit */
    }

  free_public_key( pk );

  return ot;
}


static void
mark_keyblock_seen (KeyHashTable tbl, KBNODE node)
{
  for ( ;node; node = node->next )
    if (node->pkt->pkttype == PKT_PUBLIC_KEY
	|| node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      {
        u32 aki[2];

        keyid_from_pk (node->pkt->pkt.public_key, aki);
        add_key_hash_table (tbl, aki);
      }
}


static void
dump_key_array (int depth, struct key_array *keys)
{
  struct key_array *kar;

  for (kar=keys; kar->keyblock; kar++)
    {
      KBNODE node = kar->keyblock;
      u32 kid[2];

      keyid_from_pk(node->pkt->pkt.public_key, kid);
      es_printf ("%d:%08lX%08lX:K::%c::::\n",
                 depth, (ulong)kid[0], (ulong)kid[1], '?');

      for (; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_USER_ID)
            {
              int len = node->pkt->pkt.user_id->len;

              if (len > 30)
                len = 30;
              es_printf ("%d:%08lX%08lX:U:::%c:::",
                         depth, (ulong)kid[0], (ulong)kid[1],
                         (node->flag & 4)? 'f':
                         (node->flag & 2)? 'm':
                         (node->flag & 1)? 'q':'-');
              es_write_sanitized (es_stdout, node->pkt->pkt.user_id->name,
                                  len, ":", NULL);
              es_putc (':', es_stdout);
              es_putc ('\n', es_stdout);
            }
        }
    }
}


static void
store_validation_status (ctrl_t ctrl, int depth,
                         kbnode_t keyblock, KeyHashTable stored)
{
  KBNODE node;
  int status;
  int any = 0;

  for (node=keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          PKT_user_id *uid = node->pkt->pkt.user_id;
          if (node->flag & 4)
            status = TRUST_FULLY;
          else if (node->flag & 2)
            status = TRUST_MARGINAL;
          else if (node->flag & 1)
            status = TRUST_UNDEFINED;
          else
            status = 0;

          if (status)
            {
              update_validity (ctrl, keyblock->pkt->pkt.public_key,
			       uid, depth, status);

	      mark_keyblock_seen(stored,keyblock);

              any = 1;
            }
        }
    }

  if (any)
    do_sync ();
}


/* Returns a sanitized copy of the regexp (which might be "", but not
   NULL). */
/* Operator characters except '.' and backslash.
   See regex(7) on BSD.  */
#define REGEXP_OPERATOR_CHARS "^[$()|*+?{"

static char *
sanitize_regexp(const char *old)
{
  size_t start=0,len=strlen(old),idx=0;
  int escaped=0,standard_bracket=0;
  char *new=xmalloc((len*2)+1); /* enough to \-escape everything if we
				   have to */

  /* There are basically two commonly-used regexps here.  GPG and most
     versions of PGP use "<[^>]+[@.]example\.com>$" and PGP (9)
     command line uses "example.com" (i.e. whatever the user specifies,
     and we can't expect users know to use "\." instead of ".").  So
     here are the rules: we're allowed to start with "<[^>]+[@.]" and
     end with ">$" or start and end with nothing.  In between, the
     only legal regex character is ".", and everything else gets
     escaped.  Part of the gotcha here is that some regex packages
     allow more than RFC-4880 requires.  For example, 4880 has no "{}"
     operator, but GNU regex does.  Commenting removes these operators
     from consideration.  A possible future enhancement is to use
     commenting to effectively back off a given regex to the Henry
     Spencer syntax in 4880. -dshaw */

  /* Are we bracketed between "<[^>]+[@.]" and ">$" ? */
  if(len>=12 && strncmp(old,"<[^>]+[@.]",10)==0
     && old[len-2]=='>' && old[len-1]=='$')
    {
      strcpy(new,"<[^>]+[@.]");
      idx=strlen(new);
      standard_bracket=1;
      start+=10;
      len-=2;
    }

  /* Walk the remaining characters and ensure that everything that is
     left is not an operational regex character. */
  for(;start<len;start++)
    {
      if(!escaped && old[start]=='\\')
	escaped=1;
      else if (!escaped && strchr (REGEXP_OPERATOR_CHARS, old[start]))
	new[idx++]='\\';
      else
	escaped=0;

      new[idx++]=old[start];
    }

  new[idx]='\0';

  /* Note that the (sub)string we look at might end with a bare "\".
     If it does, leave it that way.  If the regexp actually ended with
     ">$", then it was escaping the ">" and is fine.  If the regexp
     actually ended with the bare "\", then it's an illegal regexp and
     regcomp should kick it out. */

  if(standard_bracket)
    strcat(new,">$");

  return new;
}

/* Used by validate_one_keyblock to confirm a regexp within a trust
   signature.  Returns 1 for match, and 0 for no match or regex
   error. */
static int
check_regexp(const char *expr,const char *string)
{
  int ret;
  char *regexp;

  regexp=sanitize_regexp(expr);

  {
    regex_t pat;

    ret=regcomp(&pat,regexp,REG_ICASE|REG_EXTENDED);
    if(ret==0)
      {
	ret=regexec(&pat,string,0,NULL,0);
	regfree(&pat);
      }
    ret=(ret==0);
  }

  if(DBG_TRUST)
    log_debug("regexp '%s' ('%s') on '%s': %s\n",
	      regexp,expr,string,ret?"YES":"NO");

  xfree(regexp);

  return ret;
}

/*
 * Return true if the key is signed by one of the keys in the given
 * key ID list.  User IDs with a valid signature are marked by node
 * flags as follows:
 *  flag bit 0: There is at least one signature
 *           1: There is marginal confidence that this is a legitimate uid
 *           2: There is full confidence that this is a legitimate uid.
 *           8: Used for internal purposes.
 *           9: Ditto (in mark_usable_uid_certs())
 *          10: Ditto (ditto)
 * This function assumes that all kbnode flags are cleared on entry.
 */
static int
validate_one_keyblock (ctrl_t ctrl, kbnode_t kb, struct key_item *klist,
                       u32 curtime, u32 *next_expire)
{
  struct key_item *kr;
  KBNODE node, uidnode=NULL;
  PKT_user_id *uid=NULL;
  PKT_public_key *pk = kb->pkt->pkt.public_key;
  u32 main_kid[2];
  int issigned=0, any_signed = 0;

  keyid_from_pk(pk, main_kid);
  for (node=kb; node; node = node->next)
    {
      /* A bit of discussion here: is it better for the web of trust
	 to be built among only self-signed uids?  On the one hand, a
	 self-signed uid is a statement that the key owner definitely
	 intended that uid to be there, but on the other hand, a
	 signed (but not self-signed) uid does carry trust, of a sort,
	 even if it is a statement being made by people other than the
	 key owner "through" the uids on the key owner's key.  I'm
	 going with the latter.  However, if the user ID was
	 explicitly revoked, or passively allowed to expire, that
	 should stop validity through the user ID until it is
	 resigned.  -dshaw */

      if (node->pkt->pkttype == PKT_USER_ID
	  && !node->pkt->pkt.user_id->flags.revoked
	  && !node->pkt->pkt.user_id->flags.expired)
        {
          if (uidnode && issigned)
            {
              if (uid->help_full_count >= opt.completes_needed
                  || uid->help_marginal_count >= opt.marginals_needed )
                uidnode->flag |= 4;
              else if (uid->help_full_count || uid->help_marginal_count)
                uidnode->flag |= 2;
              uidnode->flag |= 1;
              any_signed = 1;
            }
          uidnode = node;
	  uid=uidnode->pkt->pkt.user_id;

	  /* If the selfsig is going to expire... */
	  if(uid->expiredate && uid->expiredate<*next_expire)
	    *next_expire = uid->expiredate;

          issigned = 0;
	  get_validity_counts (ctrl, pk, uid);
          mark_usable_uid_certs (ctrl, kb, uidnode, main_kid, klist,
                                 curtime, next_expire);
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE
	       && (node->flag & (1<<8)) && uid)
        {
	  /* Note that we are only seeing unrevoked sigs here */
          PKT_signature *sig = node->pkt->pkt.signature;

          kr = is_in_klist (klist, sig);
	  /* If the trust_regexp does not match, it's as if the sig
             did not exist.  This is safe for non-trust sigs as well
             since we don't accept a regexp on the sig unless it's a
             trust sig. */
          if (kr && (!kr->trust_regexp
                     || !(opt.trust_model == TM_PGP
                          || opt.trust_model == TM_TOFU_PGP)
                     || (uidnode
                         && check_regexp(kr->trust_regexp,
                                         uidnode->pkt->pkt.user_id->name))))
            {
	      /* Are we part of a trust sig chain?  We always favor
                 the latest trust sig, rather than the greater or
                 lesser trust sig or value.  I could make a decent
                 argument for any of these cases, but this seems to be
                 what PGP does, and I'd like to be compatible. -dms */
              if ((opt.trust_model == TM_PGP
                   || opt.trust_model == TM_TOFU_PGP)
                  && sig->trust_depth
                  && pk->trust_timestamp <= sig->timestamp)
		{
		  unsigned char depth;

		  /* If the depth on the signature is less than the
		     chain currently has, then use the signature depth
		     so we don't increase the depth beyond what the
		     signer wanted.  If the depth on the signature is
		     more than the chain currently has, then use the
		     chain depth so we use as much of the signature
		     depth as the chain will permit.  An ultimately
		     trusted signature can restart the depth to
		     whatever level it likes. */

		  if (sig->trust_depth < kr->trust_depth
                      || kr->ownertrust == TRUST_ULTIMATE)
		    depth = sig->trust_depth;
		  else
		    depth = kr->trust_depth;

		  if (depth)
		    {
		      if(DBG_TRUST)
			log_debug ("trust sig on %s, sig depth is %d,"
                                   " kr depth is %d\n",
                                   uidnode->pkt->pkt.user_id->name,
                                   sig->trust_depth,
                                   kr->trust_depth);

		      /* If we got here, we know that:

			 this is a trust sig.

			 it's a newer trust sig than any previous trust
			 sig on this key (not uid).

			 it is legal in that it was either generated by an
			 ultimate key, or a key that was part of a trust
			 chain, and the depth does not violate the
			 original trust sig.

			 if there is a regexp attached, it matched
			 successfully.
		      */

		      if (DBG_TRUST)
			log_debug ("replacing trust value %d with %d and "
                                   "depth %d with %d\n",
                                   pk->trust_value,sig->trust_value,
                                   pk->trust_depth,depth);

		      pk->trust_value = sig->trust_value;
		      pk->trust_depth = depth-1;

		      /* If the trust sig contains a regexp, record it
			 on the pk for the next round. */
		      if (sig->trust_regexp)
			pk->trust_regexp = sig->trust_regexp;
		    }
		}

              if (kr->ownertrust == TRUST_ULTIMATE)
                uid->help_full_count = opt.completes_needed;
              else if (kr->ownertrust == TRUST_FULLY)
                uid->help_full_count++;
              else if (kr->ownertrust == TRUST_MARGINAL)
                uid->help_marginal_count++;
              issigned = 1;
	    }
        }
    }

  if (uidnode && issigned)
    {
      if (uid->help_full_count >= opt.completes_needed
	  || uid->help_marginal_count >= opt.marginals_needed )
        uidnode->flag |= 4;
      else if (uid->help_full_count || uid->help_marginal_count)
        uidnode->flag |= 2;
      uidnode->flag |= 1;
      any_signed = 1;
    }

  return any_signed;
}


static int
search_skipfnc (void *opaque, u32 *kid, int dummy_uid_no)
{
  (void)dummy_uid_no;
  return test_key_hash_table ((KeyHashTable)opaque, kid);
}


/*
 * Scan all keys and return a key_array of all suitable keys from
 * kllist.  The caller has to pass keydb handle so that we don't use
 * to create our own.  Returns either a key_array or NULL in case of
 * an error.  No results found are indicated by an empty array.
 * Caller hast to release the returned array.
 */
static struct key_array *
validate_key_list (ctrl_t ctrl, KEYDB_HANDLE hd, KeyHashTable full_trust,
                   struct key_item *klist, u32 curtime, u32 *next_expire)
{
  KBNODE keyblock = NULL;
  struct key_array *keys = NULL;
  size_t nkeys, maxkeys;
  int rc;
  KEYDB_SEARCH_DESC desc;

  maxkeys = 1000;
  keys = xmalloc ((maxkeys+1) * sizeof *keys);
  nkeys = 0;

  rc = keydb_search_reset (hd);
  if (rc)
    {
      log_error ("keydb_search_reset failed: %s\n", gpg_strerror (rc));
      xfree (keys);
      return NULL;
    }

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  desc.skipfnc = search_skipfnc;
  desc.skipfncvalue = full_trust;
  rc = keydb_search (hd, &desc, 1, NULL);
  if (gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
    {
      keys[nkeys].keyblock = NULL;
      return keys;
    }
  if (rc)
    {
      log_error ("keydb_search(first) failed: %s\n", gpg_strerror (rc));
      goto die;
    }

  desc.mode = KEYDB_SEARCH_MODE_NEXT; /* change mode */
  do
    {
      PKT_public_key *pk;

      rc = keydb_get_keyblock (hd, &keyblock);
      if (rc)
        {
          log_error ("keydb_get_keyblock failed: %s\n", gpg_strerror (rc));
	  goto die;
        }

      if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY)
        {
          log_debug ("ooops: invalid pkttype %d encountered\n",
                     keyblock->pkt->pkttype);
          dump_kbnode (keyblock);
          release_kbnode(keyblock);
          continue;
        }

      /* prepare the keyblock for further processing */
      merge_keys_and_selfsig (ctrl, keyblock);
      clear_kbnode_flags (keyblock);
      pk = keyblock->pkt->pkt.public_key;
      if (pk->has_expired || pk->flags.revoked)
        {
          /* it does not make sense to look further at those keys */
          mark_keyblock_seen (full_trust, keyblock);
        }
      else if (validate_one_keyblock (ctrl, keyblock, klist,
                                      curtime, next_expire))
        {
	  KBNODE node;

          if (pk->expiredate && pk->expiredate >= curtime
              && pk->expiredate < *next_expire)
            *next_expire = pk->expiredate;

          if (nkeys == maxkeys) {
            maxkeys += 1000;
            keys = xrealloc (keys, (maxkeys+1) * sizeof *keys);
          }
          keys[nkeys++].keyblock = keyblock;

	  /* Optimization - if all uids are fully trusted, then we
	     never need to consider this key as a candidate again. */

	  for (node=keyblock; node; node = node->next)
	    if (node->pkt->pkttype == PKT_USER_ID && !(node->flag & 4))
	      break;

	  if(node==NULL)
	    mark_keyblock_seen (full_trust, keyblock);

          keyblock = NULL;
        }

      release_kbnode (keyblock);
      keyblock = NULL;
    }
  while (!(rc = keydb_search (hd, &desc, 1, NULL)));

  if (rc && gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
    {
      log_error ("keydb_search_next failed: %s\n", gpg_strerror (rc));
      goto die;
    }

  keys[nkeys].keyblock = NULL;
  return keys;

 die:
  keys[nkeys].keyblock = NULL;
  release_key_array (keys);
  return NULL;
}

/* Caller must sync */
static void
reset_trust_records (ctrl_t ctrl)
{
  TRUSTREC rec;
  ulong recnum;
  int count = 0, nreset = 0;

  for (recnum=1; !tdbio_read_record (recnum, &rec, 0); recnum++ )
    {
      if(rec.rectype==RECTYPE_TRUST)
	{
	  count++;
	  if(rec.r.trust.min_ownertrust)
	    {
	      rec.r.trust.min_ownertrust=0;
	      write_record (ctrl, &rec);
	    }

	}
      else if(rec.rectype==RECTYPE_VALID
	      && ((rec.r.valid.validity&TRUST_MASK)
		  || rec.r.valid.marginal_count
		  || rec.r.valid.full_count))
	{
	  rec.r.valid.validity &= ~TRUST_MASK;
	  rec.r.valid.marginal_count=rec.r.valid.full_count=0;
	  nreset++;
	  write_record (ctrl, &rec);
	}

    }

  if (opt.verbose)
    {
      log_info (ngettext("%d key processed",
                         "%d keys processed",
                         count), count);
      log_printf (ngettext(" (%d validity count cleared)\n",
                           " (%d validity counts cleared)\n",
                           nreset), nreset);
    }
}

/*
 * Run the key validation procedure.
 *
 * This works this way:
 * Step 1: Find all ultimately trusted keys (UTK).
 *         mark them all as seen and put them into klist.
 * Step 2: loop max_cert_times
 * Step 3:   if OWNERTRUST of any key in klist is undefined
 *             ask user to assign ownertrust
 * Step 4:   Loop over all keys in the keyDB which are not marked seen
 * Step 5:     if key is revoked or expired
 *                mark key as seen
 *                continue loop at Step 4
 * Step 6:     For each user ID of that key signed by a key in klist
 *                Calculate validity by counting trusted signatures.
 *                Set validity of user ID
 * Step 7:     If any signed user ID was found
 *                mark key as seen
 *             End Loop
 * Step 8:   Build a new klist from all fully trusted keys from step 6
 *           End Loop
 *         Ready
 *
 */
static int
validate_keys (ctrl_t ctrl, int interactive)
{
  int rc = 0;
  int quit=0;
  struct key_item *klist = NULL;
  struct key_item *k;
  struct key_array *keys = NULL;
  struct key_array *kar;
  KEYDB_HANDLE kdb = NULL;
  KBNODE node;
  int depth;
  int ot_unknown, ot_undefined, ot_never, ot_marginal, ot_full, ot_ultimate;
  KeyHashTable stored,used,full_trust;
  u32 start_time, next_expire;

  /* Make sure we have all sigs cached.  TODO: This is going to
     require some architectural re-thinking, as it is agonizingly slow.
     Perhaps combine this with reset_trust_records(), or only check
     the caches on keys that are actually involved in the web of
     trust. */
  keydb_rebuild_caches (ctrl, 0);

  kdb = keydb_new ();
  if (!kdb)
    return gpg_error_from_syserror ();

  start_time = make_timestamp ();
  next_expire = 0xffffffff; /* set next expire to the year 2106 */
  stored = new_key_hash_table ();
  used = new_key_hash_table ();
  full_trust = new_key_hash_table ();

  reset_trust_records (ctrl);

  /* Fixme: Instead of always building a UTK list, we could just build it
   * here when needed */
  if (!utk_list)
    {
      if (!opt.quiet)
        log_info (_("no ultimately trusted keys found\n"));
      goto leave;
    }

  /* mark all UTKs as used and fully_trusted and set validity to
     ultimate */
  for (k=utk_list; k; k = k->next)
    {
      KBNODE keyblock;
      PKT_public_key *pk;

      keyblock = get_pubkeyblock (ctrl, k->kid);
      if (!keyblock)
        {
          log_error (_("public key of ultimately"
                       " trusted key %s not found\n"), keystr(k->kid));
          continue;
        }
      mark_keyblock_seen (used, keyblock);
      mark_keyblock_seen (stored, keyblock);
      mark_keyblock_seen (full_trust, keyblock);
      pk = keyblock->pkt->pkt.public_key;
      for (node=keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_USER_ID)
	    update_validity (ctrl, pk, node->pkt->pkt.user_id,
                             0, TRUST_ULTIMATE);
        }
      if ( pk->expiredate && pk->expiredate >= start_time
           && pk->expiredate < next_expire)
        next_expire = pk->expiredate;

      release_kbnode (keyblock);
      do_sync ();
    }

  if (opt.trust_model == TM_TOFU)
    /* In the TOFU trust model, we only need to save the ultimately
       trusted keys.  */
    goto leave;

  klist = utk_list;

  if (!opt.quiet)
    log_info ("marginals needed: %d  completes needed: %d  trust model: %s\n",
              opt.marginals_needed, opt.completes_needed,
              trust_model_string (opt.trust_model));

  for (depth=0; depth < opt.max_cert_depth; depth++)
    {
      int valids=0,key_count;
      /* See whether we should assign ownertrust values to the keys in
         klist.  */
      ot_unknown = ot_undefined = ot_never = 0;
      ot_marginal = ot_full = ot_ultimate = 0;
      for (k=klist; k; k = k->next)
        {
	  int min=0;

	  /* 120 and 60 are as per RFC2440 */
	  if(k->trust_value>=120)
	    min=TRUST_FULLY;
	  else if(k->trust_value>=60)
	    min=TRUST_MARGINAL;

	  if(min!=k->min_ownertrust)
	    update_min_ownertrust (ctrl, k->kid,min);

          if (interactive && k->ownertrust == TRUST_UNKNOWN)
	    {
	      k->ownertrust = ask_ownertrust (ctrl, k->kid,min);

	      if (k->ownertrust == (unsigned int)(-1))
		{
		  quit=1;
		  goto leave;
		}
	    }

	  /* This can happen during transition from an old trustdb
	     before trust sigs.  It can also happen if a user uses two
	     different versions of GnuPG or changes the --trust-model
	     setting. */
	  if(k->ownertrust<min)
	    {
	      if(DBG_TRUST)
		log_debug("key %08lX%08lX:"
			  " overriding ownertrust '%s' with '%s'\n",
			  (ulong)k->kid[0],(ulong)k->kid[1],
			  trust_value_to_string(k->ownertrust),
			  trust_value_to_string(min));

	      k->ownertrust=min;
	    }

	  if (k->ownertrust == TRUST_UNKNOWN)
            ot_unknown++;
          else if (k->ownertrust == TRUST_UNDEFINED)
            ot_undefined++;
          else if (k->ownertrust == TRUST_NEVER)
            ot_never++;
          else if (k->ownertrust == TRUST_MARGINAL)
            ot_marginal++;
          else if (k->ownertrust == TRUST_FULLY)
            ot_full++;
          else if (k->ownertrust == TRUST_ULTIMATE)
            ot_ultimate++;

	  valids++;
        }

      /* Find all keys which are signed by a key in kdlist */
      keys = validate_key_list (ctrl, kdb, full_trust, klist,
				start_time, &next_expire);
      if (!keys)
        {
          log_error ("validate_key_list failed\n");
          rc = GPG_ERR_GENERAL;
          goto leave;
        }

      for (key_count=0, kar=keys; kar->keyblock; kar++, key_count++)
        ;

      /* Store the calculated valididation status somewhere */
      if (opt.verbose > 1 && DBG_TRUST)
        dump_key_array (depth, keys);

      for (kar=keys; kar->keyblock; kar++)
        store_validation_status (ctrl, depth, kar->keyblock, stored);

      if (!opt.quiet)
        log_info (_("depth: %d  valid: %3d  signed: %3d"
                    "  trust: %d-, %dq, %dn, %dm, %df, %du\n"),
                  depth, valids, key_count, ot_unknown, ot_undefined,
                  ot_never, ot_marginal, ot_full, ot_ultimate );

      /* Build a new kdlist from all fully valid keys in KEYS */
      if (klist != utk_list)
        release_key_items (klist);
      klist = NULL;
      for (kar=keys; kar->keyblock; kar++)
        {
          for (node=kar->keyblock; node; node = node->next)
            {
              if (node->pkt->pkttype == PKT_USER_ID && (node->flag & 4))
                {
		  u32 kid[2];

		  /* have we used this key already? */
                  keyid_from_pk (kar->keyblock->pkt->pkt.public_key, kid);
		  if(test_key_hash_table(used,kid)==0)
		    {
		      /* Normally we add both the primary and subkey
			 ids to the hash via mark_keyblock_seen, but
			 since we aren't using this hash as a skipfnc,
			 that doesn't matter here. */
		      add_key_hash_table (used,kid);
		      k = new_key_item ();
		      k->kid[0]=kid[0];
		      k->kid[1]=kid[1];
		      k->ownertrust =
			(tdb_get_ownertrust
                           (ctrl, kar->keyblock->pkt->pkt.public_key, 0)
                         & TRUST_MASK);
		      k->min_ownertrust = tdb_get_min_ownertrust
                        (ctrl, kar->keyblock->pkt->pkt.public_key, 0);
		      k->trust_depth=
			kar->keyblock->pkt->pkt.public_key->trust_depth;
		      k->trust_value=
			kar->keyblock->pkt->pkt.public_key->trust_value;
		      if(kar->keyblock->pkt->pkt.public_key->trust_regexp)
			k->trust_regexp=
			  xstrdup(kar->keyblock->pkt->
				   pkt.public_key->trust_regexp);
		      k->next = klist;
		      klist = k;
		      break;
		    }
		}
	    }
	}
      release_key_array (keys);
      keys = NULL;
      if (!klist)
        break; /* no need to dive in deeper */
    }

 leave:
  keydb_release (kdb);
  release_key_array (keys);
  if (klist != utk_list)
    release_key_items (klist);
  release_key_hash_table (full_trust);
  release_key_hash_table (used);
  release_key_hash_table (stored);
  if (!rc && !quit) /* mark trustDB as checked */
    {
      int rc2;

      if (next_expire == 0xffffffff || next_expire < start_time )
        tdbio_write_nextcheck (ctrl, 0);
      else
        {
          tdbio_write_nextcheck (ctrl, next_expire);
          if (!opt.quiet)
            log_info (_("next trustdb check due at %s\n"),
                      strtimestamp (next_expire));
        }

      rc2 = tdbio_update_version_record (ctrl);
      if (rc2)
	{
	  log_error (_("unable to update trustdb version record: "
                       "write failed: %s\n"), gpg_strerror (rc2));
	  tdbio_invalid ();
	}

      do_sync ();
      pending_check_trustdb = 0;
    }

  return rc;
}
