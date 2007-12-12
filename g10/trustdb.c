/* trustdb.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef DISABLE_REGEX
#include <sys/types.h>
#ifdef USE_INTERNAL_REGEX
#include "_regex.h"
#else
#include <regex.h>
#endif
#endif /* !DISABLE_REGEX */

#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "i18n.h"
#include "tdbio.h"
#include "trustdb.h"


/*
 * A structure to store key identification as well as some stuff needed
 * for validation 
 */
struct key_item {
  struct key_item *next;
  unsigned int ownertrust,min_ownertrust;
  byte trust_depth;
  byte trust_value;
  char *trust_regexp;
  u32 kid[2];
};


typedef struct key_item **KeyHashTable; /* see new_key_hash_table() */

/*
 * Structure to keep track of keys, this is used as an array wherre
 * the item right after the last one has a keyblock set to NULL. 
 * Maybe we can drop this thing and replace it by key_item
 */
struct key_array {
  KBNODE keyblock;
};


/* control information for the trust DB */
static struct {
    int init;
    int level;
    char *dbname;
} trustdb_args;

/* some globals */
static struct key_item *user_utk_list; /* temp. used to store --trusted-keys */
static struct key_item *utk_list;      /* all ultimately trusted keys */

static int pending_check_trustdb;

static int validate_keys (int interactive);


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

/*
 * For fast keylook up we need a hash table.  Each byte of a KeyIDs
 * should be distributed equally over the 256 possible values (except
 * for v3 keyIDs but we consider them as not important here). So we
 * can just use 10 bits to index a table of 1024 key items. 
 * Possible optimization: Don not use key_items but other hash_table when the
 * duplicates lists gets too large. 
 */
static KeyHashTable 
new_key_hash_table (void)
{
  struct key_item **tbl;

  tbl = xmalloc_clear (1024 * sizeof *tbl);
  return tbl;
}

static void
release_key_hash_table (KeyHashTable tbl)
{
  int i;

  if (!tbl)
    return;
  for (i=0; i < 1024; i++)
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

  for (k = tbl[(kid[1] & 0x03ff)]; k; k = k->next)
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
  struct key_item *k, *kk;

  for (k = tbl[(kid[1] & 0x03ff)]; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      return; /* already in table */
  
  kk = new_key_item ();
  kk->kid[0] = kid[0];
  kk->kid[1] = kid[1];
  kk->next = tbl[(kid[1] & 0x03ff)];
  tbl[(kid[1] & 0x03ff)] = kk;
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
register_trusted_keyid(u32 *keyid)
{
  struct key_item *k;

  k = new_key_item ();
  k->kid[0] = keyid[0];
  k->kid[1] = keyid[1];
  k->next = user_utk_list;
  user_utk_list = k;
}

void
register_trusted_key( const char *string )
{
  KEYDB_SEARCH_DESC desc;

  if (classify_user_id (string, &desc) != KEYDB_SEARCH_MODE_LONG_KID )
    {
      log_error(_("`%s' is not a valid long keyID\n"), string );
      return;
    }

  register_trusted_keyid(desc.u.kid);
}

/*
 * Helper to add a key to the global list of ultimately trusted keys.
 * Retruns: true = inserted, false = already in in list.
 */
static int
add_utk (u32 *kid)
{
  struct key_item *k;

  for (k = utk_list; k; k = k->next) 
    {
      if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
        {
          return 0;
        }
    }

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
verify_own_keys(void)
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
            keyid_from_fingerprint (fpr, fprlen, kid);
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
          rc = get_pubkey (&pk, k->kid);
          if (rc)
	    log_info(_("key %s: no public key for trusted key - skipped\n"),
		     keystr(k->kid));
          else
	    {
	      update_ownertrust (&pk,
				 ((get_ownertrust (&pk) & ~TRUST_MASK)
				  | TRUST_ULTIMATE ));
	      release_public_key_parts (&pk);
	    }

          log_info (_("key %s marked as ultimately trusted\n"),keystr(k->kid));
        }
    }

  /* release the helper table table */
  release_key_items (user_utk_list);
  user_utk_list = NULL;
  return;
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
                recno, rec->rectype, g10_errstr(rc) );
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
write_record (TRUSTREC *rec)
{
  int rc = tdbio_write_record (rec);
  if (rc)
    {
      log_error(_("trust record %lu, type %d: write failed: %s\n"),
			    rec->recnum, rec->rectype, g10_errstr(rc) );
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
        log_error (_("trustdb: sync failed: %s\n"), g10_errstr(rc) );
        g10_exit(2);
      }
}

static const char *
trust_model_string(void)
{
  switch(opt.trust_model)
    {
    case TM_CLASSIC:  return "classic";
    case TM_PGP:      return "PGP";
    case TM_EXTERNAL: return "external";
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
init_trustdb()
{
  int level = trustdb_args.level;
  const char* dbname = trustdb_args.dbname;

  if( trustdb_args.init )
    return;

  trustdb_args.init = 1;

  if(level==0 || level==1)
    {
      int rc = tdbio_set_dbname( dbname, !!level );
      if( rc )
	log_fatal("can't init trustdb: %s\n", g10_errstr(rc) );
    }
  else
    BUG();

  if(opt.trust_model==TM_AUTO)
    {
      /* Try and set the trust model off of whatever the trustdb says
	 it is. */
      opt.trust_model=tdbio_read_model();

      /* Sanity check this ;) */
      if(opt.trust_model!=TM_CLASSIC
	 && opt.trust_model!=TM_PGP
	 && opt.trust_model!=TM_EXTERNAL)
	{
	  log_info(_("unable to use unknown trust model (%d) - "
		     "assuming %s trust model\n"),opt.trust_model,"PGP");
	  opt.trust_model=TM_PGP;
	}

      if(opt.verbose)
	log_info(_("using %s trust model\n"),trust_model_string());
    }

  if(opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC)
    {
      /* Verify the list of ultimately trusted keys and move the
	 --trusted-keys list there as well. */
      if(level==1)
	verify_own_keys();

      if(!tdbio_db_matches_options())
	pending_check_trustdb=1;
    }
}


/***********************************************
 *************	Print helpers	****************
 ***********************************************/

/****************
 * This function returns a letter for a trustvalue  Trust flags
 * are ignore.
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

/* NOTE TO TRANSLATOR: these strings are similar to those in
   trust_value_to_string(), but are a fixed length.  This is needed to
   make attractive information listings where columns line up
   properly.  The value "10" should be the length of the strings you
   choose to translate to.  This is the length in printable columns.
   It gets passed to atoi() so everything after the number is
   essentially a comment and need not be translated.  Either key and
   uid are both NULL, or neither are NULL. */
const char *
uid_trust_string_fixed(PKT_public_key *key,PKT_user_id *uid)
{
  if(!key && !uid)
    return _("10 translator see trustdb.c:uid_trust_string_fixed");
  else if(uid->is_revoked || (key && key->is_revoked))
    return                         _("[ revoked]");
  else if(uid->is_expired)
    return                         _("[ expired]");
  else if(key)
    switch(get_validity(key,uid)&TRUST_MASK)
      {
      case TRUST_UNKNOWN:   return _("[ unknown]");
      case TRUST_EXPIRED:   return _("[ expired]");
      case TRUST_UNDEFINED: return _("[  undef ]");
      case TRUST_MARGINAL:  return _("[marginal]");
      case TRUST_FULLY:     return _("[  full  ]");
      case TRUST_ULTIMATE:  return _("[ultimate]");
      }

  return "err";
}

/* The strings here are similar to those in
   pkclist.c:do_edit_ownertrust() */
const char *
trust_value_to_string (unsigned int value)
{
  switch( (value & TRUST_MASK) ) 
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
  if(ascii_strcasecmp(str,"undefined")==0)
    return TRUST_UNDEFINED;
  else if(ascii_strcasecmp(str,"never")==0)
    return TRUST_NEVER;
  else if(ascii_strcasecmp(str,"marginal")==0)
    return TRUST_MARGINAL;
  else if(ascii_strcasecmp(str,"full")==0)
    return TRUST_FULLY;
  else if(ascii_strcasecmp(str,"ultimate")==0)
    return TRUST_ULTIMATE;
  else
    return -1;
}

/****************
 * Recreate the WoT but do not ask for new ownertrusts.  Special
 * feature: In batch mode and without a forced yes, this is only done
 * when a check is due.  This can be used to run the check from a crontab
 */
void
check_trustdb ()
{
  init_trustdb();
  if(opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC)
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

      validate_keys (0);
    }
  else
    log_info (_("no need for a trustdb check with `%s' trust model\n"),
	      trust_model_string());
}


/*
 * Recreate the WoT. 
 */
void
update_trustdb()
{
  init_trustdb();
  if(opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC)
    validate_keys (1);
  else
    log_info (_("no need for a trustdb update with `%s' trust model\n"),
	      trust_model_string());
}

void
revalidation_mark (void)
{
  init_trustdb();
  /* we simply set the time for the next check to 1 (far back in 1970)
   * so that a --update-trustdb will be scheduled */
  if (tdbio_write_nextcheck (1))
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
trustdb_check_or_update(void)
{
  if(trustdb_pending_check())
    {
      if(opt.interactive)
	update_trustdb();
      else if(!opt.no_auto_check_trustdb)
	check_trustdb();
    }
}

void
read_trust_options(byte *trust_model,ulong *created,ulong *nextcheck,
		   byte *marginals,byte *completes,byte *cert_depth)
{
  TRUSTREC opts;

  init_trustdb();

  read_record(0,&opts,RECTYPE_VER);

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
}

/***********************************************
 ***********  Ownertrust et al. ****************
 ***********************************************/

static int 
read_trust_record (PKT_public_key *pk, TRUSTREC *rec)
{
  int rc;
  
  init_trustdb();
  rc = tdbio_search_trust_bypk (pk, rec);
  if (rc == -1)
    return -1; /* no record yet */
  if (rc) 
    {
      log_error ("trustdb: searching trust record failed: %s\n",
                 g10_errstr (rc));
      return rc; 
    }
      
  if (rec->rectype != RECTYPE_TRUST)
    {
      log_error ("trustdb: record %lu is not a trust record\n",
                 rec->recnum);
      return G10ERR_TRUSTDB; 
    }      
  
  return 0;
}

/****************
 * Return the assigned ownertrust value for the given public key.
 * The key should be the primary key.
 */
unsigned int 
get_ownertrust ( PKT_public_key *pk)
{
  TRUSTREC rec;
  int rc;
  
  rc = read_trust_record (pk, &rec);
  if (rc == -1)
    return TRUST_UNKNOWN; /* no record yet */
  if (rc) 
    {
      tdbio_invalid ();
      return rc; /* actually never reached */
    }

  return rec.r.trust.ownertrust;
}

unsigned int 
get_min_ownertrust (PKT_public_key *pk)
{
  TRUSTREC rec;
  int rc;
  
  rc = read_trust_record (pk, &rec);
  if (rc == -1)
    return TRUST_UNKNOWN; /* no record yet */
  if (rc) 
    {
      tdbio_invalid ();
      return rc; /* actually never reached */
    }

  return rec.r.trust.min_ownertrust;
}

/*
 * Same as get_ownertrust but this takes the minimum ownertrust value
 * into into account, and will bump up the value as needed.
 */
static int
get_ownertrust_with_min (PKT_public_key *pk)
{
  unsigned int otrust,otrust_min;

  otrust = (get_ownertrust (pk) & TRUST_MASK);
  otrust_min = get_min_ownertrust (pk);
  if(otrust<otrust_min)
    {
      /* If the trust that the user has set is less than the trust
	 that was calculated from a trust signature chain, use the
	 higher of the two.  We do this here and not in
	 get_ownertrust since the underlying ownertrust should not
	 really be set - just the appearance of the ownertrust. */

      otrust=otrust_min;
    }

  return otrust;
}

/*
 * Same as get_ownertrust but return a trust letter instead of an
 * value.  This takes the minimum ownertrust value into account.
 */
int
get_ownertrust_info (PKT_public_key *pk)
{
  return trust_letter(get_ownertrust_with_min(pk));
}

/*
 * Same as get_ownertrust but return a trust string instead of an
 * value.  This takes the minimum ownertrust value into account.
 */
const char *
get_ownertrust_string (PKT_public_key *pk)
{
  return trust_value_to_string(get_ownertrust_with_min(pk));
}

/*
 * Set the trust value of the given public key to the new value.
 * The key should be a primary one.
 */
void
update_ownertrust (PKT_public_key *pk, unsigned int new_trust )
{
  TRUSTREC rec;
  int rc;
  
  rc = read_trust_record (pk, &rec);
  if (!rc)
    {
      if (DBG_TRUST)
        log_debug ("update ownertrust from %u to %u\n",
                   (unsigned int)rec.r.trust.ownertrust, new_trust );
      if (rec.r.trust.ownertrust != new_trust)
        {
          rec.r.trust.ownertrust = new_trust;
          write_record( &rec );
          revalidation_mark ();
          do_sync ();
        }
    }
  else if (rc == -1)
    { /* no record yet - create a new one */
      size_t dummy;

      if (DBG_TRUST)
        log_debug ("insert ownertrust %u\n", new_trust );

      memset (&rec, 0, sizeof rec);
      rec.recnum = tdbio_new_recnum ();
      rec.rectype = RECTYPE_TRUST;
      fingerprint_from_pk (pk, rec.r.trust.fingerprint, &dummy);
      rec.r.trust.ownertrust = new_trust;
      write_record (&rec);
      revalidation_mark ();
      do_sync ();
      rc = 0;
    }
  else 
    {
      tdbio_invalid ();
    }
}

static void
update_min_ownertrust (u32 *kid, unsigned int new_trust )
{
  PKT_public_key *pk;
  TRUSTREC rec;
  int rc;

  pk = xmalloc_clear (sizeof *pk);
  rc = get_pubkey (pk, kid);
  if (rc)
    {
      log_error(_("public key %s not found: %s\n"),keystr(kid),g10_errstr(rc));
      return;
    }

  rc = read_trust_record (pk, &rec);
  if (!rc)
    {
      if (DBG_TRUST)
        log_debug ("key %08lX%08lX: update min_ownertrust from %u to %u\n",
                   (ulong)kid[0],(ulong)kid[1],
		   (unsigned int)rec.r.trust.min_ownertrust,
		   new_trust );
      if (rec.r.trust.min_ownertrust != new_trust)
        {
          rec.r.trust.min_ownertrust = new_trust;
          write_record( &rec );
          revalidation_mark ();
          do_sync ();
        }
    }
  else if (rc == -1)
    { /* no record yet - create a new one */
      size_t dummy;

      if (DBG_TRUST)
        log_debug ("insert min_ownertrust %u\n", new_trust );

      memset (&rec, 0, sizeof rec);
      rec.recnum = tdbio_new_recnum ();
      rec.rectype = RECTYPE_TRUST;
      fingerprint_from_pk (pk, rec.r.trust.fingerprint, &dummy);
      rec.r.trust.min_ownertrust = new_trust;
      write_record (&rec);
      revalidation_mark ();
      do_sync ();
      rc = 0;
    }
  else 
    {
      tdbio_invalid ();
    }
}

/* Clear the ownertrust and min_ownertrust values.  Return true if a
   change actually happened. */
int
clear_ownertrusts (PKT_public_key *pk)
{
  TRUSTREC rec;
  int rc;
  
  rc = read_trust_record (pk, &rec);
  if (!rc)
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
          write_record( &rec );
          revalidation_mark ();
          do_sync ();
          return 1;
        }
    }
  else if (rc != -1)
    {
      tdbio_invalid ();
    }
  return 0;
}

/* 
 * Note: Caller has to do a sync 
 */
static void
update_validity (PKT_public_key *pk, PKT_user_id *uid,
                 int depth, int validity)
{
  TRUSTREC trec, vrec;
  int rc;
  ulong recno;

  namehash_from_uid(uid);

  rc = read_trust_record (pk, &trec);
  if (rc && rc != -1)
    {
      tdbio_invalid ();
      return;
    }
  if (rc == -1) /* no record yet - create a new one */
    { 
      size_t dummy;

      rc = 0;
      memset (&trec, 0, sizeof trec);
      trec.recnum = tdbio_new_recnum ();
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
      vrec.recnum = tdbio_new_recnum ();
      vrec.rectype = RECTYPE_VALID;
      memcpy (vrec.r.valid.namehash, uid->namehash, 20);
      vrec.r.valid.next = trec.r.trust.validlist;
      trec.r.trust.validlist = vrec.recnum;
    }
  vrec.r.valid.validity = validity;
  vrec.r.valid.full_count = uid->help_full_count;
  vrec.r.valid.marginal_count = uid->help_marginal_count;
  write_record (&vrec);
  trec.r.trust.depth = depth;
  write_record (&trec);
}


/***********************************************
 *********  Query trustdb values  **************
 ***********************************************/

/* Return true if key is disabled */
int
cache_disabled_value(PKT_public_key *pk)
{
  int rc;
  TRUSTREC trec;
  int disabled=0;

  if(pk->is_disabled)
    return (pk->is_disabled==2);

  init_trustdb();

  rc = read_trust_record (pk, &trec);
  if (rc && rc != -1)
    {
      tdbio_invalid ();
      goto leave;
    }
  if (rc == -1) /* no record found, so assume not disabled */
    goto leave;
 
  if(trec.r.trust.ownertrust & TRUST_FLAG_DISABLED)
    disabled=1;
 
  /* Cache it for later so we don't need to look at the trustdb every
     time */
  if(disabled)
    pk->is_disabled=2;
  else
    pk->is_disabled=1;

 leave:
   return disabled;
}

void
check_trustdb_stale(void)
{
  static int did_nextcheck=0;

  init_trustdb ();
  if (!did_nextcheck
      && (opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC))
    {
      ulong scheduled;

      did_nextcheck = 1;
      scheduled = tdbio_read_nextcheck ();
      if (scheduled && scheduled <= make_timestamp ())
        {
          if (opt.no_auto_check_trustdb) 
            {
              pending_check_trustdb = 1;
              log_info (_("please do a --check-trustdb\n"));
            }
          else
            {
              log_info (_("checking the trustdb\n"));
              validate_keys (0);
            }
        }
    }
}

/*
 * Return the validity information for PK.  If the namehash is not
 * NULL, the validity of the corresponsing user ID is returned,
 * otherwise, a reasonable value for the entire key is returned. 
 */
unsigned int
get_validity (PKT_public_key *pk, PKT_user_id *uid)
{
  TRUSTREC trec, vrec;
  int rc;
  ulong recno;
  unsigned int validity;
  u32 kid[2];
  PKT_public_key *main_pk;

  if(uid)
    namehash_from_uid(uid);

  init_trustdb ();
  check_trustdb_stale();

  keyid_from_pk (pk, kid);
  if (pk->main_keyid[0] != kid[0] || pk->main_keyid[1] != kid[1])
    { /* this is a subkey - get the mainkey */
      main_pk = xmalloc_clear (sizeof *main_pk);
      rc = get_pubkey (main_pk, pk->main_keyid);
      if (rc)
        {
	  char *tempkeystr=xstrdup(keystr(pk->main_keyid));
          log_error ("error getting main key %s of subkey %s: %s\n",
                     tempkeystr, keystr(kid), g10_errstr(rc));
	  xfree(tempkeystr);
          validity = TRUST_UNKNOWN; 
          goto leave;
	}
    }
  else
    main_pk = pk;

  if(opt.trust_model==TM_DIRECT)
    {
      /* Note that this happens BEFORE any user ID stuff is checked.
	 The direct trust model applies to keys as a whole. */
      validity=get_ownertrust(main_pk);
      goto leave;
    }

  rc = read_trust_record (main_pk, &trec);
  if (rc && rc != -1)
    {
      tdbio_invalid ();
      return 0;
    }
  if (rc == -1) /* no record found */
    {
      validity = TRUST_UNKNOWN; 
      goto leave;
    }

  /* loop over all user IDs */
  recno = trec.r.trust.validlist;
  validity = 0;
  while (recno)
    {
      read_record (recno, &vrec, RECTYPE_VALID);

      if(uid)
	{
	  /* If a user ID is given we return the validity for that
	     user ID ONLY.  If the namehash is not found, then there
	     is no validity at all (i.e. the user ID wasn't
	     signed). */
	  if(memcmp(vrec.r.valid.namehash,uid->namehash,20)==0)
	    {
	      validity=(vrec.r.valid.validity & TRUST_MASK);
	      break;
	    }
	}
      else
	{
	  /* If no namehash is given, we take the maximum validity
	     over all user IDs */
	  if ( validity < (vrec.r.valid.validity & TRUST_MASK) )
	    validity = (vrec.r.valid.validity & TRUST_MASK);
	}

      recno = vrec.r.valid.next;
    }
  
  if ( (trec.r.trust.ownertrust & TRUST_FLAG_DISABLED) )
    {
      validity |= TRUST_FLAG_DISABLED;
      pk->is_disabled=2;
    }
  else
    pk->is_disabled=1;

 leave:
  /* set some flags direct from the key */
  if (main_pk->is_revoked)
    validity |= TRUST_FLAG_REVOKED;
  if (main_pk != pk && pk->is_revoked)
    validity |= TRUST_FLAG_SUB_REVOKED;
  /* Note: expiration is a trust value and not a flag - don't know why
   * I initially designed it that way */
  if (main_pk->has_expired || pk->has_expired)
    validity = (validity & ~TRUST_MASK) | TRUST_EXPIRED;
  
  if (pending_check_trustdb)
    validity |= TRUST_FLAG_PENDING_CHECK;

  if (main_pk != pk)
    free_public_key (main_pk);
  return validity;
}

int
get_validity_info (PKT_public_key *pk, PKT_user_id *uid)
{
    int trustlevel;

    trustlevel = get_validity (pk, uid);
    if( trustlevel & TRUST_FLAG_REVOKED )
	return 'r';
    return trust_letter ( trustlevel );
}

const char *
get_validity_string (PKT_public_key *pk, PKT_user_id *uid)
{
  int trustlevel;

  trustlevel = get_validity (pk, uid);
  if( trustlevel & TRUST_FLAG_REVOKED )
    return _("revoked");
  return trust_value_to_string(trustlevel);
}

static void
get_validity_counts (PKT_public_key *pk, PKT_user_id *uid)
{
  TRUSTREC trec, vrec;
  ulong recno;

  if(pk==NULL || uid==NULL)
    BUG();

  namehash_from_uid(uid);

  uid->help_marginal_count=uid->help_full_count=0;

  init_trustdb ();

  if(read_trust_record (pk, &trec)!=0)
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
	  /*  printf("Fetched marginal %d, full %d\n",uid->help_marginal_count,uid->help_full_count); */
	  break;
	}

      recno = vrec.r.valid.next;
    }
}

void
list_trust_path( const char *username )
{
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
    return -1;
}


/****************
 * Print the current path
 */
void
enum_cert_paths_print( void **context, FILE *fp,
				       int refresh, ulong selected_lid )
{
    return;
}



/****************************************
 *********** NEW NEW NEW ****************
 ****************************************/

static int
ask_ownertrust (u32 *kid,int minimum)
{
  PKT_public_key *pk;
  int rc;
  int ot;

  pk = xmalloc_clear (sizeof *pk);
  rc = get_pubkey (pk, kid);
  if (rc)
    {
      log_error (_("public key %s not found: %s\n"),
                 keystr(kid), g10_errstr(rc) );
      return TRUST_UNKNOWN;
    }
 
  if(opt.force_ownertrust)
    {
      log_info("force trust for key %s to %s\n",
	       keystr(kid),trust_value_to_string(opt.force_ownertrust));
      update_ownertrust(pk,opt.force_ownertrust);
      ot=opt.force_ownertrust;
    }
  else
    {
      ot=edit_ownertrust(pk,0);
      if(ot>0)
	ot = get_ownertrust (pk);
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
      printf ("%d:%08lX%08lX:K::%c::::\n",
              depth, (ulong)kid[0], (ulong)kid[1], '?');

      for (; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_USER_ID)
            {
              int len = node->pkt->pkt.user_id->len;

              if (len > 30)
                len = 30;
              printf ("%d:%08lX%08lX:U:::%c:::",
                      depth, (ulong)kid[0], (ulong)kid[1],
                      (node->flag & 4)? 'f':
                      (node->flag & 2)? 'm':
                      (node->flag & 1)? 'q':'-');
              print_string (stdout,  node->pkt->pkt.user_id->name, len, ':');
              putchar (':');
              putchar ('\n');
            }
        }
    }
}  


static void
store_validation_status (int depth, KBNODE keyblock, KeyHashTable stored)
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
              update_validity (keyblock->pkt->pkt.public_key,
			       uid, depth, status);

	      mark_keyblock_seen(stored,keyblock);

              any = 1;
            }
        }
    }

  if (any)
    do_sync ();
}  

/*
 * check whether the signature sig is in the klist k
 */
static struct key_item *
is_in_klist (struct key_item *k, PKT_signature *sig)
{
  for (; k; k = k->next)
    {
      if (k->kid[0] == sig->keyid[0] && k->kid[1] == sig->keyid[1])
        return k;
    }
  return NULL;
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
static void
mark_usable_uid_certs (KBNODE keyblock, KBNODE uidnode,
                       u32 *main_kid, struct key_item *klist,
                       u32 curtime, u32 *next_expire)
{
  KBNODE node;
  PKT_signature *sig;
  
  /* first check all signatures */
  for (node=uidnode->next; node; node = node->next)
    {
      int rc;

      node->flag &= ~(1<<8 | 1<<9 | 1<<10 | 1<<11 | 1<<12);
      if (node->pkt->pkttype == PKT_USER_ID
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
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
      if ((rc=check_key_signature (keyblock, node, NULL)))
	{
	  /* we ignore anything that won't verify, but tag the
	     no_pubkey case */
	  if(rc==G10ERR_NO_PUBKEY)
	    node->flag |= 1<<12;
	  continue;
	}
      node->flag |= 1<<9;
    }      
  /* reset the remaining flags */
  for (; node; node = node->next)
      node->flag &= ~(1<<8 | 1<<9 | 1<<10 | 1<<11 | 1<<12);

  /* kbnode flag usage: bit 9 is here set for signatures to consider,
   * bit 10 will be set by the loop to keep track of keyIDs already
   * processed, bit 8 will be set for the usable signatures, and bit
   * 11 will be set for usable revocations. */

  /* for each cert figure out the latest valid one */
  for (node=uidnode->next; node; node = node->next)
    {
      KBNODE n, signode;
      u32 kid[2];
      u32 sigdate;

      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
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
          if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
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
          expire = p? sig->timestamp + buffer_to_u32(p) : 0;

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
clean_sigs_from_uid(KBNODE keyblock,KBNODE uidnode,int noisy,int self_only)
{
  int deleted=0;
  KBNODE node;
  u32 keyid[2];

  assert(keyblock->pkt->pkttype==PKT_PUBLIC_KEY);

  keyid_from_pk(keyblock->pkt->pkt.public_key,keyid);

  /* Passing in a 0 for current time here means that we'll never weed
     out an expired sig.  This is correct behavior since we want to
     keep the most recent expired sig in a series. */
  mark_usable_uid_certs(keyblock,uidnode,NULL,NULL,0,NULL);

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

  for(node=uidnode->next;
      node && node->pkt->pkttype==PKT_SIGNATURE;
      node=node->next)
    {
      int keep=self_only?(node->pkt->pkt.signature->keyid[0]==keyid[0]
			  && node->pkt->pkt.signature->keyid[1]==keyid[1]):1;

      /* Keep usable uid sigs ... */
      if((node->flag & (1<<8)) && keep)
	continue;

      /* ... and usable revocations... */
      if((node->flag & (1<<11)) && keep)
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
	 If 9 or 10 is set, it's superceded.  Otherwise, it's
	 invalid. */

      if(noisy)
	log_info("removing signature from key %s on user ID \"%s\": %s\n",
		 keystr(node->pkt->pkt.signature->keyid),
		 uidnode->pkt->pkt.user_id->name,
		 node->flag&(1<<12)?"key unavailable":
		 node->flag&(1<<9)?"signature superceded":"invalid signature");

      delete_kbnode(node);
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
   be ressurected in a later merge.  Note that this function requires
   that the caller has already done a merge_keys_and_selfsig().

   TODO: change the import code to allow importing a uid with only a
   revocation if the uid already exists on the keyring. */

static int
clean_uid_from_key(KBNODE keyblock,KBNODE uidnode,int noisy)
{
  KBNODE node;
  PKT_user_id *uid=uidnode->pkt->pkt.user_id;
  int deleted=0;

  assert(keyblock->pkt->pkttype==PKT_PUBLIC_KEY);
  assert(uidnode->pkt->pkttype==PKT_USER_ID);

  /* Skip valid user IDs, compacted user IDs, and non-self-signed user
     IDs if --allow-non-selfsigned-uid is set. */
  if(uid->created || uid->flags.compacted
     || (!uid->is_expired && !uid->is_revoked
	 && opt.allow_non_selfsigned_uid))
    return 0;

  for(node=uidnode->next;
      node && node->pkt->pkttype==PKT_SIGNATURE;
      node=node->next)
    if(!node->pkt->pkt.signature->flags.chosen_selfsig)
      {
	delete_kbnode(node);
	deleted=1;
	uidnode->pkt->pkt.user_id->flags.compacted=1;
      }

  if(noisy)
    {
      const char *reason;
      char *user=utf8_to_native(uid->name,uid->len,0);

      if(uid->is_revoked)
	reason=_("revoked");
      else if(uid->is_expired)
	reason=_("expired");
      else
	reason=_("invalid");

      log_info("compacting user ID \"%s\" on key %s: %s\n",
	       user,keystr_from_pk(keyblock->pkt->pkt.public_key),
	       reason);

      xfree(user);
    }

  return deleted;
}

/* Needs to be called after a merge_keys_and_selfsig() */
void
clean_one_uid(KBNODE keyblock,KBNODE uidnode,int noisy,int self_only,
	      int *uids_cleaned,int *sigs_cleaned)
{
  int dummy;

  assert(keyblock->pkt->pkttype==PKT_PUBLIC_KEY);
  assert(uidnode->pkt->pkttype==PKT_USER_ID);

  if(!uids_cleaned)
    uids_cleaned=&dummy;

  if(!sigs_cleaned)
    sigs_cleaned=&dummy;

  /* Do clean_uid_from_key first since if it fires off, we don't
     have to bother with the other */
  *uids_cleaned+=clean_uid_from_key(keyblock,uidnode,noisy);
  if(!uidnode->pkt->pkt.user_id->flags.compacted)
    *sigs_cleaned+=clean_sigs_from_uid(keyblock,uidnode,noisy,self_only);
}

void
clean_key(KBNODE keyblock,int noisy,int self_only,
	  int *uids_cleaned,int *sigs_cleaned)
{
  KBNODE uidnode;

  merge_keys_and_selfsig(keyblock);

  for(uidnode=keyblock->next;
      uidnode && uidnode->pkt->pkttype!=PKT_PUBLIC_SUBKEY;
      uidnode=uidnode->next)
    if(uidnode->pkt->pkttype==PKT_USER_ID)
      clean_one_uid(keyblock,uidnode,noisy,self_only,
		    uids_cleaned,sigs_cleaned);
}

/* Returns a sanitized copy of the regexp (which might be "", but not
   NULL). */
static char *
sanitize_regexp(const char *old)
{
  size_t start=0,len=strlen(old),idx=0;
  int escaped=0,standard_bracket=0;
  char *new=xmalloc((len*2)+1); /* enough to \-escape everything if we
				   have to */

  /* There are basically two commonly-used regexps here.  GPG and most
     versions of PGP use "<[^>]+[@.]example\.com>$" and PGP (9)
     command line uses "example.com" (i.e. whatever the user specfies,
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
      else if(!escaped && old[start]!='.')
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
#ifdef DISABLE_REGEX
  /* When DISABLE_REGEX is defined, assume all regexps do not
     match. */
  return 0;
#else
  int ret;
  char *regexp;

  regexp=sanitize_regexp(expr);

#ifdef __riscos__
  ret=riscos_check_regexp(expr, string, DBG_TRUST);
#else
  {
    regex_t pat;

    ret=regcomp(&pat,regexp,REG_ICASE|REG_NOSUB|REG_EXTENDED);
    if(ret==0)
      {
	ret=regexec(&pat,string,0,NULL,0);
	regfree(&pat);
	ret=(ret==0);
      }
  }
#endif

  if(DBG_TRUST)
    log_debug("regexp `%s' (`%s') on `%s': %s\n",
	      regexp,expr,string,ret==0?"YES":"NO");

  xfree(regexp);

  return ret;
#endif
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
validate_one_keyblock (KBNODE kb, struct key_item *klist,
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
	  && !node->pkt->pkt.user_id->is_revoked
	  && !node->pkt->pkt.user_id->is_expired)
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
	  get_validity_counts(pk,uid);
          mark_usable_uid_certs (kb, uidnode, main_kid, klist, 
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
          if (kr && (kr->trust_regexp==NULL || opt.trust_model!=TM_PGP ||
		     (uidnode && check_regexp(kr->trust_regexp,
					    uidnode->pkt->pkt.user_id->name))))
            {
	      if(DBG_TRUST && opt.trust_model==TM_PGP && sig->trust_depth)
		log_debug("trust sig on %s, sig depth is %d, kr depth is %d\n",
			  uidnode->pkt->pkt.user_id->name,sig->trust_depth,
			  kr->trust_depth);

	      /* Are we part of a trust sig chain?  We always favor
                 the latest trust sig, rather than the greater or
                 lesser trust sig or value.  I could make a decent
                 argument for any of these cases, but this seems to be
                 what PGP does, and I'd like to be compatible. -dms */
	      if(opt.trust_model==TM_PGP && sig->trust_depth
		 && pk->trust_timestamp<=sig->timestamp
		 && (sig->trust_depth<=kr->trust_depth
		     || kr->ownertrust==TRUST_ULTIMATE))
		{
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

		  if(DBG_TRUST)
		    log_debug("replacing trust value %d with %d and "
			      "depth %d with %d\n",
			      pk->trust_value,sig->trust_value,
			      pk->trust_depth,sig->trust_depth);

		  pk->trust_value=sig->trust_value;
		  pk->trust_depth=sig->trust_depth-1;

		  /* If the trust sig contains a regexp, record it
		     on the pk for the next round. */
		  if(sig->trust_regexp)
		    pk->trust_regexp=sig->trust_regexp;
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
search_skipfnc (void *opaque, u32 *kid, PKT_user_id *dummy)
{
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
validate_key_list (KEYDB_HANDLE hd, KeyHashTable full_trust,
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
      log_error ("keydb_search_reset failed: %s\n", g10_errstr(rc));
      xfree (keys);
      return NULL;
    }

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  desc.skipfnc = search_skipfnc;
  desc.skipfncvalue = full_trust;
  rc = keydb_search (hd, &desc, 1);
  if (rc == -1)
    {
      keys[nkeys].keyblock = NULL;
      return keys;
    }
  if (rc)
    {
      log_error ("keydb_search_first failed: %s\n", g10_errstr(rc));
      xfree (keys);
      return NULL;
    }
  
  desc.mode = KEYDB_SEARCH_MODE_NEXT; /* change mode */
  do
    {
      PKT_public_key *pk;
        
      rc = keydb_get_keyblock (hd, &keyblock);
      if (rc) 
        {
          log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
          xfree (keys);
          return NULL;
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
      merge_keys_and_selfsig (keyblock); 
      clear_kbnode_flags (keyblock);
      pk = keyblock->pkt->pkt.public_key;
      if (pk->has_expired || pk->is_revoked)
        {
          /* it does not make sense to look further at those keys */
          mark_keyblock_seen (full_trust, keyblock);
        }
      else if (validate_one_keyblock (keyblock, klist, curtime, next_expire))
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
  while ( !(rc = keydb_search (hd, &desc, 1)) );
  if (rc && rc != -1) 
    {
      log_error ("keydb_search_next failed: %s\n", g10_errstr(rc));
      xfree (keys);
      return NULL;
    }

  keys[nkeys].keyblock = NULL;
  return keys;
} 

/* Caller must sync */
static void
reset_trust_records(void)
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
	      write_record(&rec);
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
	  write_record(&rec);
	}

    }

  if (opt.verbose)
    log_info (_("%d keys processed (%d validity counts cleared)\n"),
	      count, nreset);
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
validate_keys (int interactive)
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
     require some architectual re-thinking, as it is agonizingly slow.
     Perhaps combine this with reset_trust_records(), or only check
     the caches on keys that are actually involved in the web of
     trust. */
  keydb_rebuild_caches(0);

  start_time = make_timestamp ();
  next_expire = 0xffffffff; /* set next expire to the year 2106 */
  stored = new_key_hash_table ();
  used = new_key_hash_table ();
  full_trust = new_key_hash_table ();

  kdb = keydb_new (0);
  reset_trust_records();

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

      keyblock = get_pubkeyblock (k->kid);
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
	    update_validity (pk, node->pkt->pkt.user_id, 0, TRUST_ULTIMATE);
        }
      if ( pk->expiredate && pk->expiredate >= start_time
           && pk->expiredate < next_expire)
        next_expire = pk->expiredate;
      
      release_kbnode (keyblock);
      do_sync ();
    }

  klist = utk_list;

  log_info(_("%d marginal(s) needed, %d complete(s) needed, %s trust model\n"),
	   opt.marginals_needed,opt.completes_needed,trust_model_string());

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
	    update_min_ownertrust(k->kid,min);

          if (interactive && k->ownertrust == TRUST_UNKNOWN)
	    {
	      k->ownertrust = ask_ownertrust (k->kid,min);

	      if (k->ownertrust == -1)
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
			  " overriding ownertrust `%s' with `%s'\n",
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
      keys = validate_key_list (kdb, full_trust, klist,
				start_time, &next_expire);
      if (!keys) 
        {
          log_error ("validate_key_list failed\n");
          rc = G10ERR_GENERAL;
          goto leave;
        }

      for (key_count=0, kar=keys; kar->keyblock; kar++, key_count++)
        ;

      /* Store the calculated valididation status somewhere */
      if (opt.verbose > 1)
        dump_key_array (depth, keys);

      for (kar=keys; kar->keyblock; kar++)
          store_validation_status (depth, kar->keyblock, stored);

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
			(get_ownertrust (kar->keyblock->pkt->pkt.public_key)
			 & TRUST_MASK);
		      k->min_ownertrust =
			get_min_ownertrust(kar->keyblock->pkt->pkt.public_key);
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
  release_key_items (klist);
  release_key_hash_table (full_trust);
  release_key_hash_table (used);
  release_key_hash_table (stored);
  if (!rc && !quit) /* mark trustDB as checked */
    {
      if (next_expire == 0xffffffff || next_expire < start_time )
        tdbio_write_nextcheck (0); 
      else
        {
          tdbio_write_nextcheck (next_expire); 
          log_info (_("next trustdb check due at %s\n"),
                    strtimestamp (next_expire));
        }

      if(tdbio_update_version_record()!=0)
	{
	  log_error(_("unable to update trustdb version record: "
		      "write failed: %s\n"), g10_errstr(rc));
	  tdbio_invalid();
	}

      do_sync ();
      pending_check_trustdb = 0;
    }

  return rc;
}
