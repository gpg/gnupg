/* trustdb.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
  unsigned int ownertrust;
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
  
  k = m_alloc_clear (sizeof *k);
  return k;
}

static void
release_key_items (struct key_item *k)
{
  struct key_item *k2;

  for (; k; k = k2)
    {
      k2 = k->next;
      m_free (k);
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

  tbl = m_alloc_clear (1024 * sizeof *tbl);
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
  m_free (tbl);
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
        m_free (keys);
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
register_trusted_key( const char *string )
{
  KEYDB_SEARCH_DESC desc;
  struct key_item *k;

  if (classify_user_id (string, &desc) != KEYDB_SEARCH_MODE_LONG_KID ) {
    log_error(_("`%s' is not a valid long keyID\n"), string );
    return;
  }

  k = new_key_item ();
  k->kid[0] = desc.u.kid[0];
  k->kid[1] = desc.u.kid[1];
  k->next = user_utk_list;
  user_utk_list = k;
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
    log_info(_("key %08lX: accepted as trusted key\n"), (ulong)kid[1]);
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
                log_info(_("key %08lX occurs more than once in the trustdb\n"),
                            (ulong)kid[1]);
        }
    }
  
  /* the --trusted-key option is again deprecated; however we automagically
   * add those keys to the trustdb */
  for (k = user_utk_list; k; k = k->next) 
    {
      if ( add_utk (k->kid) ) 
        { /* not yet in trustDB as ultimately trusted */
          PKT_public_key pk;

          memset (&pk, 0, sizeof pk);
          rc = get_pubkey (&pk, k->kid);
          if (rc) {
            log_info(_("key %08lX: no public key for trusted key - skipped\n"),
                     (ulong)k->kid[1] );
          }
          else {
            update_ownertrust (&pk,
                               ((get_ownertrust (&pk) & ~TRUST_MASK)
                                | TRUST_ULTIMATE ));
            release_public_key_parts (&pk);
          }
          log_info (_("key %08lX marked as ultimately trusted\n"),
                    (ulong)k->kid[1]);
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
    trustdb_args.dbname = dbname? m_strdup(dbname): NULL;
    return 0;
}

void
init_trustdb()
{
  int rc=0;
  int level = trustdb_args.level;
  const char* dbname = trustdb_args.dbname;

  if( trustdb_args.init )
    return;

  trustdb_args.init = 1;

  if ( !level || level==1)
    {
      rc = tdbio_set_dbname( dbname, !!level );
      if( !rc )
        {
          if( !level )
            return;
          
          /* verify that our own keys are in the trustDB
           * or move them to the trustdb. */
          verify_own_keys();
          
          /* should we check whether there is no other ultimately trusted
           * key in the database? */
        }
    }
  else
    BUG();
  if( rc )
    log_fatal("can't init trustdb: %s\n", g10_errstr(rc) );
}




/***********************************************
 *************	Print helpers	****************
 ***********************************************/

/****************
 * This function returns a letter for a trustvalue  Trust flags
 * are ignore.
 */
int
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
    default:              return 0;
    }
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


/*
 * Recreate the WoT. 
 */
void
update_trustdb()
{
  init_trustdb();
  validate_keys (1);
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

/*
 * Same as get_ownertrust but return a trust letter instead of an value.
 */
int
get_ownertrust_info (PKT_public_key *pk)
{
    unsigned int otrust;
    int c;

    otrust = get_ownertrust (pk);
    c = trust_letter( (otrust & TRUST_MASK) );
    if( !c )
	c = '?';
    return c;
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

/* Clear the ownertrust value.  Return true if a changed actually happend. */
int
clear_ownertrust (PKT_public_key *pk)
{
  TRUSTREC rec;
  int rc;
  
  rc = read_trust_record (pk, &rec);
  if (!rc)
    {
      if (DBG_TRUST)
        log_debug ("clearing ownertrust (old value %u)\n",
                   (unsigned int)rec.r.trust.ownertrust);
      if (rec.r.trust.ownertrust)
        {
          rec.r.trust.ownertrust = 0;
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
update_validity (PKT_public_key *pk, const byte *namehash,
                 int depth, int validity)
{
  TRUSTREC trec, vrec;
  int rc;
  ulong recno;
  
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
      if ( !memcmp (vrec.r.valid.namehash, namehash, 20) )
        break;
      recno = vrec.r.valid.next;
    }

  if (!recno) /* insert a new validity record */
    {
      memset (&vrec, 0, sizeof vrec);
      vrec.recnum = tdbio_new_recnum ();
      vrec.rectype = RECTYPE_VALID;
      memcpy (vrec.r.valid.namehash, namehash, 20);
      vrec.r.valid.next = trec.r.trust.validlist;
    }
  vrec.r.valid.validity = validity;
  write_record (&vrec);
  trec.r.trust.depth = depth;
  trec.r.trust.validlist = vrec.recnum;
  write_record (&trec);
}


/* reset validity for all user IDs.  Caller must sync. */
static int
clear_validity (PKT_public_key *pk)
{
  TRUSTREC trec, vrec;
  int rc;
  ulong recno;
  int any = 0;
  
  rc = read_trust_record (pk, &trec);
  if (rc && rc != -1)
    {
      tdbio_invalid ();
      return 0;
    }
  if (rc == -1) /* no record yet - no need to clerar it then ;-) */
    return 0;

  /* reset validity for all user IDs */
  recno = trec.r.trust.validlist;
  while (recno)
    {
      read_record (recno, &vrec, RECTYPE_VALID);
      if ((vrec.r.valid.validity & TRUST_MASK))
        {
          vrec.r.valid.validity &= ~TRUST_MASK;
          write_record (&vrec);
          any = 1;
        }
      recno = vrec.r.valid.next;
    }

  return any;
}



/***********************************************
 *********  Query trustdb values  **************
 ***********************************************/

/*
 * Return the validity information for PK.  If the namehash is not
 * NULL, the validity of the corresponsing user ID is returned,
 * otherwise, a reasonable value for the entire key is returned. 
 */
unsigned int
get_validity (PKT_public_key *pk, const byte *namehash)
{
  static int did_nextcheck;
  TRUSTREC trec, vrec;
  int rc;
  ulong recno;
  unsigned int validity;
  u32 kid[2];
  PKT_public_key *main_pk;
  
  init_trustdb ();
  if (!did_nextcheck)
    {
      ulong scheduled;

      did_nextcheck = 1;
      scheduled = tdbio_read_nextcheck ();
      if (scheduled && scheduled <= make_timestamp ())
        {
          if (opt.no_auto_check_trustdb) 
            {
              pending_check_trustdb = 1;
              log_info ("please do a --check-trustdb\n");
            }
          else
            {
              log_info (_("checking the trustdb\n"));
              validate_keys (0);
            }
        }
    }

  keyid_from_pk (pk, kid);
  if (pk->main_keyid[0] != kid[0] || pk->main_keyid[1] != kid[1])
    { /* this is a subkey - get the mainkey */
      main_pk = m_alloc_clear (sizeof *main_pk);
      rc = get_pubkey (main_pk, pk->main_keyid);
      if (rc)
        {
          log_error ("error getting main key %08lX of subkey %08lX: %s\n",
                     (ulong)pk->main_keyid[1], (ulong)kid[1], g10_errstr(rc));
          validity = TRUST_UNKNOWN; 
          goto leave;
	}
    }
  else
    main_pk = pk;

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
      if ( validity < (vrec.r.valid.validity & TRUST_MASK) )
        validity = (vrec.r.valid.validity & TRUST_MASK);
      if ( namehash && !memcmp (vrec.r.valid.namehash, namehash, 20) )
        break;
      recno = vrec.r.valid.next;
    }
  
  if (recno) /* okay, use the user ID associated one */
    validity = (vrec.r.valid.validity & TRUST_MASK);

  if ( (trec.r.trust.ownertrust & TRUST_FLAG_DISABLED) )
    validity |= TRUST_FLAG_DISABLED;

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
get_validity_info (PKT_public_key *pk, const byte *namehash)
{
    int trustlevel;
    int c;

    trustlevel = get_validity (pk, namehash);
    if( trustlevel & TRUST_FLAG_DISABLED )
	return 'd';
    if( trustlevel & TRUST_FLAG_REVOKED )
	return 'r';
    c = trust_letter ( (trustlevel & TRUST_MASK) );
    if( !c )
	c = '?';
    return c;
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
ask_ownertrust (u32 *kid)
{
  PKT_public_key *pk;
  int rc;
  int ot;

  pk = m_alloc_clear (sizeof *pk);
  rc = get_pubkey (pk, kid);
  if (rc)
    {
      log_error (_("public key %08lX not found: %s\n"),
                 (ulong)kid[1], g10_errstr(rc) );
      return TRUST_UNKNOWN;
    }
 
  ot=edit_ownertrust(pk,0);
  if(ot>0)
    ot = get_ownertrust (pk);
  else if(ot==0)
    ot = TRUST_UNDEFINED;
  else
    ot = -1; /* quit */
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
store_validation_status (int depth, KBNODE keyblock)
{
  KBNODE node;
  byte namehash[20];
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
              if( uid->attrib_data )
                rmd160_hash_buffer (namehash,uid->attrib_data,uid->attrib_len);
              else
                rmd160_hash_buffer (namehash, uid->name, uid->len );
              
              update_validity (keyblock->pkt->pkt.public_key,
                               namehash, depth, status);
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
 * node flag bit 8.  Note that flag bits 9 and 10 are used for internal
 * purposes.  
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
      node->flag &= ~(1<<8 | 1<<9 | 1<<10);
      if (node->pkt->pkttype == PKT_USER_ID
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        break; /* ready */
      if (node->pkt->pkttype != PKT_SIGNATURE)
        continue;
      
      sig = node->pkt->pkt.signature;
      if (sig->keyid[0] == main_kid[0] && sig->keyid[1] == main_kid[1])
        continue; /* ignore self-signatures */
      if (!IS_UID_SIG(sig) && !IS_UID_REV(sig))
        continue; /* we only look at these signature classes */
      if (!is_in_klist (klist, sig))
        continue;  /* no need to check it then */
      if (check_key_signature (keyblock, node, NULL))
        continue; /* ignore invalid signatures */
      node->flag |= 1<<9;
    }      
  /* reset the remaining flags */
  for (; node; node = node->next)
      node->flag &= ~(1<<8 | 1<<9 | 1 << 10);

  /* kbnode flag usage: bit 9 is here set for signatures to consider,
   * bit 10 will be set by the loop to keep track of keyIDs already
   * processed, bit 8 will be set for the usable signatures */

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
              if (expire && expire < *next_expire)
                *next_expire = expire;
            }
        }
    }
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
  PKT_public_key *pk = kb->pkt->pkt.public_key;
  u32 main_kid[2];
  int issigned=0, any_signed = 0, fully_count =0, marginal_count = 0;

  keyid_from_pk(pk, main_kid);
  for (node=kb; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          if (uidnode && issigned)
            {
              if (fully_count >= opt.completes_needed
                  || marginal_count >= opt.marginals_needed )
                uidnode->flag |= 4; 
              else if (fully_count || marginal_count)
                uidnode->flag |= 2;
              uidnode->flag |= 1;
              any_signed = 1;
            }
          uidnode = node;
          issigned = 0;
          fully_count = marginal_count = 0;
          mark_usable_uid_certs (kb, uidnode, main_kid, klist, 
                                 curtime, next_expire);
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE 
               && (node->flag & (1<<8)) )
        {
          PKT_signature *sig = node->pkt->pkt.signature;
          
          kr = is_in_klist (klist, sig);
          if (kr)
            {
              if (kr->ownertrust == TRUST_ULTIMATE)
                fully_count = opt.completes_needed;
              else if (kr->ownertrust == TRUST_FULLY)
                fully_count++;
              else if (kr->ownertrust == TRUST_MARGINAL)
                marginal_count++;
              issigned = 1;
            }
        }
    }

  if (uidnode && issigned)
    {
      if (fully_count >= opt.completes_needed
               || marginal_count >= opt.marginals_needed )
        uidnode->flag |= 4; 
      else if (fully_count || marginal_count)
        uidnode->flag |= 2;
      uidnode->flag |= 1;
      any_signed = 1;
    }

  return any_signed;
}


static int
search_skipfnc (void *opaque, u32 *kid)
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
validate_key_list (KEYDB_HANDLE hd, KeyHashTable visited,
                   struct key_item *klist, u32 curtime, u32 *next_expire)
{
  KBNODE keyblock = NULL;
  struct key_array *keys = NULL;
  size_t nkeys, maxkeys;
  int rc;
  KEYDB_SEARCH_DESC desc;
  
  maxkeys = 1000;
  keys = m_alloc ((maxkeys+1) * sizeof *keys);
  nkeys = 0;
  
  rc = keydb_search_reset (hd);
  if (rc)
    {
      log_error ("keydb_search_reset failed: %s\n", g10_errstr(rc));
      m_free (keys);
      return NULL;
    }

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  desc.skipfnc = search_skipfnc;
  desc.skipfncvalue = visited;
  rc = keydb_search (hd, &desc, 1);
  if (rc == -1)
    {
      keys[nkeys].keyblock = NULL;
      return keys;
    }
  if (rc)
    {
      log_error ("keydb_search_first failed: %s\n", g10_errstr(rc));
      m_free (keys);
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
          m_free (keys);
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
          mark_keyblock_seen (visited, keyblock);
        }
      else if (validate_one_keyblock (keyblock, klist, curtime, next_expire))
        {
          if (pk->expiredate && pk->expiredate >= curtime
              && pk->expiredate < *next_expire)
            *next_expire = pk->expiredate;

          if (nkeys == maxkeys) {
            maxkeys += 1000;
            keys = m_realloc (keys, (maxkeys+1) * sizeof *keys);
          }
          keys[nkeys++].keyblock = keyblock;
          /* this key is signed - don't check it again */
          mark_keyblock_seen (visited, keyblock);
          keyblock = NULL;
        }

      release_kbnode (keyblock);
      keyblock = NULL;
    } 
  while ( !(rc = keydb_search (hd, &desc, 1)) );
  if (rc && rc != -1) 
    {
      log_error ("keydb_search_next failed: %s\n", g10_errstr(rc));
      m_free (keys);
      return NULL;
    }

  keys[nkeys].keyblock = NULL;
  return keys;
} 


static void
reset_unconnected_keys (KEYDB_HANDLE hd, KeyHashTable visited)
{
  int rc;
  KBNODE keyblock = NULL;
  KEYDB_SEARCH_DESC desc;
  int count = 0, nreset = 0;
  
  rc = keydb_search_reset (hd);
  if (rc)
    {
      log_error ("keydb_search_reset failed: %s\n", g10_errstr(rc));
      return;
    }

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  desc.skipfnc = search_skipfnc;
  desc.skipfncvalue = visited;
  rc = keydb_search (hd, &desc, 1);
  if (rc && rc != -1 )
    log_error ("keydb_search_first failed: %s\n", g10_errstr(rc));
  else if (!rc)
    {
      desc.mode = KEYDB_SEARCH_MODE_NEXT; /* change mode */
      do
        {
          rc = keydb_get_keyblock (hd, &keyblock);
          if (rc) 
            {
              log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
              break;
            }
          count++;

          if (keyblock->pkt->pkttype == PKT_PUBLIC_KEY) /* paranoid assertion*/
            {
              nreset += clear_validity (keyblock->pkt->pkt.public_key);
              release_kbnode (keyblock);
            } 
        }
      while ( !(rc = keydb_search (hd, &desc, 1)) );
      if (rc && rc != -1) 
        log_error ("keydb_search_next failed: %s\n", g10_errstr(rc));
    }
  if (opt.verbose)
    log_info ("%d unconnected keys (%d trust records cleared)\n",
              count, nreset);
  do_sync ();
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
  int key_count;
  int ot_unknown, ot_undefined, ot_never, ot_marginal, ot_full, ot_ultimate;
  KeyHashTable visited;
  u32 start_time, next_expire;

  start_time = make_timestamp ();
  next_expire = 0xffffffff; /* set next expire to the year 2106 */
  visited = new_key_hash_table ();
  /* Fixme: Instead of always building a UTK list, we could just build it
   * here when needed */
  if (!utk_list)
    {
      log_info ("no ultimately trusted keys found\n");
      goto leave;
    }


  /* mark all UTKs as visited and set validity to ultimate */
  for (k=utk_list; k; k = k->next)
    {
      KBNODE keyblock;
      PKT_public_key *pk;

      keyblock = get_pubkeyblock (k->kid);
      if (!keyblock)
        {
          log_error (_("public key of ultimately"
                       " trusted key %08lX not found\n"), (ulong)k->kid[1]);
          continue;
        }
      mark_keyblock_seen (visited, keyblock);
      pk = keyblock->pkt->pkt.public_key;
      for (node=keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_USER_ID)
            {
              byte namehash[20];
              PKT_user_id *uid = node->pkt->pkt.user_id;
              
              if( uid->attrib_data )
                rmd160_hash_buffer (namehash,uid->attrib_data,uid->attrib_len);
              else
                rmd160_hash_buffer (namehash, uid->name, uid->len );
              update_validity (pk, namehash, 0, TRUST_ULTIMATE);
            }
        }
      if ( pk->expiredate && pk->expiredate >= start_time
           && pk->expiredate < next_expire)
        next_expire = pk->expiredate;
      
      release_kbnode (keyblock);
      do_sync ();
    }


  klist = utk_list;
  kdb = keydb_new (0);

  for (depth=0; depth < opt.max_cert_depth; depth++)
    {
      /* See whether we should assign ownertrust values to the keys in
         utk_list.  */
      ot_unknown = ot_undefined = ot_never = 0;
      ot_marginal = ot_full = ot_ultimate = 0;
      for (k=klist; k; k = k->next)
        {
          if (interactive && k->ownertrust == TRUST_UNKNOWN)
              k->ownertrust = ask_ownertrust (k->kid);
	  if (k->ownertrust == -1)
	    {
	      quit=1;
	      goto leave;
	    }
	  else if (k->ownertrust == TRUST_UNKNOWN)
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
        }

      /* Find all keys which are signed by a key in kdlist */
      keys = validate_key_list (kdb, visited, klist, start_time, &next_expire);
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

      log_info (_("checking at depth %d signed=%d"
                  " ot(-/q/n/m/f/u)=%d/%d/%d/%d/%d/%d\n"), 
                depth, key_count, ot_unknown, ot_undefined,
                ot_never, ot_marginal, ot_full, ot_ultimate ); 

      for (kar=keys; kar->keyblock; kar++)
          store_validation_status (depth, kar->keyblock);

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
                  k = new_key_item ();
                  keyid_from_pk (kar->keyblock->pkt->pkt.public_key, k->kid);
                  k->ownertrust = get_ownertrust (kar->keyblock
                                                  ->pkt->pkt.public_key);
                  k->next = klist;
                  klist = k;
                  break;
                }
            }
        }
      release_key_array (keys);
      keys = NULL;
      if (!klist)
        break; /* no need to dive in deeper */
    }

  reset_unconnected_keys (kdb, visited);

 leave:
  keydb_release (kdb);
  release_key_array (keys);
  release_key_items (klist);
  release_key_hash_table (visited);
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
      do_sync ();
      pending_check_trustdb = 0;
    }
  return rc;
}


