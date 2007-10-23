/* tdbio.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "options.h"
#include "main.h"
#include "i18n.h"
#include "trustdb.h"
#include "tdbio.h"

#if defined(HAVE_DOSISH_SYSTEM)
#define ftruncate chsize
#endif

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
#define MY_O_BINARY  O_BINARY
#else
#define MY_O_BINARY  0
#endif


/****************
 * Yes, this is a very simple implementation. We should really
 * use a page aligned buffer and read complete pages.
 * To implement a simple trannsaction system, this is sufficient.
 */
typedef struct cache_ctrl_struct *CACHE_CTRL;
struct cache_ctrl_struct {
    CACHE_CTRL next;
    struct {
	unsigned used:1;
	unsigned dirty:1;
    } flags;
    ulong recno;
    char data[TRUST_RECORD_LEN];
};

#define MAX_CACHE_ENTRIES_SOFT	200    /* may be increased while in a */
#define MAX_CACHE_ENTRIES_HARD	10000  /* transaction to this one */
static CACHE_CTRL cache_list;
static int cache_entries;
static int cache_is_dirty;

/* a type used to pass infomation to cmp_krec_fpr */
struct cmp_krec_fpr_struct {
    int pubkey_algo;
    const char *fpr;
    int fprlen;
};

/* a type used to pass infomation to cmp_[s]dir */
struct cmp_xdir_struct {
    int pubkey_algo;
    u32 keyid[2];
};


static char *db_name;
static DOTLOCK lockhandle;
static int is_locked;
static int  db_fd = -1;
static int in_transaction;

static void open_db(void);
static void migrate_from_v2 (void);



/*************************************
 ************* record cache **********
 *************************************/

/****************
 * Get the data from therecord cache and return a
 * pointer into that cache.  Caller should copy
 * the return data.  NULL is returned on a cache miss.
 */
static const char *
get_record_from_cache( ulong recno )
{
    CACHE_CTRL r;

    for( r = cache_list; r; r = r->next ) {
	if( r->flags.used && r->recno == recno )
	    return r->data;
    }
    return NULL;
}


static int
write_cache_item( CACHE_CTRL r )
{
    int n;

    if( lseek( db_fd, r->recno * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	log_error(_("trustdb rec %lu: lseek failed: %s\n"),
					    r->recno, strerror(errno) );
	return G10ERR_WRITE_FILE;
    }
    n = write( db_fd, r->data, TRUST_RECORD_LEN);
    if( n != TRUST_RECORD_LEN ) {
	log_error(_("trustdb rec %lu: write failed (n=%d): %s\n"),
					    r->recno, n, strerror(errno) );
	return G10ERR_WRITE_FILE;
    }
    r->flags.dirty = 0;
    return 0;
}

/****************
 * Put data into the cache.  This function may flush the
 * some cache entries if there is not enough space available.
 */
int
put_record_into_cache( ulong recno, const char *data )
{
    CACHE_CTRL r, unused;
    int dirty_count = 0;
    int clean_count = 0;

    /* see whether we already cached this one */
    for( unused = NULL, r = cache_list; r; r = r->next ) {
	if( !r->flags.used ) {
	    if( !unused )
		unused = r;
	}
	else if( r->recno == recno ) {
	    if( !r->flags.dirty ) {
		/* Hmmm: should we use a a copy and compare? */
		if( memcmp(r->data, data, TRUST_RECORD_LEN ) ) {
		    r->flags.dirty = 1;
		    cache_is_dirty = 1;
		}
	    }
	    memcpy( r->data, data, TRUST_RECORD_LEN );
	    return 0;
	}
	if( r->flags.used ) {
	    if( r->flags.dirty )
		dirty_count++;
	    else
		clean_count++;
	}
    }
    /* not in the cache: add a new entry */
    if( unused ) { /* reuse this entry */
	r = unused;
	r->flags.used = 1;
	r->recno = recno;
	memcpy( r->data, data, TRUST_RECORD_LEN );
	r->flags.dirty = 1;
	cache_is_dirty = 1;
	cache_entries++;
	return 0;
    }
    /* see whether we reached the limit */
    if( cache_entries < MAX_CACHE_ENTRIES_SOFT ) { /* no */
	r = xmalloc( sizeof *r );
	r->flags.used = 1;
	r->recno = recno;
	memcpy( r->data, data, TRUST_RECORD_LEN );
	r->flags.dirty = 1;
	r->next = cache_list;
	cache_list = r;
	cache_is_dirty = 1;
	cache_entries++;
	return 0;
    }
    /* cache is full: discard some clean entries */
    if( clean_count ) {
	int n = clean_count / 3; /* discard a third of the clean entries */
	if( !n )
	    n = 1;
	for( unused = NULL, r = cache_list; r; r = r->next ) {
	    if( r->flags.used && !r->flags.dirty ) {
		if( !unused )
		    unused = r;
		r->flags.used = 0;
		cache_entries--;
		if( !--n )
		    break;
	    }
	}
	assert( unused );
	r = unused;
	r->flags.used = 1;
	r->recno = recno;
	memcpy( r->data, data, TRUST_RECORD_LEN );
	r->flags.dirty = 1;
	cache_is_dirty = 1;
	cache_entries++;
	return 0;
    }
    /* no clean entries: have to flush some dirty entries */
    if( in_transaction ) {
	/* but we can't do this while in a transaction
	 * we increase the cache size instead */
	if( cache_entries < MAX_CACHE_ENTRIES_HARD ) { /* no */
	    if( opt.debug && !(cache_entries % 100) )
		log_debug("increasing tdbio cache size\n");
	    r = xmalloc( sizeof *r );
	    r->flags.used = 1;
	    r->recno = recno;
	    memcpy( r->data, data, TRUST_RECORD_LEN );
	    r->flags.dirty = 1;
	    r->next = cache_list;
	    cache_list = r;
	    cache_is_dirty = 1;
	    cache_entries++;
	    return 0;
	}
	log_info(_("trustdb transaction too large\n"));
	return G10ERR_RESOURCE_LIMIT;
    }
    if( dirty_count ) {
	int n = dirty_count / 5; /* discard some dirty entries */
	if( !n )
	    n = 1;
	if( !is_locked ) {
	    if( make_dotlock( lockhandle, -1 ) )
		log_fatal("can't acquire lock - giving up\n");
	    else
		is_locked = 1;
	}
	for( unused = NULL, r = cache_list; r; r = r->next ) {
	    if( r->flags.used && r->flags.dirty ) {
		int rc = write_cache_item( r );
		if( rc )
		    return rc;
		if( !unused )
		    unused = r;
		r->flags.used = 0;
		cache_entries--;
		if( !--n )
		    break;
	    }
	}
	if( !opt.lock_once ) {
	    if( !release_dotlock( lockhandle ) )
		is_locked = 0;
	}
	assert( unused );
	r = unused;
	r->flags.used = 1;
	r->recno = recno;
	memcpy( r->data, data, TRUST_RECORD_LEN );
	r->flags.dirty = 1;
	cache_is_dirty = 1;
	cache_entries++;
	return 0;
    }
    BUG();
}


int
tdbio_is_dirty()
{
    return cache_is_dirty;
}


/****************
 * Flush the cache.  This cannot be used while in a transaction.
 */
int
tdbio_sync()
{
    CACHE_CTRL r;
    int did_lock = 0;

    if( db_fd == -1 )
	open_db();
    if( in_transaction )
	log_bug("tdbio: syncing while in transaction\n");

    if( !cache_is_dirty )
	return 0;

    if( !is_locked ) {
	if( make_dotlock( lockhandle, -1 ) )
	    log_fatal("can't acquire lock - giving up\n");
	else
	    is_locked = 1;
	did_lock = 1;
    }
    for( r = cache_list; r; r = r->next ) {
	if( r->flags.used && r->flags.dirty ) {
	    int rc = write_cache_item( r );
	    if( rc )
		return rc;
	}
    }
    cache_is_dirty = 0;
    if( did_lock && !opt.lock_once ) {
	if( !release_dotlock( lockhandle ) )
	    is_locked = 0;
    }

    return 0;
}

#if 0
/* The transaction code is disabled in the 1.2.x branch, as it is not
   yet used.  It will be enabled in 1.3.x. */

/****************
 * Simple transactions system:
 * Everything between begin_transaction and end/cancel_transaction
 * is not immediatly written but at the time of end_transaction.
 *
 */
int
tdbio_begin_transaction()
{
    int rc;

    if( in_transaction )
	log_bug("tdbio: nested transactions\n");
    /* flush everything out */
    rc = tdbio_sync();
    if( rc )
	return rc;
    in_transaction = 1;
    return 0;
}

int
tdbio_end_transaction()
{
    int rc;

    if( !in_transaction )
	log_bug("tdbio: no active transaction\n");
    if( !is_locked ) {
	if( make_dotlock( lockhandle, -1 ) )
	    log_fatal("can't acquire lock - giving up\n");
	else
	    is_locked = 1;
    }
    block_all_signals();
    in_transaction = 0;
    rc = tdbio_sync();
    unblock_all_signals();
    if( !opt.lock_once ) {
	if( !release_dotlock( lockhandle ) )
	    is_locked = 0;
    }
    return rc;
}

int
tdbio_cancel_transaction()
{
    CACHE_CTRL r;

    if( !in_transaction )
	log_bug("tdbio: no active transaction\n");

    /* remove all dirty marked entries, so that the original ones
     * are read back the next time */
    if( cache_is_dirty ) {
	for( r = cache_list; r; r = r->next ) {
	    if( r->flags.used && r->flags.dirty ) {
		r->flags.used = 0;
		cache_entries--;
	    }
	}
	cache_is_dirty = 0;
    }

    in_transaction = 0;
    return 0;
}
#endif


/********************************************************
 **************** cached I/O functions ******************
 ********************************************************/

static void
cleanup(void)
{
    if( is_locked ) {
	if( !release_dotlock(lockhandle) )
	    is_locked = 0;
    }
}

/* Caller must sync */
int
tdbio_update_version_record (void)
{
  TRUSTREC rec;
  int rc;

  memset( &rec, 0, sizeof rec );

  rc=tdbio_read_record( 0, &rec, RECTYPE_VER);
  if(rc==0)
    {
      rec.r.ver.created     = make_timestamp();
      rec.r.ver.marginals   = opt.marginals_needed;
      rec.r.ver.completes   = opt.completes_needed;
      rec.r.ver.cert_depth  = opt.max_cert_depth;
      rec.r.ver.trust_model = opt.trust_model;
      rc=tdbio_write_record(&rec);
    }

  return rc;
}

static int
create_version_record (void)
{
  TRUSTREC rec;
  int rc;
  
  memset( &rec, 0, sizeof rec );
  rec.r.ver.version     = 3;
  rec.r.ver.created     = make_timestamp();
  rec.r.ver.marginals   = opt.marginals_needed;
  rec.r.ver.completes   = opt.completes_needed;
  rec.r.ver.cert_depth  = opt.max_cert_depth;
  if(opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC)
    rec.r.ver.trust_model = opt.trust_model;
  else
    rec.r.ver.trust_model = TM_PGP;
  rec.rectype = RECTYPE_VER;
  rec.recnum = 0;
  rc = tdbio_write_record( &rec );
  if( !rc )
    tdbio_sync();
  return rc;
}



int
tdbio_set_dbname( const char *new_dbname, int create )
{
    char *fname;
    static int initialized = 0;

    if( !initialized ) {
	atexit( cleanup );
	initialized = 1;
    }

    if(new_dbname==NULL)
      fname=make_filename(opt.homedir,"trustdb" EXTSEP_S "gpg", NULL);
    else if (*new_dbname != DIRSEP_C )
      {
	if (strchr(new_dbname, DIRSEP_C) )
	  fname = make_filename (new_dbname, NULL);
	else
	  fname = make_filename (opt.homedir, new_dbname, NULL);
      }
    else
      fname = xstrdup (new_dbname);

    if( access( fname, R_OK ) ) {
	if( errno != ENOENT ) {
	    log_error( _("can't access `%s': %s\n"), fname, strerror(errno) );
	    xfree(fname);
	    return G10ERR_TRUSTDB;
	}
	if( create ) {
	    FILE *fp;
	    TRUSTREC rec;
	    int rc;
	    char *p = strrchr( fname, DIRSEP_C );
	    mode_t oldmask;

	    assert(p);
	    *p = 0;
	    if( access( fname, F_OK ) ) {
		try_make_homedir( fname );
		log_fatal( _("%s: directory does not exist!\n"), fname );
	    }
	    *p = DIRSEP_C;

	    xfree(db_name);
	    db_name = fname;
#ifdef __riscos__
	    if( !lockhandle )
		lockhandle = create_dotlock( db_name );
	    if( !lockhandle )
		log_fatal( _("can't create lock for `%s'\n"), db_name );
            if( make_dotlock( lockhandle, -1 ) )
                log_fatal( _("can't lock `%s'\n"), db_name );
#endif /* __riscos__ */
	    oldmask=umask(077);
            if (is_secured_filename (fname)) {
                fp = NULL;
                errno = EPERM;
            }
            else
                fp =fopen( fname, "wb" );
	    umask(oldmask);
	    if( !fp )
		log_fatal( _("can't create `%s': %s\n"), fname, strerror(errno) );
	    fclose(fp);
	    db_fd = open( db_name, O_RDWR | MY_O_BINARY );
	    if( db_fd == -1 )
		log_fatal( _("can't open `%s': %s\n"), db_name, strerror(errno) );

#ifndef __riscos__
	    if( !lockhandle )
		lockhandle = create_dotlock( db_name );
	    if( !lockhandle )
		log_fatal( _("can't create lock for `%s'\n"), db_name );
#endif /* !__riscos__ */

            rc = create_version_record ();
	    if( rc )
		log_fatal( _("%s: failed to create version record: %s"),
						   fname, g10_errstr(rc));
	    /* and read again to check that we are okay */
	    if( tdbio_read_record( 0, &rec, RECTYPE_VER ) )
		log_fatal( _("%s: invalid trustdb created\n"), db_name );

	    if( !opt.quiet )
		log_info(_("%s: trustdb created\n"), db_name);

	    return 0;
	}
    }
    xfree(db_name);
    db_name = fname;
    return 0;
}


const char *
tdbio_get_dbname()
{
    return db_name;
}



static void
open_db()
{
  byte buf[10];
  int n;
  TRUSTREC rec;

  assert( db_fd == -1 );

  if (!lockhandle )
    lockhandle = create_dotlock( db_name );
  if (!lockhandle )
    log_fatal( _("can't create lock for `%s'\n"), db_name );
#ifdef __riscos__
  if (make_dotlock( lockhandle, -1 ) )
    log_fatal( _("can't lock `%s'\n"), db_name );
#endif /* __riscos__ */
  db_fd = open (db_name, O_RDWR | MY_O_BINARY );
  if (db_fd == -1 && (errno == EACCES
#ifdef EROFS
                      || errno == EROFS)
#endif
      ) {
      db_fd = open (db_name, O_RDONLY | MY_O_BINARY );
      if (db_fd != -1)
          log_info (_("NOTE: trustdb not writable\n"));
  }
  if ( db_fd == -1 )
    log_fatal( _("can't open `%s': %s\n"), db_name, strerror(errno) );
  register_secured_file (db_name);

  /* check whether we need to do a version migration */
  do
    n = read (db_fd, buf, 5);
  while (n==-1 && errno == EINTR);
  if (n == 5 && !memcmp (buf, "\x01gpg\x02", 5))
    {
      migrate_from_v2 ();
    }
  
  /* read the version record */
  if (tdbio_read_record (0, &rec, RECTYPE_VER ) )
    log_fatal( _("%s: invalid trustdb\n"), db_name );
}


/****************
 * Make a hashtable: type 0 = trust hash
 */
static void
create_hashtable( TRUSTREC *vr, int type )
{
    TRUSTREC rec;
    off_t offset;
    ulong recnum;
    int i, n, rc;

    offset = lseek( db_fd, 0, SEEK_END );
    if( offset == -1 )
	log_fatal("trustdb: lseek to end failed: %s\n", strerror(errno) );
    recnum = offset / TRUST_RECORD_LEN;
    assert(recnum); /* this is will never be the first record */

    if( !type )
	vr->r.ver.trusthashtbl = recnum;

    /* Now write the records */
    n = (256+ITEMS_PER_HTBL_RECORD-1) / ITEMS_PER_HTBL_RECORD;
    for(i=0; i < n; i++, recnum++ ) {
	 memset( &rec, 0, sizeof rec );
	 rec.rectype = RECTYPE_HTBL;
	 rec.recnum = recnum;
	 rc = tdbio_write_record( &rec );
	 if( rc )
	     log_fatal( _("%s: failed to create hashtable: %s\n"),
					db_name, g10_errstr(rc));
    }
    /* update the version record */
    rc = tdbio_write_record( vr );
    if( !rc )
	rc = tdbio_sync();
    if( rc )
	log_fatal( _("%s: error updating version record: %s\n"),
						  db_name, g10_errstr(rc));
}


int
tdbio_db_matches_options()
{
  static int yes_no = -1;

  if( yes_no == -1 )
    {
      TRUSTREC vr;
      int rc;

      rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
      if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
		   db_name, g10_errstr(rc) );

      yes_no = vr.r.ver.marginals == opt.marginals_needed
	&& vr.r.ver.completes == opt.completes_needed
	&& vr.r.ver.cert_depth == opt.max_cert_depth
	&& vr.r.ver.trust_model == opt.trust_model;
    }

  return yes_no;
}

byte
tdbio_read_model(void)
{
  TRUSTREC vr;
  int rc;
 
  rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
  if( rc )
    log_fatal( _("%s: error reading version record: %s\n"),
	       db_name, g10_errstr(rc) );
  return vr.r.ver.trust_model;
}

/****************
 * Return the nextstamp value.
 */
ulong
tdbio_read_nextcheck ()
{
    TRUSTREC vr;
    int rc;

    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
						    db_name, g10_errstr(rc) );
    return vr.r.ver.nextcheck;
}

/* Return true when the stamp was actually changed. */
int
tdbio_write_nextcheck (ulong stamp)
{
    TRUSTREC vr;
    int rc;

    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
				       db_name, g10_errstr(rc) );

    if (vr.r.ver.nextcheck == stamp)
      return 0;

    vr.r.ver.nextcheck = stamp;
    rc = tdbio_write_record( &vr );
    if( rc )
	log_fatal( _("%s: error writing version record: %s\n"),
				       db_name, g10_errstr(rc) );
    return 1;
}



/****************
 * Return the record number of the trusthash tbl or create a new one.
 */
static ulong
get_trusthashrec(void)
{
    static ulong trusthashtbl; /* record number of the trust hashtable */

    if( !trusthashtbl ) {
	TRUSTREC vr;
	int rc;

	rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
	if( rc )
	    log_fatal( _("%s: error reading version record: %s\n"),
					    db_name, g10_errstr(rc) );
	if( !vr.r.ver.trusthashtbl )
	    create_hashtable( &vr, 0 );

	trusthashtbl = vr.r.ver.trusthashtbl;
    }
    return trusthashtbl;
}



/****************
 * Update a hashtable.
 * table gives the start of the table, key and keylen is the key,
 * newrecnum is the record number to insert.
 */
static int
upd_hashtable( ulong table, byte *key, int keylen, ulong newrecnum )
{
    TRUSTREC lastrec, rec;
    ulong hashrec, item;
    int msb;
    int level=0;
    int rc, i;

    hashrec = table;
  next_level:
    msb = key[level];
    hashrec += msb / ITEMS_PER_HTBL_RECORD;
    rc = tdbio_read_record( hashrec, &rec, RECTYPE_HTBL );
    if( rc ) {
	log_error("upd_hashtable: read failed: %s\n",	g10_errstr(rc) );
	return rc;
    }

    item = rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item ) { /* insert a new item into the hash table */
	rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = newrecnum;
	rc = tdbio_write_record( &rec );
	if( rc ) {
	    log_error("upd_hashtable: write htbl failed: %s\n",
							    g10_errstr(rc) );
	    return rc;
	}
    }
    else if( item != newrecnum ) {  /* must do an update */
	lastrec = rec;
	rc = tdbio_read_record( item, &rec, 0 );
	if( rc ) {
	    log_error( "upd_hashtable: read item failed: %s\n",
							    g10_errstr(rc) );
	    return rc;
	}

	if( rec.rectype == RECTYPE_HTBL ) {
	    hashrec = item;
	    level++;
	    if( level >= keylen ) {
		log_error( "hashtable has invalid indirections.\n");
		return G10ERR_TRUSTDB;
	    }
	    goto next_level;
	}
	else if( rec.rectype == RECTYPE_HLST ) { /* extend list */
	    /* see whether the key is already in this list */
	    for(;;) {
		for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		    if( rec.r.hlst.rnum[i] == newrecnum ) {
			return 0; /* okay, already in the list */
		    }
		}
		if( rec.r.hlst.next ) {
		    rc = tdbio_read_record( rec.r.hlst.next,
						       &rec, RECTYPE_HLST);
		    if( rc ) {
			log_error( "upd_hashtable: read hlst failed: %s\n",
							     g10_errstr(rc) );
			return rc;
		    }
		}
		else
		    break; /* not there */
	    }
	    /* find the next free entry and put it in */
	    for(;;) {
		for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		    if( !rec.r.hlst.rnum[i] ) {
			rec.r.hlst.rnum[i] = newrecnum;
			rc = tdbio_write_record( &rec );
			if( rc )
			    log_error( "upd_hashtable: write hlst failed: %s\n",
							      g10_errstr(rc) );
			return rc; /* done */
		    }
		}
		if( rec.r.hlst.next ) {
		    rc = tdbio_read_record( rec.r.hlst.next,
						      &rec, RECTYPE_HLST );
		    if( rc ) {
			log_error( "upd_hashtable: read hlst failed: %s\n",
							     g10_errstr(rc) );
			return rc;
		    }
		}
		else { /* add a new list record */
		    rec.r.hlst.next = item = tdbio_new_recnum();
		    rc = tdbio_write_record( &rec );
		    if( rc ) {
			log_error( "upd_hashtable: write hlst failed: %s\n",
							  g10_errstr(rc) );
			return rc;
		    }
		    memset( &rec, 0, sizeof rec );
		    rec.rectype = RECTYPE_HLST;
		    rec.recnum = item;
		    rec.r.hlst.rnum[0] = newrecnum;
		    rc = tdbio_write_record( &rec );
		    if( rc )
			log_error( "upd_hashtable: write ext hlst failed: %s\n",
							  g10_errstr(rc) );
		    return rc; /* done */
		}
	    } /* end loop over hlst slots */
	}
	else if( rec.rectype == RECTYPE_TRUST ) { /* insert a list record */
	    if( rec.recnum == newrecnum ) {
		return 0;
	    }
	    item = rec.recnum; /* save number of key record */
	    memset( &rec, 0, sizeof rec );
	    rec.rectype = RECTYPE_HLST;
	    rec.recnum = tdbio_new_recnum();
	    rec.r.hlst.rnum[0] = item;	     /* old keyrecord */
	    rec.r.hlst.rnum[1] = newrecnum; /* and new one */
	    rc = tdbio_write_record( &rec );
	    if( rc ) {
		log_error( "upd_hashtable: write new hlst failed: %s\n",
						  g10_errstr(rc) );
		return rc;
	    }
	    /* update the hashtable record */
	    lastrec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = rec.recnum;
	    rc = tdbio_write_record( &lastrec );
	    if( rc )
		log_error( "upd_hashtable: update htbl failed: %s\n",
							     g10_errstr(rc) );
	    return rc; /* ready */
	}
	else {
	    log_error( "hashtbl %lu: %lu/%d points to an invalid record %lu\n",
		       table, hashrec, (msb % ITEMS_PER_HTBL_RECORD), item);
	    list_trustdb(NULL);
	    return G10ERR_TRUSTDB;
	}
    }

    return 0;
}


/****************
 * Drop an entry from a hashtable
 * table gives the start of the table, key and keylen is the key,
 */
static int
drop_from_hashtable( ulong table, byte *key, int keylen, ulong recnum )
{
    TRUSTREC rec;
    ulong hashrec, item;
    int msb;
    int level=0;
    int rc, i;

    hashrec = table;
  next_level:
    msb = key[level];
    hashrec += msb / ITEMS_PER_HTBL_RECORD;
    rc = tdbio_read_record( hashrec, &rec, RECTYPE_HTBL );
    if( rc ) {
	log_error("drop_from_hashtable: read failed: %s\n",
							g10_errstr(rc) );
	return rc;
    }

    item = rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item )  /* not found - forget about it  */
	return 0;

    if( item == recnum ) {  /* tables points direct to the record */
	rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = 0;
	rc = tdbio_write_record( &rec );
	if( rc )
	    log_error("drop_from_hashtable: write htbl failed: %s\n",
							    g10_errstr(rc) );
	return rc;
    }

    rc = tdbio_read_record( item, &rec, 0 );
    if( rc ) {
	log_error( "drop_from_hashtable: read item failed: %s\n",
							g10_errstr(rc) );
	return rc;
    }

    if( rec.rectype == RECTYPE_HTBL ) {
	hashrec = item;
	level++;
	if( level >= keylen ) {
	    log_error( "hashtable has invalid indirections.\n");
	    return G10ERR_TRUSTDB;
	}
	goto next_level;
    }

    if( rec.rectype == RECTYPE_HLST ) {
	for(;;) {
	    for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		if( rec.r.hlst.rnum[i] == recnum ) {
		    rec.r.hlst.rnum[i] = 0; /* drop */
		    rc = tdbio_write_record( &rec );
		    if( rc )
			log_error("drop_from_hashtable: write htbl failed: %s\n",
									g10_errstr(rc) );
		    return rc;
		}
	    }
	    if( rec.r.hlst.next ) {
		rc = tdbio_read_record( rec.r.hlst.next,
						   &rec, RECTYPE_HLST);
		if( rc ) {
		    log_error( "drop_from_hashtable: read hlst failed: %s\n",
							 g10_errstr(rc) );
		    return rc;
		}
	    }
	    else
		return 0; /* key not in table */
	}
    }

    log_error( "hashtbl %lu: %lu/%d points to wrong record %lu\n",
		    table, hashrec, (msb % ITEMS_PER_HTBL_RECORD), item);
    return G10ERR_TRUSTDB;
}



/****************
 * Lookup a record via the hashtable tablewith key/keylen and return the
 * result in rec.  cmp() should return if the record is the desired one.
 * Returns -1 if not found, 0 if found or another errocode
 */
static int
lookup_hashtable( ulong table, const byte *key, size_t keylen,
		  int (*cmpfnc)(void*, const TRUSTREC *), void *cmpdata,
						TRUSTREC *rec )
{
    int rc;
    ulong hashrec, item;
    int msb;
    int level=0;

    hashrec = table;
  next_level:
    msb = key[level];
    hashrec += msb / ITEMS_PER_HTBL_RECORD;
    rc = tdbio_read_record( hashrec, rec, RECTYPE_HTBL );
    if( rc ) {
	log_error("lookup_hashtable failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    item = rec->r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item )
	return -1; /* not found */

    rc = tdbio_read_record( item, rec, 0 );
    if( rc ) {
	log_error( "hashtable read failed: %s\n", g10_errstr(rc) );
	return rc;
    }
    if( rec->rectype == RECTYPE_HTBL ) {
	hashrec = item;
	level++;
	if( level >= keylen ) {
	    log_error("hashtable has invalid indirections\n");
	    return G10ERR_TRUSTDB;
	}
	goto next_level;
    }
    else if( rec->rectype == RECTYPE_HLST ) {
	for(;;) {
	    int i;

	    for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
		if( rec->r.hlst.rnum[i] ) {
		    TRUSTREC tmp;

		    rc = tdbio_read_record( rec->r.hlst.rnum[i], &tmp, 0 );
		    if( rc ) {
			log_error( "lookup_hashtable: read item failed: %s\n",
							      g10_errstr(rc) );
			return rc;
		    }
		    if( (*cmpfnc)( cmpdata, &tmp ) ) {
			*rec = tmp;
			return 0;
		    }
		}
	    }
	    if( rec->r.hlst.next ) {
		rc = tdbio_read_record( rec->r.hlst.next, rec, RECTYPE_HLST );
		if( rc ) {
		    log_error( "lookup_hashtable: read hlst failed: %s\n",
							 g10_errstr(rc) );
		    return rc;
		}
	    }
	    else
		return -1; /* not found */
	}
    }


    if( (*cmpfnc)( cmpdata, rec ) )
	return 0; /* really found */

    return -1; /* no: not found */
}


/****************
 * Update the trust hashtbl or create the table if it does not exist
 */
static int
update_trusthashtbl( TRUSTREC *tr )
{
    return upd_hashtable( get_trusthashrec(),
			  tr->r.trust.fingerprint, 20, tr->recnum );
}



void
tdbio_dump_record( TRUSTREC *rec, FILE *fp  )
{
    int i;
    ulong rnum = rec->recnum;

    fprintf(fp, "rec %5lu, ", rnum );

    switch( rec->rectype ) {
      case 0: fprintf(fp, "blank\n");
	break;
      case RECTYPE_VER: fprintf(fp,
	    "version, td=%lu, f=%lu, m/c/d=%d/%d/%d tm=%d nc=%lu (%s)\n",
                                   rec->r.ver.trusthashtbl,
				   rec->r.ver.firstfree,
				   rec->r.ver.marginals,
				   rec->r.ver.completes,
				   rec->r.ver.cert_depth,
				   rec->r.ver.trust_model,
                                   rec->r.ver.nextcheck,
				   strtimestamp(rec->r.ver.nextcheck)
                                 );
	break;
      case RECTYPE_FREE: fprintf(fp, "free, next=%lu\n", rec->r.free.next );
	break;
      case RECTYPE_HTBL:
	fprintf(fp, "htbl,");
	for(i=0; i < ITEMS_PER_HTBL_RECORD; i++ )
	    fprintf(fp, " %lu", rec->r.htbl.item[i] );
	putc('\n', fp);
	break;
      case RECTYPE_HLST:
	fprintf(fp, "hlst, next=%lu,", rec->r.hlst.next );
	for(i=0; i < ITEMS_PER_HLST_RECORD; i++ )
	    fprintf(fp, " %lu", rec->r.hlst.rnum[i] );
	putc('\n', fp);
	break;
      case RECTYPE_TRUST:
	fprintf(fp, "trust ");
	for(i=0; i < 20; i++ )
	    fprintf(fp, "%02X", rec->r.trust.fingerprint[i] );
        fprintf (fp, ", ot=%d, d=%d, vl=%lu\n", rec->r.trust.ownertrust,
                 rec->r.trust.depth, rec->r.trust.validlist);
	break;
      case RECTYPE_VALID:
	fprintf(fp, "valid ");
	for(i=0; i < 20; i++ )
	    fprintf(fp, "%02X", rec->r.valid.namehash[i] );
        fprintf (fp, ", v=%d, next=%lu\n", rec->r.valid.validity,
                 rec->r.valid.next);
	break;
      default:
	fprintf(fp, "unknown type %d\n", rec->rectype );
	break;
    }
}

/****************
 * read the record with number recnum
 * returns: -1 on error, 0 on success
 */
int
tdbio_read_record( ulong recnum, TRUSTREC *rec, int expected )
{
    byte readbuf[TRUST_RECORD_LEN];
    const byte *buf, *p;
    int rc = 0;
    int n, i;

    if( db_fd == -1 )
	open_db();
    buf = get_record_from_cache( recnum );
    if( !buf ) {
	if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	    log_error(_("trustdb: lseek failed: %s\n"), strerror(errno) );
	    return G10ERR_READ_FILE;
	}
	n = read( db_fd, readbuf, TRUST_RECORD_LEN);
	if( !n ) {
	    return -1; /* eof */
	}
	else if( n != TRUST_RECORD_LEN ) {
	    log_error(_("trustdb: read failed (n=%d): %s\n"), n,
							strerror(errno) );
	    return G10ERR_READ_FILE;
	}
	buf = readbuf;
    }
    rec->recnum = recnum;
    rec->dirty = 0;
    p = buf;
    rec->rectype = *p++;
    if( expected && rec->rectype != expected ) {
	log_error("%lu: read expected rec type %d, got %d\n",
		    recnum, expected, rec->rectype );
	return G10ERR_TRUSTDB;
    }
    p++;    /* skip reserved byte */
    switch( rec->rectype ) {
      case 0:  /* unused (free) record */
	break;
      case RECTYPE_VER: /* version record */
	if( memcmp(buf+1, "gpg", 3 ) ) {
	    log_error( _("%s: not a trustdb file\n"), db_name );
	    rc = G10ERR_TRUSTDB;
	}
	p += 2; /* skip "gpg" */
	rec->r.ver.version  = *p++;
	rec->r.ver.marginals = *p++;
	rec->r.ver.completes = *p++;
	rec->r.ver.cert_depth = *p++;
	rec->r.ver.trust_model = *p++;
	p += 3;
	rec->r.ver.created  = buftoulong(p); p += 4;
	rec->r.ver.nextcheck = buftoulong(p); p += 4;
	p += 4;
	p += 4;
	rec->r.ver.firstfree =buftoulong(p); p += 4;
	p += 4;
	rec->r.ver.trusthashtbl =buftoulong(p); p += 4;
	if( recnum ) {
	    log_error( _("%s: version record with recnum %lu\n"), db_name,
							     (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	else if( rec->r.ver.version != 3 ) {
	    log_error( _("%s: invalid file version %d\n"), db_name,
							rec->r.ver.version );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_FREE:
	rec->r.free.next  = buftoulong(p); p += 4;
	break;
      case RECTYPE_HTBL:
	for(i=0; i < ITEMS_PER_HTBL_RECORD; i++ ) {
	    rec->r.htbl.item[i] = buftoulong(p); p += 4;
	}
	break;
      case RECTYPE_HLST:
	rec->r.hlst.next = buftoulong(p); p += 4;
	for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
	    rec->r.hlst.rnum[i] = buftoulong(p); p += 4;
	}
	break;
      case RECTYPE_TRUST:
	memcpy( rec->r.trust.fingerprint, p, 20); p+=20;
        rec->r.trust.ownertrust = *p++;
        rec->r.trust.depth = *p++;
        rec->r.trust.min_ownertrust = *p++;
        p++;
	rec->r.trust.validlist = buftoulong(p); p += 4;
	break;
      case RECTYPE_VALID:
	memcpy( rec->r.valid.namehash, p, 20); p+=20;
        rec->r.valid.validity = *p++;
	rec->r.valid.next = buftoulong(p); p += 4;
	rec->r.valid.full_count = *p++;
	rec->r.valid.marginal_count = *p++;
	break;
      default:
	log_error( "%s: invalid record type %d at recnum %lu\n",
				   db_name, rec->rectype, (ulong)recnum );
	rc = G10ERR_TRUSTDB;
	break;
    }

    return rc;
}

/****************
 * Write the record at RECNUM
 */
int
tdbio_write_record( TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int i;
    ulong recnum = rec->recnum;

    if( db_fd == -1 )
	open_db();

    memset(buf, 0, TRUST_RECORD_LEN);
    p = buf;
    *p++ = rec->rectype; p++;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case RECTYPE_VER: /* version record */
	if( recnum )
	    BUG();
	memcpy(p-1, "gpg", 3 ); p += 2;
	*p++ = rec->r.ver.version;
	*p++ = rec->r.ver.marginals;
	*p++ = rec->r.ver.completes;
	*p++ = rec->r.ver.cert_depth;
	*p++ = rec->r.ver.trust_model;
	p += 3;
	ulongtobuf(p, rec->r.ver.created); p += 4;
	ulongtobuf(p, rec->r.ver.nextcheck); p += 4;
	p += 4;
	p += 4;
	ulongtobuf(p, rec->r.ver.firstfree ); p += 4;
	p += 4;
	ulongtobuf(p, rec->r.ver.trusthashtbl ); p += 4;
	break;

      case RECTYPE_FREE:
	ulongtobuf(p, rec->r.free.next); p += 4;
	break;


      case RECTYPE_HTBL:
	for(i=0; i < ITEMS_PER_HTBL_RECORD; i++ ) {
	    ulongtobuf( p, rec->r.htbl.item[i]); p += 4;
	}
	break;

      case RECTYPE_HLST:
	ulongtobuf( p, rec->r.hlst.next); p += 4;
	for(i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
	    ulongtobuf( p, rec->r.hlst.rnum[i]); p += 4;
	}
	break;

      case RECTYPE_TRUST:
	memcpy( p, rec->r.trust.fingerprint, 20); p += 20;
	*p++ = rec->r.trust.ownertrust;
	*p++ = rec->r.trust.depth;
	*p++ = rec->r.trust.min_ownertrust;
        p++;
	ulongtobuf( p, rec->r.trust.validlist); p += 4;
	break;

      case RECTYPE_VALID:
	memcpy( p, rec->r.valid.namehash, 20); p += 20;
	*p++ = rec->r.valid.validity;
	ulongtobuf( p, rec->r.valid.next); p += 4;
	*p++ = rec->r.valid.full_count;
	*p++ = rec->r.valid.marginal_count;
	break;

      default:
	BUG();
    }

    rc = put_record_into_cache( recnum, buf );
    if( rc )
	;
    else if( rec->rectype == RECTYPE_TRUST )
	rc = update_trusthashtbl( rec );

    return rc;
}

int
tdbio_delete_record( ulong recnum )
{
    TRUSTREC vr, rec;
    int rc;

    /* Must read the record fist, so we can drop it from the hash tables */
    rc = tdbio_read_record( recnum, &rec, 0 );
    if( rc )
	;
    else if( rec.rectype == RECTYPE_TRUST ) {
         rc = drop_from_hashtable( get_trusthashrec(),
				   rec.r.trust.fingerprint, 20, rec.recnum );
    }

    if( rc )
	return rc;

    /* now we can chnage it to a free record */
    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
				       db_name, g10_errstr(rc) );

    rec.recnum = recnum;
    rec.rectype = RECTYPE_FREE;
    rec.r.free.next = vr.r.ver.firstfree;
    vr.r.ver.firstfree = recnum;
    rc = tdbio_write_record( &rec );
    if( !rc )
	rc = tdbio_write_record( &vr );
    return rc;
}

/****************
 * create a new record and return its record number
 */
ulong
tdbio_new_recnum()
{
    off_t offset;
    ulong recnum;
    TRUSTREC vr, rec;
    int rc;

    /* look for unused records */
    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
					     db_name, g10_errstr(rc) );
    if( vr.r.ver.firstfree ) {
	recnum = vr.r.ver.firstfree;
	rc = tdbio_read_record( recnum, &rec, RECTYPE_FREE );
	if( rc ) {
	    log_error( _("%s: error reading free record: %s\n"),
						  db_name,  g10_errstr(rc) );
	    return rc;
	}
	/* update dir record */
	vr.r.ver.firstfree = rec.r.free.next;
	rc = tdbio_write_record( &vr );
	if( rc ) {
	    log_error( _("%s: error writing dir record: %s\n"),
						     db_name, g10_errstr(rc) );
	    return rc;
	}
	/*zero out the new record */
	memset( &rec, 0, sizeof rec );
	rec.rectype = 0; /* unused record */
	rec.recnum = recnum;
	rc = tdbio_write_record( &rec );
	if( rc )
	    log_fatal(_("%s: failed to zero a record: %s\n"),
				       db_name, g10_errstr(rc));
    }
    else { /* not found, append a new record */
	offset = lseek( db_fd, 0, SEEK_END );
	if( offset == -1 )
	    log_fatal("trustdb: lseek to end failed: %s\n", strerror(errno) );
	recnum = offset / TRUST_RECORD_LEN;
	assert(recnum); /* this is will never be the first record */
	/* we must write a record, so that the next call to this function
	 * returns another recnum */
	memset( &rec, 0, sizeof rec );
	rec.rectype = 0; /* unused record */
	rec.recnum = recnum;
	rc = 0;
	if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	    log_error(_("trustdb rec %lu: lseek failed: %s\n"),
						recnum, strerror(errno) );
	    rc = G10ERR_WRITE_FILE;
	}
	else {
	    int n = write( db_fd, &rec, TRUST_RECORD_LEN);
	    if( n != TRUST_RECORD_LEN ) {
		log_error(_("trustdb rec %lu: write failed (n=%d): %s\n"),
						 recnum, n, strerror(errno) );
		rc = G10ERR_WRITE_FILE;
	    }
	}

	if( rc )
	    log_fatal(_("%s: failed to append a record: %s\n"),
				    db_name,	g10_errstr(rc));
    }
    return recnum ;
}



static int
cmp_trec_fpr ( void *fpr, const TRUSTREC *rec )
{
    return rec->rectype == RECTYPE_TRUST
	   && !memcmp( rec->r.trust.fingerprint, fpr, 20);
}


int
tdbio_search_trust_byfpr( const byte *fingerprint, TRUSTREC *rec )
{
    int rc;

    /* locate the trust record using the hash table */
    rc = lookup_hashtable( get_trusthashrec(), fingerprint, 20,
			   cmp_trec_fpr, (void*)fingerprint, rec );
    return rc;
}

int
tdbio_search_trust_bypk (PKT_public_key *pk, TRUSTREC *rec)
{
    byte fingerprint[MAX_FINGERPRINT_LEN];
    size_t fingerlen;

    fingerprint_from_pk( pk, fingerprint, &fingerlen );
    for (; fingerlen < 20; fingerlen++ )
      fingerprint[fingerlen] = 0;
    return tdbio_search_trust_byfpr (fingerprint, rec);
}



void
tdbio_invalid(void)
{
    log_error(_(
	"the trustdb is corrupted; please run \"gpg --fix-trustdb\".\n") );
    g10_exit(2);
}

/*
 * Migrate the trustdb as just up to gpg 1.0.6 (trustdb version 2)
 * to the 2.1 version as used with 1.0.6b - This is pretty trivial as needs
 * only to scan the tdb and insert new the new trust records.  The old ones are
 * obsolte from now on
 */
static void
migrate_from_v2 ()
{
  TRUSTREC rec;
  int i, n;
  struct {
    ulong keyrecno;
    byte  ot;
    byte okay;
    byte  fpr[20];
  } *ottable;
  int ottable_size, ottable_used;
  byte oldbuf[40];
  ulong recno;
  int rc, count;

  ottable_size = 5;
  ottable = xmalloc (ottable_size * sizeof *ottable);
  ottable_used = 0;

  /* We have some restrictions here.  We can't use the version record
   * and we can't use any of the old hashtables because we dropped the
   * code.  So we first collect all ownertrusts and then use a second
   * pass fo find the associated keys.  We have to do this all without using 
   * the regular record read functions.
   */

  /* get all the ownertrusts */
  if (lseek (db_fd, 0, SEEK_SET ) == -1 ) 
      log_fatal ("migrate_from_v2: lseek failed: %s\n", strerror (errno));
  for (recno=0;;recno++)
    {
      do
        n = read (db_fd, oldbuf, 40);
      while (n==-1 && errno == EINTR);
      if (!n)
        break; /* eof */
      if (n != 40)
        log_fatal ("migrate_vfrom_v2: read error or short read\n");

      if (*oldbuf != 2)
        continue;
      
      /* v2 dir record */
      if (ottable_used == ottable_size)
        {
          ottable_size += 1000;
          ottable = xrealloc (ottable, ottable_size * sizeof *ottable);
        }
      ottable[ottable_used].keyrecno = buftoulong (oldbuf+6);
      ottable[ottable_used].ot = oldbuf[18];
      ottable[ottable_used].okay = 0;
      memset (ottable[ottable_used].fpr,0, 20);
      if (ottable[ottable_used].keyrecno && ottable[ottable_used].ot)
        ottable_used++;
    }
  log_info ("found %d ownertrust records\n", ottable_used);

  /* Read again and find the fingerprints */
  if (lseek (db_fd, 0, SEEK_SET ) == -1 ) 
      log_fatal ("migrate_from_v2: lseek failed: %s\n", strerror (errno));
  for (recno=0;;recno++)
    {
      do
        n = read (db_fd, oldbuf, 40);
      while (n==-1 && errno == EINTR);
      if (!n)
        break; /* eof */
      if (n != 40)
        log_fatal ("migrate_from_v2: read error or short read\n");

      if (*oldbuf != 3) 
        continue;

      /* v2 key record */
      for (i=0; i < ottable_used; i++)
        {
          if (ottable[i].keyrecno == recno)
            {
              memcpy (ottable[i].fpr, oldbuf+20, 20);
              ottable[i].okay = 1;
              break;
            }
        }
    }

  /* got everything - create the v3 trustdb */
  if (ftruncate (db_fd, 0))
    log_fatal ("can't truncate `%s': %s\n", db_name, strerror (errno) );
  if (create_version_record ())
    log_fatal ("failed to recreate version record of `%s'\n", db_name);

  /* access the hash table, so it is store just after the version record, 
   * this is not needed put a dump is more pretty */
  get_trusthashrec ();

  /* And insert the old ownertrust values */
  count = 0;
  for (i=0; i < ottable_used; i++)
    {
      if (!ottable[i].okay)
        continue;
      
      memset (&rec, 0, sizeof rec);
      rec.recnum = tdbio_new_recnum ();
      rec.rectype = RECTYPE_TRUST;
      memcpy(rec.r.trust.fingerprint, ottable[i].fpr, 20);
      rec.r.trust.ownertrust = ottable[i].ot;
      if (tdbio_write_record (&rec))
        log_fatal ("failed to write trust record of `%s'\n", db_name);
      count++;
    }

  revalidation_mark ();
  rc = tdbio_sync ();
  if (rc)
    log_fatal ("failed to sync `%s'\n", db_name);
  log_info ("migrated %d version 2 ownertrusts\n", count);
  xfree (ottable);
}
