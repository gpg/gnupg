/* tdbio.c
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
	r = m_alloc( sizeof *r );
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
	    r = m_alloc( sizeof *r );
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

int
tdbio_set_dbname( const char *new_dbname, int create )
{
    char *fname;
    static int initialized = 0;

    if( !initialized ) {
	atexit( cleanup );
	initialized = 1;
    }
    fname = new_dbname? m_strdup( new_dbname )
		      : make_filename(opt.homedir, "trustdb.gpg", NULL );

    if( access( fname, R_OK ) ) {
	if( errno != ENOENT ) {
	    log_error( _("%s: can't access: %s\n"), fname, strerror(errno) );
	    m_free(fname);
	    return G10ERR_TRUSTDB;
	}
	if( create ) {
	    FILE *fp;
	    TRUSTREC rec;
	    int rc;
	    char *p = strrchr( fname, '/' );

	    assert(p);
	    *p = 0;
	    if( access( fname, F_OK ) ) {
		try_make_homedir( fname );
		log_fatal( _("%s: directory does not exist!\n"), fname );
	    }
	    *p = '/';

	    fp =fopen( fname, "wb" );
	    if( !fp )
		log_fatal( _("%s: can't create: %s\n"), fname, strerror(errno) );
	    fclose(fp);
	    m_free(db_name);
	    db_name = fname;
	  #ifdef HAVE_DOSISH_SYSTEM
	    db_fd = open( db_name, O_RDWR | O_BINARY );
	  #else
	    db_fd = open( db_name, O_RDWR );
	  #endif
	    if( db_fd == -1 )
		log_fatal( _("%s: can't open: %s\n"), db_name, strerror(errno) );

	    if( !lockhandle )
		lockhandle = create_dotlock( db_name );
	    if( !lockhandle )
		log_fatal( _("%s: can't create lock\n"), db_name );

	    memset( &rec, 0, sizeof rec );
	    rec.r.ver.version = 2;
	    rec.r.ver.created = make_timestamp();
	    rec.r.ver.marginals =  opt.marginals_needed;
	    rec.r.ver.completes =  opt.completes_needed;
	    rec.r.ver.cert_depth = opt.max_cert_depth;
	    rec.rectype = RECTYPE_VER;
	    rec.recnum = 0;
	    rc = tdbio_write_record( &rec );
	    if( !rc )
		tdbio_sync();
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
    m_free(db_name);
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
    TRUSTREC rec;
    assert( db_fd == -1 );

    if( !lockhandle )
	lockhandle = create_dotlock( db_name );
    if( !lockhandle )
	log_fatal( _("%s: can't create lock\n"), db_name );
  #ifdef HAVE_DOSISH_SYSTEM
    db_fd = open( db_name, O_RDWR | O_BINARY );
  #else
    db_fd = open( db_name, O_RDWR );
  #endif
    if( db_fd == -1 )
	log_fatal( _("%s: can't open: %s\n"), db_name, strerror(errno) );
    if( tdbio_read_record( 0, &rec, RECTYPE_VER ) )
	log_fatal( _("%s: invalid trustdb\n"), db_name );
}


/****************
 * Make a hashtable: type 0 = key hash, 1 = sdir hash
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
	vr->r.ver.keyhashtbl = recnum;
    else
	vr->r.ver.sdirhashtbl = recnum;
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

    if( yes_no == -1 ) {
	TRUSTREC vr;
	int rc;

	rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
	if( rc )
	    log_fatal( _("%s: error reading version record: %s\n"),
						    db_name, g10_errstr(rc) );

	if( !vr.r.ver.marginals && !vr.r.ver.completes
				&& !vr.r.ver.cert_depth )
	{   /* special hack for trustdbs created by old versions of GnuPG */
	    vr.r.ver.marginals =  opt.marginals_needed;
	    vr.r.ver.completes =  opt.completes_needed;
	    vr.r.ver.cert_depth = opt.max_cert_depth;
	    rc = tdbio_write_record( &vr );
	    if( !rc && !in_transaction )
		rc = tdbio_sync();
	    if( rc )
		log_error( _("%s: error writing version record: %s\n"),
						db_name, g10_errstr(rc) );
	}

	yes_no = vr.r.ver.marginals == opt.marginals_needed
		 && vr.r.ver.completes == opt.completes_needed
		 && vr.r.ver.cert_depth == opt.max_cert_depth;
    }
    return yes_no;
}


/****************
 * Return the modifiy stamp.
 * if modify_down is true, the modify_down stamp will be
 * returned, otherwise the modify_up stamp.
 */
ulong
tdbio_read_modify_stamp( int modify_down )
{
    TRUSTREC vr;
    int rc;
    ulong mod;

    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
						    db_name, g10_errstr(rc) );

    mod = modify_down? vr.r.ver.mod_down : vr.r.ver.mod_up;

    /* Always return at least 1 to make comparison easier;
     * this is still far back in history (before Led Zeppelin III :-) */
    return mod ? mod : 1;
}

void
tdbio_write_modify_stamp( int up, int down )
{
    TRUSTREC vr;
    int rc;
    ulong stamp;

    if( !(up || down) )
	return;

    rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
    if( rc )
	log_fatal( _("%s: error reading version record: %s\n"),
				       db_name, g10_errstr(rc) );

    stamp = make_timestamp();
    if( down )
	vr.r.ver.mod_down = stamp;
    if( up )
	vr.r.ver.mod_up = stamp;

    rc = tdbio_write_record( &vr );
    if( rc )
	log_fatal( _("%s: error writing version record: %s\n"),
				       db_name, g10_errstr(rc) );
}


/****************
 * Return the record number of the keyhash tbl or create a new one.
 */
static ulong
get_keyhashrec(void)
{
    static ulong keyhashtbl; /* record number of the key hashtable */

    if( !keyhashtbl ) {
	TRUSTREC vr;
	int rc;

	rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
	if( rc )
	    log_fatal( _("%s: error reading version record: %s\n"),
					    db_name, g10_errstr(rc) );
	if( !vr.r.ver.keyhashtbl )
	    create_hashtable( &vr, 0 );

	keyhashtbl = vr.r.ver.keyhashtbl;
    }
    return keyhashtbl;
}

/****************
 * Return the record number of the shadow direcory hash table
 * or create a new one.
 */
static ulong
get_sdirhashrec(void)
{
    static ulong sdirhashtbl; /* record number of the hashtable */

    if( !sdirhashtbl ) {
	TRUSTREC vr;
	int rc;

	rc = tdbio_read_record( 0, &vr, RECTYPE_VER );
	if( rc )
	    log_fatal( _("%s: error reading version record: %s\n"),
						    db_name, g10_errstr(rc) );
	if( !vr.r.ver.sdirhashtbl )
	    create_hashtable( &vr, 1 );

	sdirhashtbl = vr.r.ver.sdirhashtbl;
    }
    return sdirhashtbl;
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
	log_error( db_name, "upd_hashtable: read failed: %s\n",
							g10_errstr(rc) );
	return rc;
    }

    item = rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item ) { /* insert a new item into the hash table */
	rec.r.htbl.item[msb % ITEMS_PER_HTBL_RECORD] = newrecnum;
	rc = tdbio_write_record( &rec );
	if( rc ) {
	    log_error( db_name, "upd_hashtable: write htbl failed: %s\n",
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
			log_error( "scan keyhashtbl read hlst failed: %s\n",
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
	else if( rec.rectype == RECTYPE_KEY
		 || rec.rectype == RECTYPE_DIR
		 || rec.rectype == RECTYPE_SDIR ) { /* insert a list record */
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
	log_error( db_name, "drop_from_hashtable: read failed: %s\n",
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
	    log_error( db_name, "drop_from_hashtable: write htbl failed: %s\n",
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
			log_error( db_name, "drop_from_hashtable: write htbl failed: %s\n",
									g10_errstr(rc) );
		    return rc;
		}
	    }
	    if( rec.r.hlst.next ) {
		rc = tdbio_read_record( rec.r.hlst.next,
						   &rec, RECTYPE_HLST);
		if( rc ) {
		    log_error( "scan keyhashtbl read hlst failed: %s\n",
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
	log_error( db_name, "lookup_hashtable failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    item = rec->r.htbl.item[msb % ITEMS_PER_HTBL_RECORD];
    if( !item )
	return -1; /* not found */

    rc = tdbio_read_record( item, rec, 0 );
    if( rc ) {
	log_error( db_name, "hashtable read failed: %s\n", g10_errstr(rc) );
	return rc;
    }
    if( rec->rectype == RECTYPE_HTBL ) {
	hashrec = item;
	level++;
	if( level >= keylen ) {
	    log_error( db_name, "hashtable has invalid indirections\n");
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
 * Update the key hashtbl or create the table if it does not exist
 */
static int
update_keyhashtbl( TRUSTREC *kr )
{
    return upd_hashtable( get_keyhashrec(),
			  kr->r.key.fingerprint,
			  kr->r.key.fingerprint_len, kr->recnum );
}

/****************
 * Update the shadow dir hashtbl or create the table if it does not exist
 */
static int
update_sdirhashtbl( TRUSTREC *sr )
{
    byte key[8];

    u32tobuf( key   , sr->r.sdir.keyid[0] );
    u32tobuf( key+4 , sr->r.sdir.keyid[1] );
    return upd_hashtable( get_sdirhashrec(), key, 8, sr->recnum );
}

/****************
 * Drop the records from the key-hashtbl
 */
static int
drop_from_keyhashtbl( TRUSTREC *kr )
{
    return drop_from_hashtable( get_keyhashrec(),
				kr->r.key.fingerprint,
				kr->r.key.fingerprint_len, kr->recnum );
}

/****************
 * Drop record drom the shadow dir hashtbl
 */
static int
drop_from_sdirhashtbl( TRUSTREC *sr )
{
    byte key[8];

    u32tobuf( key   , sr->r.sdir.keyid[0] );
    u32tobuf( key+4 , sr->r.sdir.keyid[1] );
    return drop_from_hashtable( get_sdirhashrec(), key, 8, sr->recnum );
}




void
tdbio_dump_record( TRUSTREC *rec, FILE *fp  )
{
    int i;
    ulong rnum = rec->recnum;
    byte *p;

    fprintf(fp, "rec %5lu, ", rnum );

    switch( rec->rectype ) {
      case 0: fprintf(fp, "blank\n");
	break;
      case RECTYPE_VER: fprintf(fp,
	    "version, kd=%lu, sd=%lu, free=%lu, m/c/d=%d/%d/%d down=%s",
	    rec->r.ver.keyhashtbl, rec->r.ver.sdirhashtbl,
				   rec->r.ver.firstfree,
				   rec->r.ver.marginals,
				   rec->r.ver.completes,
				   rec->r.ver.cert_depth,
				   strtimestamp(rec->r.ver.mod_down) );
	    fprintf(fp, ", up=%s\n", strtimestamp(rec->r.ver.mod_up) );
	break;
      case RECTYPE_FREE: fprintf(fp, "free, next=%lu\n", rec->r.free.next );
	break;
      case RECTYPE_DIR:
	fprintf(fp, "dir %lu, keys=%lu, uids=%lu, t=%02x",
		    rec->r.dir.lid,
		    rec->r.dir.keylist,
		    rec->r.dir.uidlist,
		    rec->r.dir.ownertrust );
	if( rec->r.dir.valcheck )
	    fprintf( fp, ", v=%02x/%s", rec->r.dir.validity,
					strtimestamp(rec->r.dir.valcheck) );
	if( rec->r.dir.checkat )
	    fprintf( fp, ", a=%s", strtimestamp(rec->r.dir.checkat) );
	if( rec->r.dir.dirflags & DIRF_CHECKED ) {
	    if( rec->r.dir.dirflags & DIRF_VALID )
		fputs(", valid", fp );
	    if( rec->r.dir.dirflags & DIRF_EXPIRED )
		fputs(", expired", fp );
	    if( rec->r.dir.dirflags & DIRF_REVOKED )
		fputs(", revoked", fp );
	    if( rec->r.dir.dirflags & DIRF_NEWKEYS )
		fputs(", newkeys", fp );
	}
	putc('\n', fp);
	break;
      case RECTYPE_KEY:
	fprintf(fp, "key %lu, n=%lu a=%d ",
		   rec->r.key.lid,
		   rec->r.key.next,
		   rec->r.key.pubkey_algo );
	for(i=0; i < rec->r.key.fingerprint_len; i++ )
	    fprintf(fp, "%02X", rec->r.key.fingerprint[i] );
	if( rec->r.key.keyflags & KEYF_CHECKED ) {
	    if( rec->r.key.keyflags & KEYF_VALID )
		fputs(", valid", fp );
	    if( rec->r.key.keyflags & KEYF_EXPIRED )
		fputs(", expired", fp );
	    if( rec->r.key.keyflags & KEYF_REVOKED )
		fputs(", revoked", fp );
	}
	putc('\n', fp);
	break;
      case RECTYPE_UID:
	fprintf(fp, "uid %lu, next=%lu, pref=%lu, sig=%lu, hash=%02X%02X",
		    rec->r.uid.lid,
		    rec->r.uid.next,
		    rec->r.uid.prefrec,
		    rec->r.uid.siglist,
		    rec->r.uid.namehash[18], rec->r.uid.namehash[19]);
	fprintf( fp, ", v=%02x", rec->r.uid.validity );
	if( rec->r.uid.uidflags & UIDF_CHECKED ) {
	    if( rec->r.uid.uidflags & UIDF_VALID )
		fputs(", valid", fp );
	    if( rec->r.uid.uidflags & UIDF_REVOKED )
		fputs(", revoked", fp );
	}
	putc('\n', fp);
	break;
      case RECTYPE_PREF:
	fprintf(fp, "pref %lu, next=%lu,",
		    rec->r.pref.lid, rec->r.pref.next);
	for(i=0,p=rec->r.pref.data; i < ITEMS_PER_PREF_RECORD; i+=2,p+=2 ) {
	    if( *p )
		fprintf(fp, " %c%d", *p == PREFTYPE_SYM    ? 'S' :
				     *p == PREFTYPE_HASH   ? 'H' :
				     *p == PREFTYPE_COMPR  ? 'Z' : '?', p[1]);
	}
	putc('\n', fp);
	break;
      case RECTYPE_SIG:
	fprintf(fp, "sig %lu, next=%lu,",
			 rec->r.sig.lid, rec->r.sig.next );
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    if( rec->r.sig.sig[i].lid ) {
		fprintf(fp, " %lu:", rec->r.sig.sig[i].lid );
		if( rec->r.sig.sig[i].flag & SIGF_CHECKED ) {
		    fprintf(fp,"%c%c%c",
		       (rec->r.sig.sig[i].flag & SIGF_VALID)   ? 'V':
		       (rec->r.sig.sig[i].flag & SIGF_IGNORED) ? 'I':'-',
		       (rec->r.sig.sig[i].flag & SIGF_EXPIRED) ? 'E':'-',
		       (rec->r.sig.sig[i].flag & SIGF_REVOKED) ? 'R':'-');
		}
		else if( rec->r.sig.sig[i].flag & SIGF_NOPUBKEY)
		    fputs("?--", fp);
		else
		    fputs("---", fp);
	    }
	}
	putc('\n', fp);
	break;
      case RECTYPE_SDIR:
	fprintf(fp, "sdir %lu, keyid=%08lX%08lX, algo=%d, hint=%lu\n",
		    rec->r.sdir.lid,
		    (ulong)rec->r.sdir.keyid[0],
		    (ulong)rec->r.sdir.keyid[1],
		    rec->r.sdir.pubkey_algo,
		    (ulong)rec->r.sdir.hintlist );
	break;
      case RECTYPE_CACH:
	fprintf(fp, "cach\n");
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
	p += 2; /* skip "pgp" */
	rec->r.ver.version  = *p++;
	rec->r.ver.marginals = *p++;
	rec->r.ver.completes = *p++;
	rec->r.ver.cert_depth = *p++;
	p += 4; /* lock flags */
	rec->r.ver.created  = buftoulong(p); p += 4;
	rec->r.ver.mod_down = buftoulong(p); p += 4;
	rec->r.ver.mod_up   = buftoulong(p); p += 4;
	rec->r.ver.keyhashtbl=buftoulong(p); p += 4;
	rec->r.ver.firstfree =buftoulong(p); p += 4;
	rec->r.ver.sdirhashtbl =buftoulong(p); p += 4;
	if( recnum ) {
	    log_error( _("%s: version record with recnum %lu\n"), db_name,
							     (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	else if( rec->r.ver.version != 2 ) {
	    log_error( _("%s: invalid file version %d\n"), db_name,
							rec->r.ver.version );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_FREE:
	rec->r.free.next  = buftoulong(p); p += 4;
	break;
      case RECTYPE_DIR:   /*directory record */
	rec->r.dir.lid	    = buftoulong(p); p += 4;
	rec->r.dir.keylist  = buftoulong(p); p += 4;
	rec->r.dir.uidlist  = buftoulong(p); p += 4;
	rec->r.dir.cacherec = buftoulong(p); p += 4;
	rec->r.dir.ownertrust = *p++;
	rec->r.dir.dirflags   = *p++;
	rec->r.dir.validity   = *p++;
	rec->r.dir.valcheck   = buftoulong(p); p += 4;
	rec->r.dir.checkat    = buftoulong(p); p += 4;
	switch( rec->r.dir.validity ) {
	  case 0:
	  case TRUST_UNDEFINED:
	  case TRUST_NEVER:
	  case TRUST_MARGINAL:
	  case TRUST_FULLY:
	  case TRUST_ULTIMATE:
	    break;
	  default:
	    log_info("lid %lu: invalid validity value - cleared\n", recnum);
	}
	if( rec->r.dir.lid != recnum ) {
	    log_error( "%s: dir LID != recnum (%lu,%lu)\n",
			      db_name, rec->r.dir.lid, (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_KEY:   /* public key record */
	rec->r.key.lid	    = buftoulong(p); p += 4;
	rec->r.key.next     = buftoulong(p); p += 4;
	p += 7;
	rec->r.key.keyflags = *p++;
	rec->r.key.pubkey_algo = *p++;
	rec->r.key.fingerprint_len = *p++;
	if( rec->r.key.fingerprint_len < 1 || rec->r.key.fingerprint_len > 20 )
	    rec->r.key.fingerprint_len = 20;
	memcpy( rec->r.key.fingerprint, p, 20);
	break;
      case RECTYPE_UID:   /* user id record */
	rec->r.uid.lid	    = buftoulong(p); p += 4;
	rec->r.uid.next     = buftoulong(p); p += 4;
	rec->r.uid.prefrec  = buftoulong(p); p += 4;
	rec->r.uid.siglist  = buftoulong(p); p += 4;
	rec->r.uid.uidflags = *p++;
	rec->r.uid.validity   = *p++;
	switch( rec->r.uid.validity ) {
	  case 0:
	  case TRUST_UNDEFINED:
	  case TRUST_NEVER:
	  case TRUST_MARGINAL:
	  case TRUST_FULLY:
	  case TRUST_ULTIMATE:
	    break;
	  default:
	    log_info("lid %lu: invalid validity value - cleared\n", recnum);
	}
	memcpy( rec->r.uid.namehash, p, 20);
	break;
      case RECTYPE_PREF:  /* preference record */
	rec->r.pref.lid     = buftoulong(p); p += 4;
	rec->r.pref.next    = buftoulong(p); p += 4;
	memcpy( rec->r.pref.data, p, 30 );
	break;
      case RECTYPE_SIG:
	rec->r.sig.lid	   = buftoulong(p); p += 4;
	rec->r.sig.next    = buftoulong(p); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    rec->r.sig.sig[i].lid  = buftoulong(p); p += 4;
	    rec->r.sig.sig[i].flag = *p++;
	}
	break;
      case RECTYPE_SDIR:   /* shadow directory record */
	rec->r.sdir.lid     = buftoulong(p); p += 4;
	rec->r.sdir.keyid[0]= buftou32(p); p += 4;
	rec->r.sdir.keyid[1]= buftou32(p); p += 4;
	rec->r.sdir.pubkey_algo = *p++;
	p += 3;
	rec->r.sdir.hintlist = buftoulong(p);
	if( rec->r.sdir.lid != recnum ) {
	    log_error( "%s: sdir LID != recnum (%lu,%lu)\n",
			       db_name, rec->r.sdir.lid, (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_CACH:   /* cache record */
	rec->r.cache.lid    = buftoulong(p); p += 4;
	memcpy(rec->r.cache.blockhash, p, 20); p += 20;
	rec->r.cache.trustlevel = *p++;
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
	p += 4; /* skip lock flags */
	ulongtobuf(p, rec->r.ver.created); p += 4;
	ulongtobuf(p, rec->r.ver.mod_down); p += 4;
	ulongtobuf(p, rec->r.ver.mod_up); p += 4;
	ulongtobuf(p, rec->r.ver.keyhashtbl); p += 4;
	ulongtobuf(p, rec->r.ver.firstfree ); p += 4;
	ulongtobuf(p, rec->r.ver.sdirhashtbl ); p += 4;
	break;

      case RECTYPE_FREE:
	ulongtobuf(p, rec->r.free.next); p += 4;
	break;

      case RECTYPE_DIR:   /*directory record */
	ulongtobuf(p, rec->r.dir.lid); p += 4;
	ulongtobuf(p, rec->r.dir.keylist); p += 4;
	ulongtobuf(p, rec->r.dir.uidlist); p += 4;
	ulongtobuf(p, rec->r.dir.cacherec); p += 4;
	*p++ = rec->r.dir.ownertrust;
	*p++ = rec->r.dir.dirflags;
	*p++ = rec->r.dir.validity;
	ulongtobuf(p, rec->r.dir.valcheck); p += 4;
	ulongtobuf(p, rec->r.dir.checkat); p += 4;
	assert( rec->r.dir.lid == recnum );
	break;

      case RECTYPE_KEY:
	ulongtobuf(p, rec->r.key.lid); p += 4;
	ulongtobuf(p, rec->r.key.next); p += 4;
	p += 7;
	*p++ = rec->r.key.keyflags;
	*p++ = rec->r.key.pubkey_algo;
	*p++ = rec->r.key.fingerprint_len;
	memcpy( p, rec->r.key.fingerprint, 20); p += 20;
	break;

      case RECTYPE_UID:   /* user id record */
	ulongtobuf(p, rec->r.uid.lid); p += 4;
	ulongtobuf(p, rec->r.uid.next); p += 4;
	ulongtobuf(p, rec->r.uid.prefrec); p += 4;
	ulongtobuf(p, rec->r.uid.siglist); p += 4;
	*p++ = rec->r.uid.uidflags;
	*p++ = rec->r.uid.validity;
	memcpy( p, rec->r.uid.namehash, 20 ); p += 20;
	break;

      case RECTYPE_PREF:
	ulongtobuf(p, rec->r.pref.lid); p += 4;
	ulongtobuf(p, rec->r.pref.next); p += 4;
	memcpy( p, rec->r.pref.data, 30 );
	break;

      case RECTYPE_SIG:
	ulongtobuf(p, rec->r.sig.lid); p += 4;
	ulongtobuf(p, rec->r.sig.next); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    ulongtobuf(p, rec->r.sig.sig[i].lid); p += 4;
	    *p++ = rec->r.sig.sig[i].flag;
	}
	break;

      case RECTYPE_SDIR:
	ulongtobuf( p, rec->r.sdir.lid); p += 4;
	u32tobuf( p, rec->r.sdir.keyid[0] ); p += 4;
	u32tobuf( p, rec->r.sdir.keyid[1] ); p += 4;
	*p++ = rec->r.sdir.pubkey_algo;
	p += 3;
	ulongtobuf( p, rec->r.sdir.hintlist );
	break;

      case RECTYPE_CACH:
	ulongtobuf(p, rec->r.cache.lid); p += 4;
	memcpy(p, rec->r.cache.blockhash, 20); p += 20;
	*p++ = rec->r.cache.trustlevel;
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

      default:
	BUG();
    }

    rc = put_record_into_cache( recnum, buf );
    if( rc )
	;
    else if( rec->rectype == RECTYPE_KEY )
	rc = update_keyhashtbl( rec );
    else if( rec->rectype == RECTYPE_SDIR )
	rc = update_sdirhashtbl( rec );

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
    else if( rec.rectype == RECTYPE_KEY )
	rc = drop_from_keyhashtbl( &rec );
    else if( rec.rectype == RECTYPE_SDIR )
	rc = drop_from_sdirhashtbl( &rec );

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



/****************
 * Search the trustdb for a key which matches PK and return the dir record
 * The local_id of PK is set to the correct value
 */
int
tdbio_search_dir_bypk( PKT_public_key *pk, TRUSTREC *rec )
{
    byte fingerprint[MAX_FINGERPRINT_LEN];
    size_t fingerlen;
    u32 keyid[2];
    int rc;

    keyid_from_pk( pk, keyid );
    fingerprint_from_pk( pk, fingerprint, &fingerlen );
    rc = tdbio_search_dir_byfpr( fingerprint, fingerlen,
				 pk->pubkey_algo, rec );

    if( !rc ) {
	if( pk->local_id && pk->local_id != rec->recnum )
	    log_error("%s: found record, but LID from memory does "
		       "not match recnum (%lu,%lu)\n",
			    db_name,  pk->local_id, rec->recnum );
	pk->local_id = rec->recnum;
    }
    return rc;
}


static int
cmp_krec_fpr( void *dataptr, const TRUSTREC *rec )
{
    const struct cmp_krec_fpr_struct *d = dataptr;

    return rec->rectype == RECTYPE_KEY
	   && ( !d->pubkey_algo || rec->r.key.pubkey_algo == d->pubkey_algo )
	   && rec->r.key.fingerprint_len == d->fprlen
	   && !memcmp( rec->r.key.fingerprint, d->fpr, d->fprlen );
}

int
tdbio_search_dir_byfpr( const byte *fingerprint, size_t fingerlen,
			int pubkey_algo, TRUSTREC *rec )
{
    struct cmp_krec_fpr_struct cmpdata;
    ulong recnum;
    int rc;

    assert( fingerlen == 20 || fingerlen == 16 );

    /* locate the key using the hash table */
    cmpdata.pubkey_algo = pubkey_algo;
    cmpdata.fpr = fingerprint;
    cmpdata.fprlen = fingerlen;
    rc = lookup_hashtable( get_keyhashrec(), fingerprint, fingerlen,
			   cmp_krec_fpr, &cmpdata, rec );
    if( !rc ) {
	recnum = rec->r.key.lid;
	/* Now read the dir record */
	rc = tdbio_read_record( recnum, rec, RECTYPE_DIR);
	if( rc )
	    log_error("%s: can't read dirrec %lu: %s\n",
				     db_name, recnum, g10_errstr(rc) );
    }
    return rc;
}



static int
cmp_sdir( void *dataptr, const TRUSTREC *rec )
{
    const struct cmp_xdir_struct *d = dataptr;

    return rec->rectype == RECTYPE_SDIR
	   && ( !d->pubkey_algo || rec->r.sdir.pubkey_algo == d->pubkey_algo )
	   && rec->r.sdir.keyid[0] == d->keyid[0]
	   && rec->r.sdir.keyid[1] == d->keyid[1];
}


int
tdbio_search_sdir( u32 *keyid, int pubkey_algo, TRUSTREC *rec )
{
    struct cmp_xdir_struct cmpdata;
    int rc;
    byte key[8];

    /* locate the shadow dir record using the hash table */
    u32tobuf( key   , keyid[0] );
    u32tobuf( key+4 , keyid[1] );
    cmpdata.pubkey_algo = pubkey_algo;
    cmpdata.keyid[0] = keyid[0];
    cmpdata.keyid[1] = keyid[1];
    rc = lookup_hashtable( get_sdirhashrec(), key, 8,
			   cmp_sdir, &cmpdata, rec );
    return rc;
}


void
tdbio_invalid(void)
{
    log_error(_(
	"the trustdb is corrupted; please run \"gpg --fix-trustdb\".\n") );
    g10_exit(2);
}


