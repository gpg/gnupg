/* trustdb.c
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
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"
#include "options.h"
#include "packet.h"
#include "main.h"
#include "i18n.h"
#include "tdbio.h"
#include "ttyio.h"

#if MAX_FINGERPRINT_LEN > 20
  #error Must change structure of trustdb
#endif

struct keyid_list {
    struct keyid_list *next;
    u32 keyid[2];
};

struct local_id_item {
    struct local_id_item *next;
    ulong lid;
    unsigned flag;
};

struct local_id_table {
    struct local_id_table *next; /* only used to keep a list of unused tables */
    struct local_id_item *items[16];
};


typedef struct local_id_table *LOCAL_ID_TABLE;


struct enum_cert_paths_ctx {
   int init;
   int idx;
};


struct recno_list_struct {
    struct recno_list_struct *next;
    ulong recno;
    int type;
};
typedef struct recno_list_struct *RECNO_LIST;



typedef struct trust_node *TN;
struct trust_node {
    TN	  back;  /* parent */
    TN	  list;  /* list of other node (should all be of the same type)*/
    TN	  next;  /* used to build the list */
    int   is_uid; /* set if this is an uid node */
    ulong lid;	 /* key or uid recordnumber */
    union {
	struct {
	    int ownertrust;
	    int validity;
	    /* helper */
	    int buckstop;
	} k;
	struct {
	    int marginal_count;
	    int fully_count;
	    int validity;
	} u;
    } n;
};


static TN used_tns;
static int alloced_tns;
static int max_alloced_tns;

static struct keyid_list *trusted_key_list;

static LOCAL_ID_TABLE new_lid_table(void);
static int ins_lid_table_item( LOCAL_ID_TABLE tbl, ulong lid, unsigned flag );
static int qry_lid_table_flag( LOCAL_ID_TABLE tbl, ulong lid, unsigned *flag );


static int propagate_validity( TN root, TN node,
			       int (*add_fnc)(ulong), unsigned *retflgs );

static void print_user_id( FILE *fp, const char *text, u32 *keyid );
static int do_check( TRUSTREC *drec, unsigned *trustlevel,
		     const char *nhash, int (*add_fnc)(ulong),
						unsigned *retflgs);
static int get_dir_record( PKT_public_key *pk, TRUSTREC *rec );
static int do_update_trust_record( KBNODE keyblock, TRUSTREC *drec,
				   int sigs_only, int *modified );
static int check_trust_record( TRUSTREC *drec, int sigs_only );
static void mark_fresh_keys(void);

/* a table used to keep track of ultimately trusted keys
 * which are the ones from our secrings and the trusted keys */
static LOCAL_ID_TABLE ultikey_table;


/* a table to keep track of newly importted keys.  This one is
 * create by the insert_trust_record function and from time to time
 * used to verify key signature which have been done with these new keys */
static LOCAL_ID_TABLE fresh_imported_keys;
static int fresh_imported_keys_count;
#define FRESH_KEY_CHECK_THRESHOLD 200

/* list of unused lid items and tables */
static LOCAL_ID_TABLE unused_lid_tables;
static struct local_id_item *unused_lid_items;

static struct {
    int init;
    int level;
    char *dbname;
} trustdb_args;


/**********************************************
 ***********  record read write  **************
 **********************************************/


/****************
 * Read a record but die if it does not exist
 */
static void
read_record( ulong recno, TRUSTREC *rec, int rectype )
{
    int rc = tdbio_read_record( recno, rec, rectype );
    if( !rc )
	return;
    log_error(_("trust record %lu, req type %d: read failed: %s\n"),
				    recno, rectype,  g10_errstr(rc) );
    tdbio_invalid();
}


/****************
 * Wirte a record but die on error
 */
static void
write_record( TRUSTREC *rec )
{
    int rc = tdbio_write_record( rec );
    if( !rc )
	return;
    log_error(_("trust record %lu, type %d: write failed: %s\n"),
			    rec->recnum, rec->rectype, g10_errstr(rc) );
    tdbio_invalid();
}

/****************
 * Delete a record but die on error
 */
static void
delete_record( ulong recno )
{
    int rc = tdbio_delete_record( recno );
    if( !rc )
	return;
    log_error(_("trust record %lu: delete failed: %s\n"),
					      recno, g10_errstr(rc) );
    tdbio_invalid();
}

/****************
 * sync the db
 */
static void
do_sync(void)
{
    int rc = tdbio_sync();
    if( !rc )
	return;
    log_error(_("trustdb: sync failed: %s\n"), g10_errstr(rc) );
    g10_exit(2);
}



/**********************************************
 *****************  helpers  ******************
 **********************************************/


static LOCAL_ID_TABLE
new_lid_table(void)
{
    LOCAL_ID_TABLE a;

    a = unused_lid_tables;
    if( a ) {
	unused_lid_tables = a->next;
	memset( a, 0, sizeof *a );
    }
    else
	a = m_alloc_clear( sizeof *a );
    return a;
}

#if 0
static void
release_lid_table( LOCAL_ID_TABLE tbl )
{
    struct local_id_item *a, *a2;
    int i;

    for(i=0; i < 16; i++ ) {
	for(a=tbl->items[i]; a; a = a2 ) {
	    a2 = a->next;
	    a->next = unused_lid_items;
	    unused_lid_items = a;
	}
    }
    tbl->next = unused_lid_tables;
    unused_lid_tables = tbl;
}
#endif


/****************
 * Remove all items from a LID table
 */
static void
clear_lid_table( LOCAL_ID_TABLE tbl )
{
    struct local_id_item *a, *a2;
    int i;

    for(i=0; i < 16; i++ ) {
	for(a=tbl->items[i]; a; a = a2 ) {
	    a2 = a->next;
	    a->next = unused_lid_items;
	    unused_lid_items = a;
	}
	tbl->items[i] = NULL;
    }
}


/****************
 * Add a new item to the table or return 1 if we already have this item
 */
static int
ins_lid_table_item( LOCAL_ID_TABLE tbl, ulong lid, unsigned flag )
{
    struct local_id_item *a;

    for( a = tbl->items[lid & 0x0f]; a; a = a->next )
	if( a->lid == lid )
	    return 1;
    a = unused_lid_items;
    if( a )
	unused_lid_items = a->next;
    else
	a = m_alloc( sizeof *a );
    a->lid = lid;
    a->flag = flag;
    a->next = tbl->items[lid & 0x0f];
    tbl->items[lid & 0x0f] = a;
    return 0;
}

static int
qry_lid_table_flag( LOCAL_ID_TABLE tbl, ulong lid, unsigned *flag )
{
    struct local_id_item *a;

    for( a = tbl->items[lid & 0x0f]; a; a = a->next )
	if( a->lid == lid ) {
	    if( flag )
		*flag = a->flag;
	    return 0;
	}
    return -1;
}


static TN
new_tn(void)
{
    TN t;

    if( used_tns ) {
	t = used_tns;
	used_tns = t->next;
	memset( t, 0, sizeof *t );
    }
    else
	t = m_alloc_clear( sizeof *t );
    if( ++alloced_tns > max_alloced_tns )
	max_alloced_tns = alloced_tns;
    return t;
}


static void
release_tn( TN t )
{
    if( t ) {
	t->next = used_tns;
	used_tns = t;
	alloced_tns--;
    }
}


static void
release_tn_tree( TN kr )
{
    TN	kr2;

    for( ; kr; kr = kr2 ) {
	release_tn_tree( kr->list );
	kr2 = kr->next;
	release_tn( kr );
    }
}




/**********************************************
 ****** access by LID and other helpers *******
 **********************************************/

/****************
 * Return the keyid from the primary key identified by LID.
 */
int
keyid_from_lid( ulong lid, u32 *keyid )
{
    TRUSTREC rec;
    int rc;

    init_trustdb();
    keyid[0] = keyid[1] = 0;
    rc = tdbio_read_record( lid, &rec, 0 );
    if( rc ) {
	log_error(_("error reading dir record for LID %lu: %s\n"),
						    lid, g10_errstr(rc));
	return G10ERR_TRUSTDB;
    }
    if( rec.rectype == RECTYPE_SDIR )
	return 0;
    if( rec.rectype != RECTYPE_DIR ) {
	log_error(_("lid %lu: expected dir record, got type %d\n"),
						    lid, rec.rectype );
	return G10ERR_TRUSTDB;
    }
    if( !rec.r.dir.keylist ) {
	log_error(_("no primary key for LID %lu\n"), lid );
	return G10ERR_TRUSTDB;
    }
    rc = tdbio_read_record( rec.r.dir.keylist, &rec, RECTYPE_KEY );
    if( rc ) {
	log_error(_("error reading primary key for LID %lu: %s\n"),
						    lid, g10_errstr(rc));
	return G10ERR_TRUSTDB;
    }
    keyid_from_fingerprint( rec.r.key.fingerprint, rec.r.key.fingerprint_len,
			    keyid );

    return 0;
}


ulong
lid_from_keyblock( KBNODE keyblock )
{
    KBNODE node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    PKT_public_key *pk;
    if( !node )
	BUG();
    pk = node->pkt->pkt.public_key;
    if( !pk->local_id ) {
	TRUSTREC rec;
	init_trustdb();

	get_dir_record( pk, &rec );
    }
    return pk->local_id;
}


static int
get_dir_record( PKT_public_key *pk, TRUSTREC *rec )
{
    int rc=0;

    if( pk->local_id ) {
	read_record( pk->local_id, rec, RECTYPE_DIR );
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=tdbio_search_dir_bypk( pk, rec )) && rc != -1 )
	    log_error(_("get_dir_record: search_record failed: %s\n"),
							    g10_errstr(rc));
    }
    return rc;
}

static ulong
lid_from_keyid_no_sdir( u32 *keyid )
{
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    TRUSTREC rec;
    ulong lid = 0;
    int rc;

    rc = get_pubkey( pk, keyid );
    if( !rc ) {
	if( pk->local_id )
	    lid = pk->local_id;
	else {
	    rc = tdbio_search_dir_bypk( pk, &rec );
	    if( !rc )
		lid = rec.recnum;
	}
    }
    free_public_key( pk );
    return lid;
}



/***********************************************
 *************	Initialization	****************
 ***********************************************/

void
register_trusted_key( const char *string )
{
    u32 keyid[2];
    struct keyid_list *r;

    if( classify_user_id( string, keyid, NULL, NULL, NULL ) != 11 ) {
        log_error(_("'%s' is not a valid long keyID\n"), string );
        return;
    }

    for( r = trusted_key_list; r; r = r->next )
        if( r->keyid[0] == keyid[0] && r->keyid[1] == keyid[1] )
            return;
    r = m_alloc( sizeof *r );
    r->keyid[0] = keyid[0];
    r->keyid[1] = keyid[1];
    r->next = trusted_key_list;
    trusted_key_list = r;
}


static void
add_ultimate_key( PKT_public_key *pk, u32 *keyid )
{
    int rc;

    /* first make sure that the pubkey is in the trustdb */
    rc = query_trust_record( pk );
    if( rc == -1 && opt.dry_run )
	return;
    if( rc == -1 ) { /* put it into the trustdb */
        rc = insert_trust_record_by_pk( pk );
        if( rc ) {
            log_error(_("key %08lX: can't put it into the trustdb\n"),
                      (ulong)keyid[1] );
            return;
        }
    }
    else if( rc ) {
        log_error(_("key %08lX: query record failed\n"), (ulong)keyid[1] );
        return;
    }

    if( DBG_TRUST )
        log_debug("key %08lX.%lu: stored into ultikey_table\n",
                  (ulong)keyid[1], pk->local_id );

    if( ins_lid_table_item( ultikey_table, pk->local_id, 0 ) )
        log_error(_("key %08lX: already in trusted key table\n"),
                  (ulong)keyid[1]);
    else if( opt.verbose > 1 )
        log_info(_("key %08lX: accepted as trusted key.\n"),
                 (ulong)keyid[1]);

}

/****************
 * Verify that all our public keys are in the trustdb.
 */
static int
verify_own_keys(void)
{
    int rc;
    void *enum_context = NULL;
    PKT_secret_key *sk = m_alloc_clear( sizeof *sk );
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    u32 keyid[2];
    struct keyid_list *kl;


    /* put the trusted keys into the ultikey table */
    for( kl = trusted_key_list; kl; kl = kl->next ) {
        keyid[0] = kl->keyid[0];
        keyid[1] = kl->keyid[1];
        /* get the public key */
        memset( pk, 0, sizeof *pk );
        rc = get_pubkey( pk, keyid );
        if( rc ) {
            log_info(_("key %08lX: no public key for trusted key - skipped\n"),
                                                            (ulong)keyid[1] );
        }
        else {
            add_ultimate_key( pk, keyid );
            release_public_key_parts( pk );
        }
    }

    /* And now add all secret keys to the ultikey table */
    while( !(rc=enum_secret_keys( &enum_context, sk, 0 ) ) ) {
	int have_pk = 0;

	keyid_from_sk( sk, keyid );

	if( DBG_TRUST )
	    log_debug("key %08lX: checking secret key\n", (ulong)keyid[1] );

	if( !opt.quiet && is_secret_key_protected( sk ) < 1 )
	    log_info(_("NOTE: secret key %08lX is NOT protected.\n"),
							    (ulong)keyid[1] );

        for( kl = trusted_key_list; kl; kl = kl->next ) {
            if( kl->keyid[0] == keyid[0] && kl->keyid[1] == keyid[1] )
                goto skip; /* already in trusted key table */
        }

	/* see whether we can access the public key of this secret key */
	memset( pk, 0, sizeof *pk );
	rc = get_pubkey( pk, keyid );
	if( rc ) {
	    log_info(_("key %08lX: secret key without public key - skipped\n"),
							    (ulong)keyid[1] );
	    goto skip;
	}
	have_pk=1;

	if( cmp_public_secret_key( pk, sk ) ) {
	    log_info(_("key %08lX: secret and public key don't match\n"),
							    (ulong)keyid[1] );
	    goto skip;
	}

	add_ultimate_key( pk, keyid );

      skip:
	release_secret_key_parts( sk );
	if( have_pk )
	    release_public_key_parts( pk );
    }
    if( rc != -1 )
	log_error(_("enumerate secret keys failed: %s\n"), g10_errstr(rc) );
    else
	rc = 0;

    /* release the trusted keyid table */
    {   struct keyid_list *kl2;
        for( kl = trusted_key_list; kl; kl = kl2 ) {
            kl2 = kl->next;
            m_free( kl );
        }
        trusted_key_list = NULL;
    }

    enum_secret_keys( &enum_context, NULL, 0 ); /* free context */
    free_secret_key( sk );
    free_public_key( pk );
    return rc;
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

    if( !ultikey_table )
	ultikey_table = new_lid_table();

    if( !level || level==1 ) {
	rc = tdbio_set_dbname( dbname, !!level );
	if( !rc ) {
	    if( !level )
		return;

	    /* verify that our own keys are in the trustDB
	     * or move them to the trustdb. */
	    rc = verify_own_keys();

	    /* should we check whether there is no other ultimately trusted
	     * key in the database? */
	}
    }
    else
	BUG();
    if( rc )
	log_fatal("can't init trustdb: %s\n", g10_errstr(rc) );
}



/****************
 * This function should be called in certain cases to sync the internal state
 * of the trustdb with the file image.	Currently it is needed after
 * a sequence of insert_trust_record() calls.
 */
void
sync_trustdb()
{
    if( fresh_imported_keys && fresh_imported_keys_count )
	mark_fresh_keys();
}



/***********************************************
 *************	Print helpers	****************
 ***********************************************/
static void
print_user_id( FILE *fp, const char *text, u32 *keyid )
{
    char *p;
    size_t n;

    p = get_user_id( keyid, &n );
    if( fp ) {
	fprintf( fp, "%s \"", text );
	print_utf8_string( fp, p, n );
	putc('\"', fp);
	putc('\n', fp);
    }
    else {
	tty_printf( "%s \"", text );
	tty_print_utf8_string( p, n );
	tty_printf( "\"\n" );
    }
    m_free(p);
}



/****************
 * This function returns a letter for a trustvalue  Trust flags
 * are ignore.
 */
int
trust_letter( unsigned value )
{
    switch( (value & TRUST_MASK) ) {
      case TRUST_UNKNOWN:   return '-';
      case TRUST_EXPIRED:   return 'e';
      case TRUST_UNDEFINED: return 'q';
      case TRUST_NEVER:     return 'n';
      case TRUST_MARGINAL:  return 'm';
      case TRUST_FULLY:     return 'f';
      case TRUST_ULTIMATE:  return 'u';
      default:		    return  0 ;
    }
}


#if 0
static void
print_path( int pathlen, TN ME .........., FILE *fp, ulong highlight )
{
    int rc, c, i;
    u32 keyid[2];
    char *p;
    size_t n;

    for( i = 0; i < pathlen; i++ )  {
	if( highlight )
	    fputs(highlight == path[i].lid? "* ":"  ", fp );
	rc = keyid_from_lid( path[i].lid, keyid );
	if( rc )
	    fprintf(fp, "????????.%lu:", path[i].lid );
	else
	    fprintf(fp,"%08lX.%lu:", (ulong)keyid[1], path[i].lid );
	c = trust_letter(path[i].otrust);
	if( c )
	    putc( c, fp );
	else
	    fprintf( fp, "%02x", path[i].otrust );
	putc('/', fp);
	c = trust_letter(path[i].trust);
	if( c )
	    putc( c, fp );
	else
	    fprintf( fp, "%02x", path[i].trust );
	putc(' ', fp);
	p = get_user_id( keyid, &n );
	putc(' ', fp);
	putc('\"', fp);
	print_utf8_string( fp, p, n > 40? 40:n );
	putc('\"', fp);
	m_free(p);
	putc('\n', fp );
    }
}
#endif


static void
print_default_uid( FILE *fp, ulong lid )
{
    u32 keyid[2];

    if( !keyid_from_lid( lid, keyid ) )
	print_user_id( fp, "", keyid );
}


static void
print_uid_from_keyblock( FILE *fp, KBNODE keyblock, ulong urecno )
{
    TRUSTREC urec;
    KBNODE node;
    byte uhash[20];

    read_record( urecno, &urec, RECTYPE_UID );
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uidpkt = node->pkt->pkt.user_id;

	    if( uidpkt->photo )
		rmd160_hash_buffer( uhash, uidpkt->photo, uidpkt->photolen );
	    else
		rmd160_hash_buffer( uhash, uidpkt->name, uidpkt->len );
	    if( !memcmp( uhash, urec.r.uid.namehash, 20 ) ) {
		print_string( fp,  uidpkt->name, uidpkt->len, ':' );
		return;
	    }
	}
    }

    fputs("[?]", fp );
}



static void
dump_tn_tree( FILE *fp, int level, TN tree )
{
    TN kr, ur;

    for( kr=tree; kr; kr = kr->next ) {
	if( fp ) {
	    fprintf( fp, "%*s", level*4, "" );
	    fprintf( fp, "K%lu(ot=%d,val=%d)  ", kr->lid,
					     kr->n.k.ownertrust,
					     kr->n.k.validity  );
	}
	else {
	    tty_printf("%*s", level*4, "" );
	    tty_printf("K%lu(ot=%d,val=%d)  ", kr->lid,
					     kr->n.k.ownertrust,
					     kr->n.k.validity  );
	}
	print_default_uid( fp, kr->lid );
	for( ur=kr->list; ur; ur = ur->next ) {
	    if( fp ) {
		fprintf(fp, "%*s  ", level*4, "" );
		fprintf(fp, "U%lu(mc=%d,fc=%d,val=%d)\n", ur->lid,
						     ur->n.u.marginal_count,
						     ur->n.u.fully_count,
						     ur->n.u.validity
						);
	    }
	    else {
		tty_printf("%*s  ", level*4, "" );
		tty_printf("U%lu(mc=%d,fc=%d,val=%d)\n", ur->lid,
						     ur->n.u.marginal_count,
						     ur->n.u.fully_count,
						     ur->n.u.validity
						);
	    }
	    dump_tn_tree( fp, level+1, ur->list );
	}
    }
}

/****************
 * Special version of dump_tn_tree, which prints it colon delimited.
 * Format:
 *   level:keyid:type:recno:ot:val:mc:cc:name:
 * With TYPE = U for a user ID
 *	       K for a key
 * The RECNO is either the one of the dir record or the one of the uid record.
 * OT is the the usual trust letter and only availabel on K lines.
 * VAL is the calcualted validity
 * MC is the marginal trust counter and only available on U lines
 * CC is the same for the complete count
 * NAME ist the username and only printed on U lines
 */
static void
dump_tn_tree_with_colons( int level, TN tree )
{
    TN kr, ur;

    for( kr=tree; kr; kr = kr->next ) {
	KBNODE kb = NULL;
	u32 kid[2];

	keyid_from_lid( kr->lid, kid );
	get_keyblock_bylid( &kb, kr->lid );

	printf( "%d:%08lX%08lX:K:%lu:%c:%c::::\n",
			level, (ulong)kid[0], (ulong)kid[1], kr->lid,
			trust_letter( kr->n.k.ownertrust ),
			trust_letter( kr->n.k.validity ) );
	for( ur=kr->list; ur; ur = ur->next ) {
	    printf( "%d:%08lX%08lX:U:%lu::%c:%d:%d:",
			level, (ulong)kid[0], (ulong)kid[1], ur->lid,
			trust_letter( kr->n.u.validity ),
			ur->n.u.marginal_count,
			ur->n.u.fully_count );
	    print_uid_from_keyblock( stdout, kb, ur->lid );
	    putchar(':');
	    putchar('\n');
	    dump_tn_tree_with_colons( level+1, ur->list );
	}
	release_kbnode( kb );
    }
}



/***********************************************
 *************	trustdb maintenance  ***********
 ***********************************************/

/****************
 * Create or update shadow dir record and return the LID of the record
 */
static ulong
create_shadow_dir( PKT_signature *sig )
{
    TRUSTREC sdir;
    int rc;

    /* first see whether we already have such a record */
    rc = tdbio_search_sdir( sig->keyid, sig->pubkey_algo, &sdir );
    if( rc && rc != -1 ) {
	log_error("tdbio_search_sdir failed: %s\n", g10_errstr(rc));
	tdbio_invalid();
    }
    if( rc == -1 ) { /* not found: create */
	memset( &sdir, 0, sizeof sdir );
	sdir.recnum = tdbio_new_recnum();
	sdir.rectype= RECTYPE_SDIR;
	sdir.r.sdir.lid = sdir.recnum;
	sdir.r.sdir.keyid[0] = sig->keyid[0];
	sdir.r.sdir.keyid[1] = sig->keyid[1];
	sdir.r.sdir.pubkey_algo = sig->pubkey_algo;
	write_record( &sdir );
    }
    return sdir.recnum;
}


static ulong
find_or_create_lid( PKT_signature *sig )
{
    ulong lid;

    lid = lid_from_keyid_no_sdir( sig->keyid );
    if( !lid )
	lid = create_shadow_dir( sig );
    return lid;
}



/****************
 * Check the validity of a key and calculate the keyflags
 * keynode points to
 * a node with a [sub]key.  mainkid has the key ID of the primary key
 * keyblock is the complete keyblock which is needed for signature
 * checking.  LID and PK is only used in verbose mode.
 */
static unsigned int
check_keybinding( KBNODE keyblock, KBNODE keynode, u32 *mainkid,
		  ulong lid, PKT_public_key *pk )
{
    KBNODE node;
    int keybind_seen = 0;
    int revoke_seen = 0;
    unsigned int keyflags=0;
    int is_main = (keynode->pkt->pkttype == PKT_PUBLIC_KEY);
    int rc;

    if( DBG_TRUST )
	log_debug("check_keybinding: %08lX.%lu\n",
			    (ulong)mainkid[1], lid );

    if( is_main ) {
	/* a primary key is always valid (user IDs are handled elsewhere)*/
	keyflags = KEYF_CHECKED | KEYF_VALID;
    }

    for( node=keynode->next; node; node = node->next ) {
	PKT_signature *sig;

	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* ready */
	if( node->pkt->pkttype != PKT_SIGNATURE )
	    continue; /* don't care about other packets */

	sig = node->pkt->pkt.signature;

	if( mainkid[0] != sig->keyid[0] || mainkid[1] != sig->keyid[1] )
	    continue; /* we only care about self-signatures */

	if( sig->sig_class == 0x18 && !keybind_seen && !is_main ) {
	    /* check until we find a valid keybinding */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info(_("key %08lX.%lu: Good subkey binding\n"),
				     (ulong)keyid_from_pk(pk,NULL), lid );
		keyflags |= KEYF_CHECKED | KEYF_VALID;
	    }
	    else {
		log_info(_(
		  "key %08lX.%lu: Invalid subkey binding: %s\n"),
		    (ulong)keyid_from_pk(pk,NULL), lid, g10_errstr(rc) );
		keyflags |= KEYF_CHECKED;
		keyflags &= ~KEYF_VALID;
	    }
	    keybind_seen = 1;
	}
	else if( sig->sig_class == 0x20 && !revoke_seen ) {
	    /* this is a key revocation certificate: check it */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info(_("key %08lX.%lu: Valid key revocation\n"),
				 (ulong)keyid_from_pk(pk, NULL), lid );
		keyflags |= KEYF_REVOKED;
	    }
	    else {
		log_info(_(
		  "key %08lX.%lu: Invalid key revocation: %s\n"),
		  (ulong)keyid_from_pk(pk,NULL), lid, g10_errstr(rc) );
	    }
	    revoke_seen = 1;
	}
	else if( sig->sig_class == 0x28 && !revoke_seen && !is_main ) {
	    /* this is a subkey revocation certificate: check it */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info(_(
			"key %08lX.%lu: Valid subkey revocation\n"),
			 (ulong)keyid_from_pk(pk,NULL), lid );
		keyflags |= KEYF_REVOKED;
	    }
	    else {
		log_info(_(
		  "key %08lX.%lu: Invalid subkey binding: %s\n"),
		  (ulong)keyid_from_pk(pk,NULL), lid, g10_errstr(rc) );
	    }
	    revoke_seen = 1;
	}
	/* Hmmm: should we handle direct key signatures here? */
    }

    return keyflags;
}


static ulong
make_key_records( KBNODE keyblock, ulong lid, u32 *keyid, int *mainrev )
{
    TRUSTREC *krecs, **kend, *k, *k2;
    KBNODE  node;
    PKT_public_key *pk;
    byte fpr[MAX_FINGERPRINT_LEN];
    size_t fprlen;
    ulong keyrecno;

    *mainrev = 0;
    krecs = NULL; kend = &krecs;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype != PKT_PUBLIC_KEY
	    && node->pkt->pkttype != PKT_PUBLIC_SUBKEY )
	    continue;
	pk = node->pkt->pkt.public_key;
	fingerprint_from_pk( pk, fpr, &fprlen );

	/* create the key record */
	k = m_alloc_clear( sizeof *k );
	k->rectype = RECTYPE_KEY;
	k->r.key.lid = lid;
	k->r.key.pubkey_algo = pk->pubkey_algo;
	k->r.key.fingerprint_len = fprlen;
	memcpy(k->r.key.fingerprint, fpr, fprlen );
	k->recnum = tdbio_new_recnum();
	*kend = k;
	kend = &k->next;

	k->r.key.keyflags = check_keybinding( keyblock, node, keyid, lid, pk );
	if( (k->r.key.keyflags & KEYF_REVOKED)
	    && node->pkt->pkttype == PKT_PUBLIC_KEY )
	    *mainrev = 1;
    }

    keyrecno = krecs? krecs->recnum : 0;
    /* write the keylist and release the memory */
    for( k = krecs; k ; k = k2 ) {
	if( k->next )
	    k->r.key.next = k->next->recnum;
	write_record( k );
	k2 = k->next;
	m_free( k );
    }
    return keyrecno;
}


/****************
 * Check the validity of a user ID and calculate the uidflags
 * keynode points to  a node with a user ID.
 * mainkid has the key ID of the primary key, keyblock is the complete
 * keyblock which is needed for signature checking.
 * Returns: The uid flags and the self-signature which is considered to
 * be the most current.
 */
static unsigned int
check_uidsigs( KBNODE keyblock, KBNODE keynode, u32 *mainkid, ulong lid,
						  PKT_signature **bestsig )
{
    KBNODE node;
    unsigned int uidflags = 0;
    PKT_signature *sig;
    PKT_signature *selfsig = NULL; /* the latest valid self signature */
    int rc;

    if( DBG_TRUST ) {
	PKT_user_id *uid;
	log_debug("check_uidsigs: %08lX.%lu \"",
			    (ulong)mainkid[1], lid );
	assert(keynode->pkt->pkttype == PKT_USER_ID );
	uid = keynode->pkt->pkt.user_id;
	print_string( log_stream(), uid->name, uid->len, '\"' );
	fputs("\"\n", log_stream());
    }

    /* first we check only the selfsignatures */
    for( node=keynode->next; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* ready */
	if( node->pkt->pkttype != PKT_SIGNATURE )
	    continue; /* don't care about other packets */
	sig = node->pkt->pkt.signature;
	if( mainkid[0] != sig->keyid[0] || mainkid[1] != sig->keyid[1] )
	    continue; /* we only care about self-signatures for now */

	if( (sig->sig_class&~3) == 0x10 ) { /* regular self signature */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info( "uid %08lX.%lu: %s\n",
		       (ulong)mainkid[1], lid, _("Good self-signature") );
		uidflags |= UIDF_CHECKED | UIDF_VALID;
		if( !selfsig )
		    selfsig = sig; /* use the first valid sig */
		else if( sig->timestamp > selfsig->timestamp
			 && sig->sig_class >= selfsig->sig_class )
		    selfsig = sig; /* but this one is newer */
	    }
	    else {
		log_info( "uid %08lX: %s: %s\n",
			   (ulong)mainkid[1], _("Invalid self-signature"),
			   g10_errstr(rc) );
		uidflags |= UIDF_CHECKED;
	    }
	}
    }

    /* and now check for revocations - we must do this after the
     * self signature check because a self-signature which is newer
     * than a revocation makes the revocation invalid.
     * RFC2440 is quiet about tis but I feel this is reasonable for
     * non-primary-key revocations. */
    for( node=keynode->next; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* ready */
	if( node->pkt->pkttype != PKT_SIGNATURE )
	    continue; /* don't care about other packets */
	sig = node->pkt->pkt.signature;
	if( mainkid[0] != sig->keyid[0] || mainkid[1] != sig->keyid[1] )
	    continue; /* we only care about self-signatures for now */

	if( sig->sig_class == 0x30 ) { /* cert revocation */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc && selfsig && selfsig->timestamp > sig->timestamp ) {
		log_info( "uid %08lX.%lu: %s\n",
		       (ulong)mainkid[1], lid,
		       _("Valid user ID revocation skipped "
			 "due to a newer self signature") );
	    }
	    else if( !rc ) {
		if( opt.verbose )
		    log_info( "uid %08lX.%lu: %s\n",
		       (ulong)mainkid[1], lid, _("Valid user ID revocation") );
		uidflags |= UIDF_CHECKED | UIDF_VALID | UIDF_REVOKED;
	    }
	    else {
		log_info("uid %08lX: %s: %s\n",
			    (ulong)mainkid[1], _("Invalid user ID revocation"),
						    g10_errstr(rc) );
	    }
	}
    }

    *bestsig = selfsig;
    return uidflags;
}


static unsigned int
check_sig_record( KBNODE keyblock, KBNODE signode,
		  ulong siglid, int sigidx, u32 *keyid, ulong lid,
		  u32 *r_expiretime, int *mod_down, int *mod_up )
{
    PKT_signature *sig = signode->pkt->pkt.signature;
    unsigned int sigflag = 0;
    TRUSTREC tmp;
    int revocation=0, expired=0, rc;

    if( DBG_TRUST )
	log_debug("check_sig_record: %08lX.%lu %lu[%d]\n",
			    (ulong)keyid[1], lid, siglid, sigidx );
    *r_expiretime = 0;
    if( (sig->sig_class&~3) == 0x10 ) /* regular certification */
	;
    else if( sig->sig_class == 0x30 ) /* cert revocation */
	revocation = 1;
    else
	return SIGF_CHECKED | SIGF_IGNORED;

    read_record( siglid, &tmp, 0 );
    if( tmp.rectype == RECTYPE_DIR ) {
	/* the public key is in the trustdb: check sig */
	rc = check_key_signature2( keyblock, signode, NULL,
					     r_expiretime, &expired );
	if( !rc ) { /* valid signature */
	    if( opt.verbose )
		log_info("sig %08lX.%lu/%lu[%d]/%08lX: %s\n",
			(ulong)keyid[1], lid, siglid, sigidx,
						(ulong)sig->keyid[1],
			revocation? _("Valid certificate revocation")
				  : _("Good certificate") );
	    sigflag |= SIGF_CHECKED | SIGF_VALID;
	    if( expired ) {
		sigflag |= SIGF_EXPIRED;
		/* We have to reset the expiretime, so that this signature
		 * does not get checked over and over due to the reached
		 * expiretime */
		*r_expiretime = 0;
	    }
	    if( revocation ) {
		sigflag |= SIGF_REVOKED;
		*mod_down = 1;
	    }
	    else
		*mod_up = 1;
	}
	else if( rc == G10ERR_NO_PUBKEY ) {
	    /* This may happen if the key is still in the trustdb
	     * but not available in the keystorage */
	    sigflag |= SIGF_NOPUBKEY;
	    *mod_down = 1;
	    if( revocation )
		sigflag |= SIGF_REVOKED;
	}
	else {
	    log_info("sig %08lX.%lu/%lu[%d]/%08lX: %s: %s\n",
			(ulong)keyid[1], lid, siglid, sigidx,
						(ulong)sig->keyid[1],
			revocation? _("Invalid certificate revocation")
				   : _("Invalid certificate"),
					    g10_errstr(rc));
	    sigflag |= SIGF_CHECKED;
	    if( revocation ) {
		sigflag |= SIGF_REVOKED;
		*mod_down = 1;
	    }
	}
    }
    else if( tmp.rectype == RECTYPE_SDIR ) {
	/* better check that it is the right one */
	if(    tmp.r.sdir.keyid[0] == sig->keyid[0]
	    && tmp.r.sdir.keyid[1] == sig->keyid[1]
	    && (!tmp.r.sdir.pubkey_algo
		 || tmp.r.sdir.pubkey_algo == sig->pubkey_algo ))
	    sigflag |= SIGF_NOPUBKEY;
	else
	    log_error(_("sig record %lu[%d] points to wrong record.\n"),
			 siglid, sigidx );
    }
    else {
	log_error(_("sig record %lu[%d] points to wrong record.\n"),
		    siglid, sigidx );
	tdbio_invalid();
    }

    return sigflag;
}

/****************
 * Make the sig records for the given uid record
 * We don't set flags here or even check the signatures; this will
 * happen latter.
 */
static ulong
make_sig_records( KBNODE keyblock, KBNODE uidnode,
		  ulong lid, u32 *mainkid, u32 *min_expire,
					int *mod_down, int *mod_up  )
{
    TRUSTREC *srecs, **s_end, *s=NULL, *s2;
    KBNODE  node;
    PKT_signature *sig;
    ulong sigrecno, siglid;
    int i, sigidx = 0;
    u32 expiretime;

    srecs = NULL; s_end = &srecs;
    for( node=uidnode->next; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* ready */
	if( node->pkt->pkttype != PKT_SIGNATURE )
	    continue; /* don't care about other packets */
	sig = node->pkt->pkt.signature;
	if( mainkid[0] == sig->keyid[0] && mainkid[1] == sig->keyid[1] )
	    continue; /* we don't care about self-signatures here */

	siglid = find_or_create_lid( sig );
	/* smash dups */
	/* FIXME: Here we have a problem:
	 *  We can't distinguish between a certification and a certification
	 *  revocation without looking at class of the signature - we have
	 *  to see how we can store the sigclass in the sigrecord..
	 *  Argg- I hope I can get rid of this ugly trustdb ASAP.
	 */
	for( s2 = s; s2 ; s2 = s2->next ) {
	    for(i=0; i < sigidx; i++ ) {
		if( s2->r.sig.sig[i].lid == siglid )
		    goto leaveduptest;
	    }
	}
	for( s2 = srecs; s2 ; s2 = s2->next ) {
	    for(i=0; i < SIGS_PER_RECORD; i++ ) {
		if( s2->r.sig.sig[i].lid == siglid )
		    goto leaveduptest;
	    }
	}
      leaveduptest:
	if( s2 ) {
	    log_info( "sig %08lX.%lu: %s\n", (ulong)mainkid[1], lid,
				    _("duplicated certificate - deleted") );
	    continue;
	}

	/* create the sig record */
	if( !sigidx ) {
	    s = m_alloc_clear( sizeof *s );
	    s->rectype = RECTYPE_SIG;
	    s->r.sig.lid = lid;
	}
	s->r.sig.sig[sigidx].lid = siglid;
	s->r.sig.sig[sigidx].flag= check_sig_record( keyblock, node,
						     siglid, sigidx,
						     mainkid, lid, &expiretime,
						     mod_down, mod_up );

	sigidx++;
	if( sigidx == SIGS_PER_RECORD ) {
	    s->recnum = tdbio_new_recnum();
	    *s_end = s;
	    s_end = &s->next;
	    sigidx = 0;
	}
	/* keep track of signers pk expire time */
	if( expiretime && (!*min_expire || *min_expire > expiretime ) )
	    *min_expire = expiretime;
    }
    if( sigidx ) {
       s->recnum = tdbio_new_recnum();
       *s_end = s;
       s_end = &s->next;
    }

    sigrecno = srecs? srecs->recnum : 0;
    /* write the keylist and release the memory */
    for( s = srecs; s ; s = s2 ) {
	if( s->next )
	    s->r.sig.next = s->next->recnum;
	write_record( s );
	s2 = s->next;
	m_free( s );
    }
    return sigrecno;
}



/****************
 * Make a preference record (or a list of them) according to the supplied
 * signature.
 * Returns: The record number of the first pref record.
 */
static ulong
make_pref_record( PKT_signature *sig, ulong lid )
{
    static struct {
	sigsubpkttype_t subpkttype;
	int preftype;
    } ptable[] = {
	{ SIGSUBPKT_PREF_SYM,	PREFTYPE_SYM	},
	{ SIGSUBPKT_PREF_HASH,	PREFTYPE_HASH	},
	{ SIGSUBPKT_PREF_COMPR, PREFTYPE_COMPR	},
	{ 0, 0 }
    };
    TRUSTREC *precs, **p_end, *p=NULL, *p2;
    ulong precno;
    int k, idx=0;
    const byte *s;
    size_t n;

  #if (ITEMS_PER_PREF_RECORD % 2) != 0
    #error ITEMS_PER_PREF_RECORD must have an even value
  #endif

    precs = NULL; p_end = &precs;
    for(k=0; ptable[k].subpkttype; k++ ) {
	s = parse_sig_subpkt2( sig, ptable[k].subpkttype, &n );
	if( !s )
	    continue;
	for( ; n; n--, s++ ) {
	    if( !idx ) {
		p = m_alloc_clear( sizeof *p );
		p->rectype = RECTYPE_PREF;
		p->r.pref.lid = lid;
	    }
	    p->r.pref.data[idx++] = ptable[k].preftype;
	    p->r.pref.data[idx++] = *s;
	    if( idx >= ITEMS_PER_PREF_RECORD ) {
		p->recnum = tdbio_new_recnum();
		*p_end = p;
		p_end = &p->next;
		idx = 0;
	    }
	}
    }
    if( idx ) {
       p->recnum = tdbio_new_recnum();
       *p_end = p;
       p_end = &p->next;
    }

    precno = precs? precs->recnum : 0;
    /* write the precs and release the memory */
    for( p = precs; p ; p = p2 ) {
	if( p->next )
	    p->r.pref.next = p->next->recnum;
	write_record( p );
	p2 = p->next;
	m_free( p );
    }
    return precno;
}


static ulong
make_uid_records( KBNODE keyblock, ulong lid, u32 *keyid, u32 *min_expire,
						 int *mod_down, int *mod_up )
{
    TRUSTREC *urecs, **uend, *u, *u2;
    KBNODE  node;
    PKT_user_id *uid;
    byte uidhash[20];
    ulong uidrecno;

    urecs = NULL; uend = &urecs;
    for( node=keyblock; node; node = node->next ) {
	PKT_signature *bestsig;

	if( node->pkt->pkttype != PKT_USER_ID )
	    continue;
	uid = node->pkt->pkt.user_id;
	if( uid->photo )
	    rmd160_hash_buffer( uidhash, uid->photo, uid->photolen );
	else
	    rmd160_hash_buffer( uidhash, uid->name, uid->len );

	/* create the uid record */
	u = m_alloc_clear( sizeof *u );
	u->rectype = RECTYPE_UID;
	u->r.uid.lid = lid;
	memcpy(u->r.uid.namehash, uidhash, 20 );
	u->recnum = tdbio_new_recnum();
	*uend = u;
	uend = &u->next;

	u->r.uid.uidflags = check_uidsigs( keyblock, node, keyid,
						     lid, &bestsig );
	if( (u->r.uid.uidflags & UIDF_CHECKED)
	    && (u->r.uid.uidflags & UIDF_VALID) ) {
	    u->r.uid.prefrec = bestsig? make_pref_record( bestsig, lid ) : 0;
	}

	/* the next test is really bad because we should modify
	 * out modification timestamps only if we really have a change.
	 * But because we are deleting the uid records first it is somewhat
	 * difficult to track those changes.  fixme */
	if(   !( u->r.uid.uidflags & UIDF_VALID )
	    || ( u->r.uid.uidflags & UIDF_REVOKED ) )
	    *mod_down=1;
	else
	    *mod_up=1;

	/* create the list of signatures */
	u->r.uid.siglist = make_sig_records( keyblock, node,
					     lid, keyid, min_expire,
					     mod_down, mod_up );
    }

    uidrecno = urecs? urecs->recnum : 0;
    /* write the uidlist and release the memory */
    for( u = urecs; u ; u = u2 ) {
	if( u->next )
	    u->r.uid.next = u->next->recnum;
	write_record( u );
	u2 = u->next;
	m_free( u );
    }
    return uidrecno;
}



/****************
 * Update all the info from the public keyblock.
 * The key must already exist in the keydb.
 */
int
update_trust_record( KBNODE keyblock, int recheck, int *modified )
{
    TRUSTREC drec;
    int rc;

    /* NOTE: We don't need recheck anymore, but this might chnage again in
     * the future */
    if( opt.dry_run )
	return 0;
    if( modified )
	*modified = 0;
    init_trustdb();
    rc = get_dir_record( find_kbnode( keyblock, PKT_PUBLIC_KEY )
					    ->pkt->pkt.public_key, &drec );
    if( rc )
	return rc;

    rc = do_update_trust_record( keyblock, &drec, 0, modified );
    return rc;
}

/****************
 * Same as update_trust_record, but this functions expects the dir record.
 * On exit the dir record will reflect any changes made.
 * With sigs_only set only foreign key signatures are checked.
 */
static int
do_update_trust_record( KBNODE keyblock, TRUSTREC *drec,
			int sigs_only, int *modified )
{
    PKT_public_key *primary_pk;
    TRUSTREC krec, urec, prec, helprec;
    int i, rc = 0;
    u32 keyid[2]; /* keyid of primary key */
    int mod_up = 0;
    int mod_down = 0;
    ulong recno, r2;
    u32 expiretime;

    primary_pk = find_kbnode( keyblock, PKT_PUBLIC_KEY )->pkt->pkt.public_key;
    if( !primary_pk->local_id )
	primary_pk->local_id = drec->recnum;

    keyid_from_pk( primary_pk, keyid );
    if( DBG_TRUST )
	log_debug("do_update_trust_record: %08lX.%lu\n",
					(ulong)keyid[1], drec->recnum );

    rc = tdbio_begin_transaction();
    if( rc )
	return rc;

    /* delete the old stuff FIXME: implementend sigs_only */
    for( recno=drec->r.dir.keylist; recno; recno = krec.r.key.next ) {
	read_record( recno, &krec, RECTYPE_KEY );
	delete_record( recno );
    }
    drec->r.dir.keylist = 0;
    for( recno=drec->r.dir.uidlist; recno; recno = urec.r.uid.next ) {
	read_record( recno, &urec, RECTYPE_UID );
	for(r2=urec.r.uid.prefrec ; r2; r2 = prec.r.pref.next ) {
	    read_record( r2, &prec, RECTYPE_PREF );
	    delete_record( r2 );
	}
	for(r2=urec.r.uid.siglist ; r2; r2 = helprec.r.sig.next ) {
	    read_record( r2, &helprec, RECTYPE_SIG );
	    delete_record( r2 );
	}
	delete_record( recno );
    }
    drec->r.dir.uidlist = 0;


    /* insert new stuff */
    drec->r.dir.dirflags &= ~DIRF_REVOKED;
    drec->r.dir.dirflags &= ~DIRF_NEWKEYS;
    drec->r.dir.keylist = make_key_records( keyblock, drec->recnum, keyid, &i );
    if( i ) /* primary key has been revoked */
	drec->r.dir.dirflags |= DIRF_REVOKED;
    expiretime = 0;
    drec->r.dir.uidlist = make_uid_records( keyblock, drec->recnum, keyid,
					    &expiretime, &mod_down, &mod_up );
    if( rc )
	rc = tdbio_cancel_transaction();
    else {
	if( modified && tdbio_is_dirty() )
	    *modified = 1;
	drec->r.dir.dirflags |= DIRF_CHECKED;
	drec->r.dir.valcheck = 0;
	drec->r.dir.checkat = expiretime;
	write_record( drec );
	tdbio_write_modify_stamp( mod_up, mod_down );
	rc = tdbio_end_transaction();
    }
    return rc;
}



/****************
 * Insert a trust record into the TrustDB
 * This function assumes that the record does not yet exist.
 */
int
insert_trust_record( KBNODE keyblock )
{
    TRUSTREC dirrec;
    TRUSTREC shadow;
    KBNODE node;
    int rc = 0;
    PKT_public_key *pk;


    if( opt.dry_run )
	return 0;

    init_trustdb();

    pk = find_kbnode( keyblock, PKT_PUBLIC_KEY )->pkt->pkt.public_key;
    if( pk->local_id ) {
	log_debug("insert_trust_record with pk->local_id=%lu (2)\n",
							pk->local_id );
	rc = update_trust_record( keyblock, 1, NULL );
	return rc;
    }

    /* We have to look for a shadow dir record which must be reused
     * as the dir record. */
    rc = tdbio_search_sdir( pk->keyid, pk->pubkey_algo, &shadow );
    if( rc && rc != -1 ) {
	log_error(_("tdbio_search_dir failed: %s\n"), g10_errstr(rc));
	tdbio_invalid();
    }
    memset( &dirrec, 0, sizeof dirrec );
    dirrec.rectype = RECTYPE_DIR;
    if( !rc ) /* we have a shadow dir record - convert to dir record */
	dirrec.recnum = shadow.recnum;
    else
	dirrec.recnum = tdbio_new_recnum();
    dirrec.r.dir.lid = dirrec.recnum;
    write_record( &dirrec );

    /* put the LID into the keyblock */
    pk->local_id = dirrec.r.dir.lid;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *a_pk = node->pkt->pkt.public_key;
	    a_pk->local_id = dirrec.r.dir.lid;
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *a_sig = node->pkt->pkt.signature;
	    a_sig->local_id = dirrec.r.dir.lid;
	}
    }


    /* mark tdb as modified upwards */
    tdbio_write_modify_stamp( 1, 0 );

    /* and put all the other stuff into the keydb */
    rc = do_update_trust_record( keyblock, &dirrec, 0, NULL );

    do_sync();

    /* keep track of new keys */
    if( !fresh_imported_keys )
	fresh_imported_keys = new_lid_table();
    ins_lid_table_item( fresh_imported_keys, pk->local_id, 0 );
    if( ++fresh_imported_keys_count > FRESH_KEY_CHECK_THRESHOLD )
	mark_fresh_keys();

    return rc;
}




/****************
 * Insert a trust record indentified by a PK into the TrustDB
 */
int
insert_trust_record_by_pk( PKT_public_key *pk )
{
    KBNODE keyblock = NULL;
    byte fingerprint[MAX_FINGERPRINT_LEN];
    size_t fingerlen;
    int rc;

    /* get the keyblock */
    fingerprint_from_pk( pk, fingerprint, &fingerlen );
    rc = get_keyblock_byfprint( &keyblock, fingerprint, fingerlen );
    if( rc ) { /* that should never happen */
	log_debug( "insert_trust_record_by_pk: keyblock not found: %s\n",
							  g10_errstr(rc) );
    }
    else {
	rc = insert_trust_record( keyblock );
	if( !rc ) /* copy the LID into the PK */
	    pk->local_id = find_kbnode( keyblock, PKT_PUBLIC_KEY )
					    ->pkt->pkt.public_key->local_id;
    }

    release_kbnode( keyblock );
    return rc;
}


/****************
 * Check one trust record.  This function is called for every
 * directory record which is to be checked.  The supplied
 * dir record is modified according to the performed actions.
 * Currently we only do an update_trust_record.
 */
static int
check_trust_record( TRUSTREC *drec, int sigs_only )
{
    KBNODE keyblock;
    int modified, rc;

    rc = get_keyblock_bylid( &keyblock, drec->recnum );
    if( rc ) {
	log_debug( "check_trust_record %lu: keyblock not found: %s\n",
					      drec->recnum, g10_errstr(rc) );
	return rc;
    }

    rc = do_update_trust_record( keyblock, drec, sigs_only, &modified );
    release_kbnode( keyblock );

    return rc;
}


/****************
 * Walk over the keyrings and create trustdb records for all keys
 * which are not currently in the trustdb.
 * It is intended to be used after a fast-import operation.
 */
void
update_trustdb()
{
    KBNODE keyblock = NULL;
    KBPOS kbpos;
    int rc;

    if( opt.dry_run )
	return;

    init_trustdb();
    rc = enum_keyblocks( 0, &kbpos, &keyblock );
    if( !rc ) {
	ulong count=0, err_count=0, new_count=0;

	while( !(rc = enum_keyblocks( 1, &kbpos, &keyblock )) ) {
	    /*int modified;*/
	    TRUSTREC drec;
	    PKT_public_key *pk = find_kbnode( keyblock, PKT_PUBLIC_KEY )
					->pkt->pkt.public_key;

	    rc = get_dir_record( pk, &drec );
	    if( rc == -1 ) { /* not in trustdb: insert */
		rc = insert_trust_record( keyblock );
		if( rc && !pk->local_id ) {
		    log_error(_("lid ?: insert failed: %s\n"),
						     g10_errstr(rc) );
		    err_count++;
		}
		else if( rc ) {
		    log_error(_("lid %lu: insert failed: %s\n"),
				       pk->local_id, g10_errstr(rc) );
		    err_count++;
		}
		else {
		    if( opt.verbose )
			log_info(_("lid %lu: inserted\n"), pk->local_id );
		    new_count++;
		}
	    }
	    else if( rc ) {
		log_error(_("error reading dir record: %s\n"), g10_errstr(rc));
		err_count++;
	    }

	    release_kbnode( keyblock ); keyblock = NULL;
	    if( !(++count % 100) )
		log_info(_("%lu keys so far processed\n"), count);
	}
	log_info(_("%lu keys processed\n"), count);
	if( err_count )
	    log_info(_("\t%lu keys with errors\n"), err_count);
	if( new_count )
	    log_info(_("\t%lu keys inserted\n"), new_count);
    }
    if( rc && rc != -1 )
	log_error(_("enumerate keyblocks failed: %s\n"), g10_errstr(rc));

    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
}



/****************
 * Do all required checks in the trustdb.  This function walks over all
 * records in the trustdb and does scheduled processing.
 */
void
check_trustdb( const char *username )
{
    TRUSTREC rec;
    ulong recnum;
    ulong count=0, upd_count=0, err_count=0, skip_count=0, sigonly_count=0;
    ulong current_time = make_timestamp();

    if( username )
	log_info("given user IDs ignored in check_trustdb\n");

    init_trustdb();

    for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	int sigs_only;

	if( rec.rectype != RECTYPE_DIR )
	    continue; /* we only want the dir records */

	if( count && !(count % 100) && !opt.quiet )
	    log_info(_("%lu keys so far processed\n"), count);
	count++;
	sigs_only = 0;

	if( !(rec.r.dir.dirflags & DIRF_CHECKED) )
	    ;
	else if( !rec.r.dir.checkat || rec.r.dir.checkat > current_time ) {
	    if( !(rec.r.dir.dirflags & DIRF_NEWKEYS) ) {
		skip_count++;
		continue;  /* not scheduled for checking */
	    }
	    sigs_only = 1; /* new public keys - check them */
	    sigonly_count++;
	}

	if( !rec.r.dir.keylist ) {
	    log_info(_("lid %lu: dir record w/o key - skipped\n"), recnum);
	    skip_count++;
	    continue;
	}

	check_trust_record( &rec, sigs_only );
    }

    log_info(_("%lu keys processed\n"), count);
    if( sigonly_count )
	log_info(_("\t%lu due to new pubkeys\n"), sigonly_count);
    if( skip_count )
	log_info(_("\t%lu keys skipped\n"), skip_count);
    if( err_count )
	log_info(_("\t%lu keys with errors\n"), err_count);
    if( upd_count )
	log_info(_("\t%lu keys updated\n"), upd_count);
}



/***********************************************
 *********  Trust calculation  *****************
 ***********************************************/

/****************
 * Find all certification paths of a given LID.
 * Limit the search to MAX_DEPTH.  stack is a helper variable which
 * should have been allocated with size max_depth, stack[0] should
 * be setup to the key we are investigating, so the minimal depth
 * we should ever see in this function is 1.
 * Returns: a new tree
 * certchain_set must be a valid set or point to NULL; this function
 * may modifiy it.
 *
 * Hmmm: add a fastscan mode which stops at valid validity nodes.
 */
static TN
build_cert_tree( ulong lid, int depth, int max_depth, TN helproot )
{
    TRUSTREC dirrec;
    TRUSTREC uidrec;
    ulong uidrno;
    TN keynode;

    if( depth >= max_depth )
	return NULL;

    keynode = new_tn();
    if( !helproot )
	helproot = keynode;
    keynode->lid = lid;
    if( !qry_lid_table_flag( ultikey_table, lid, NULL ) ) {
	/* this is an ultimately trusted key;
	 * which means that we have found the end of the chain:
	 * We do this here prior to reading the dir record
	 * because we don't really need the info from that record */
	keynode->n.k.ownertrust = TRUST_ULTIMATE;
	keynode->n.k.buckstop	= 1;
	return keynode;
    }
    read_record( lid, &dirrec, 0 );
    if( dirrec.rectype != RECTYPE_DIR ) {
	if( dirrec.rectype != RECTYPE_SDIR )
	    log_debug("lid %lu, has rectype %d"
		      " - skipped\n", lid, dirrec.rectype );
	m_free(keynode);
	return NULL;
    }

    if( dirrec.r.dir.checkat && dirrec.r.dir.checkat <= make_timestamp() ) {
	check_trust_record( &dirrec, 0 );
    }
    else if( (dirrec.r.dir.dirflags & DIRF_NEWKEYS) ) {
	check_trust_record( &dirrec, 1 );
    }

    keynode->n.k.ownertrust = dirrec.r.dir.ownertrust & TRUST_MASK;

    /* loop over all user ids */
    for( uidrno = dirrec.r.dir.uidlist; uidrno; uidrno = uidrec.r.uid.next ) {
	TRUSTREC sigrec;
	ulong sigrno;
	TN uidnode = NULL;

	read_record( uidrno, &uidrec, RECTYPE_UID );

	if( !(uidrec.r.uid.uidflags & UIDF_CHECKED) )
	    continue; /* user id has not been checked */
	if( !(uidrec.r.uid.uidflags & UIDF_VALID) )
	    continue; /* user id is not valid */
	if( (uidrec.r.uid.uidflags & UIDF_REVOKED) )
	    continue; /* user id has been revoked */

	/* loop over all signature records */
	for(sigrno=uidrec.r.uid.siglist; sigrno; sigrno = sigrec.r.sig.next ) {
	    int i;
	    TN tn;

	    read_record( sigrno, &sigrec, RECTYPE_SIG );

	    for(i=0; i < SIGS_PER_RECORD; i++ ) {
		if( !sigrec.r.sig.sig[i].lid )
		    continue; /* skip deleted sigs */
		if( !(sigrec.r.sig.sig[i].flag & SIGF_CHECKED) )
		    continue; /* skip unchecked signatures */
		if( !(sigrec.r.sig.sig[i].flag & SIGF_VALID) )
		    continue; /* skip invalid signatures */
		if( (sigrec.r.sig.sig[i].flag & SIGF_EXPIRED) )
		    continue; /* skip expired signatures */
		if( (sigrec.r.sig.sig[i].flag & SIGF_REVOKED) )
		    continue; /* skip revoked signatures */
		/* check for cycles */
		for( tn=keynode; tn && tn->lid != sigrec.r.sig.sig[i].lid;
							  tn = tn->back )
		    ;
		if( tn )
		    continue; /* cycle found */

		tn = build_cert_tree( sigrec.r.sig.sig[i].lid,
				      depth+1, max_depth, helproot );
		if( !tn )
		    continue; /* cert chain too deep or error */

		if( !uidnode ) {
		    uidnode = new_tn();
		    uidnode->back = keynode;
		    uidnode->lid = uidrno;
		    uidnode->is_uid = 1;
		    uidnode->next = keynode->list;
		    keynode->list = uidnode;
		}

		tn->back = uidnode;
		tn->next = uidnode->list;
		uidnode->list = tn;
		if( tn->n.k.buckstop ) {
		    /* ultimately trusted key found:
		     * no need to check more signatures of this uid */
		    sigrec.r.sig.next = 0;
		    break;
		}
	    }
	} /* end loop over sig recs */
    } /* end loop over user ids */

    if( !keynode->list ) {
	release_tn_tree( keynode );
	keynode = NULL;
    }

    return keynode;
}


static void
upd_one_ownertrust( ulong lid, unsigned new_trust, unsigned *retflgs )
{
    TRUSTREC rec;

    read_record( lid, &rec, RECTYPE_DIR );
    if( DBG_TRUST )
	log_debug("upd_one_ownertrust of %lu from %u to %u\n",
			   lid, (unsigned)rec.r.dir.ownertrust, new_trust );
    if( retflgs ) {
	if( (new_trust & TRUST_MASK) > (rec.r.dir.ownertrust & TRUST_MASK) )
	    *retflgs |= 16; /* modified up */
	else
	    *retflgs |= 32; /* modified down */
    }

    /* we preserve the disabled state here */
    if( (rec.r.dir.ownertrust & TRUST_FLAG_DISABLED) )
	rec.r.dir.ownertrust = new_trust | TRUST_FLAG_DISABLED;
    else
	rec.r.dir.ownertrust = new_trust & ~TRUST_FLAG_DISABLED;
    write_record( &rec );
}

/****************
 * Update the ownertrust in the complete tree.
 */
static void
propagate_ownertrust( TN kr, ulong lid, unsigned trust )
{
    TN ur;

    for( ; kr; kr = kr->next ) {
	if( kr->lid == lid )
	    kr->n.k.ownertrust = trust;
	for( ur=kr->list; ur; ur = ur->next )
	    propagate_ownertrust( ur->list, lid, trust );
    }
}

/****************
 * Calculate the validity of all keys in the tree and especially
 * the one of the top key.  If add_fnc is not NULL, it is used to
 * ask for missing ownertrust values (but only if this will help
 * us to increase the validity.
 * add_fnc is expected to take the LID of the key under question
 * and return a ownertrust value or an error:  positive values
 * are assumed to be the new ownertrust value; a 0 does mean no change,
 * a -1 is a request to cancel this validation procedure, a -2 requests
 * a listing of the sub-tree using the tty functions.
 *
 *
 * Returns: 0 = okay
 */
static int
propagate_validity( TN root, TN node, int (*add_fnc)(ulong), unsigned *retflgs )
{
    TN kr, ur;
    int max_validity = 0;

    assert( !node->is_uid );
    if( node->n.k.ownertrust == TRUST_ULTIMATE ) {
	/* this is one of our keys */
	assert( !node->list ); /* it should be a leaf */
	node->n.k.validity = TRUST_ULTIMATE;
	if( retflgs )
	    *retflgs |= 1;  /* found a path to an ultimately trusted key */
	return 0;
    }

    /* loop over all user ids */
    for( ur=node->list; ur && max_validity <= TRUST_FULLY; ur = ur->next ) {
	assert( ur->is_uid );
	/* loop over all signators */
	for(kr=ur->list; kr && max_validity <= TRUST_FULLY; kr = kr->next ) {
	    if( propagate_validity( root, kr, add_fnc, retflgs ) )
		return -1; /* quit */
	    if( kr->n.k.validity == TRUST_ULTIMATE ) {
		ur->n.u.fully_count = opt.completes_needed;
	    }
	    else if( kr->n.k.validity == TRUST_FULLY ) {
		if( add_fnc && !kr->n.k.ownertrust ) {
		    int rc;

		    if( retflgs )
			*retflgs |= 2; /* found key with undefined ownertrust*/
		    do {
			rc = add_fnc( kr->lid );
			switch( rc ) {
			  case TRUST_NEVER:
			  case TRUST_MARGINAL:
			  case TRUST_FULLY:
			    propagate_ownertrust( root, kr->lid, rc );
			    upd_one_ownertrust( kr->lid, rc, retflgs );
			    if( retflgs )
				*retflgs |= 4; /* changed */
			    break;
			  case -1:
			    return -1; /* cancel */
			  case -2:
			    dump_tn_tree( NULL, 0, kr );
			    tty_printf("\n");
			    break;
			  default:
			    break;
			}
		    } while( rc == -2 );
		}
		if( kr->n.k.ownertrust == TRUST_FULLY )
		    ur->n.u.fully_count++;
		else if( kr->n.k.ownertrust == TRUST_MARGINAL )
		    ur->n.u.marginal_count++;
	    }

	    if( ur->n.u.fully_count >= opt.completes_needed
		|| ur->n.u.marginal_count >= opt.marginals_needed )
		ur->n.u.validity = TRUST_FULLY;
	    else if( ur->n.u.fully_count || ur->n.u.marginal_count )
		ur->n.u.validity = TRUST_MARGINAL;

	    if( ur->n.u.validity >= max_validity )
		max_validity = ur->n.u.validity;
	}
    }

    node->n.k.validity = max_validity;
    return 0;
}



/****************
 * Given the directory record of a key, check whether we can
 * find a path to an ultimately trusted key.  We do this by
 * checking all key signatures up to a some depth.
 */
static int
verify_key( int max_depth, TRUSTREC *drec, const char *namehash,
			    int (*add_fnc)(ulong), unsigned *retflgs )
{
    TN tree;
    int keytrust;
    int pv_result;

    tree = build_cert_tree( drec->r.dir.lid, 0, opt.max_cert_depth, NULL );
    if( !tree )
	return TRUST_UNDEFINED;
    pv_result = propagate_validity( tree, tree, add_fnc, retflgs );
    if( namehash && tree->n.k.validity != TRUST_ULTIMATE ) {
	/* find the matching user id.
	 * We don't do this here if the key is ultimately trusted; in
	 * this case there will be no lids for the user IDs and frankly
	 * it does not make sense to compare by the name if we do
	 * have the secret key.
	 * fixme: the way we handle this is too inefficient */
	TN ur;
	TRUSTREC rec;

	keytrust = 0;
	for( ur=tree->list; ur; ur = ur->next ) {
	    read_record( ur->lid, &rec, RECTYPE_UID );
	    if( !memcmp( namehash, rec.r.uid.namehash, 20 ) ) {
		keytrust = ur->n.u.validity;
		break;
	    }
	}
    }
    else
	keytrust = tree->n.k.validity;

    /* update the cached validity values */
    if( !pv_result
	&& keytrust >= TRUST_UNDEFINED
	&& tdbio_db_matches_options()
	&& ( !drec->r.dir.valcheck || drec->r.dir.validity != keytrust ) ) {
	TN ur;
	TRUSTREC rec;

	for( ur=tree->list; ur; ur = ur->next ) {
	    read_record( ur->lid, &rec, RECTYPE_UID );
	    if( rec.r.uid.validity != ur->n.u.validity ) {
		rec.r.uid.validity = ur->n.u.validity;
		write_record( &rec );
	    }
	}

	drec->r.dir.validity = tree->n.k.validity;
	drec->r.dir.valcheck = make_timestamp();
	write_record( drec );
	do_sync();
    }

    release_tn_tree( tree );
    return keytrust;
}


/****************
 * we have the pubkey record and all needed informations are in the trustdb
 * but nothing more is known.
 */
static int
do_check( TRUSTREC *dr, unsigned *validity,
	  const char *namehash, int (*add_fnc)(ulong), unsigned *retflgs )
{
    if( !dr->r.dir.keylist ) {
	log_error(_("Ooops, no keys\n"));
	return G10ERR_TRUSTDB;
    }
    if( !dr->r.dir.uidlist ) {
	log_error(_("Ooops, no user IDs\n"));
	return G10ERR_TRUSTDB;
    }

    if( retflgs )
	*retflgs &= ~(16|32);  /* reset the 2 special flags */

    if( (dr->r.dir.ownertrust & TRUST_FLAG_DISABLED) )
	*validity = 0; /* no need to check further */
    else if( namehash ) {
	/* Fixme: use a cache */
	*validity = verify_key( opt.max_cert_depth, dr, namehash,
							add_fnc, retflgs );
    }
    else if( !add_fnc
	&& tdbio_db_matches_options()
	    /* FIXME, TODO: This comparision is WRONG ! */
	&& dr->r.dir.valcheck
	    > tdbio_read_modify_stamp( (dr->r.dir.validity < TRUST_FULLY) )
	&& dr->r.dir.validity )
	*validity = dr->r.dir.validity;
    else
	*validity = verify_key( opt.max_cert_depth, dr, NULL,
							add_fnc, retflgs );

    if( !(*validity & TRUST_MASK) )
	*validity = TRUST_UNDEFINED;

    if( (dr->r.dir.ownertrust & TRUST_FLAG_DISABLED) )
	*validity |= TRUST_FLAG_DISABLED;

    if( dr->r.dir.dirflags & DIRF_REVOKED )
	*validity |= TRUST_FLAG_REVOKED;

    /* If we have changed some ownertrusts, set the trustdb timestamps
     * and do a sync */
    if( retflgs && (*retflgs & (16|32)) ) {
	tdbio_write_modify_stamp( (*retflgs & 16), (*retflgs & 32) );
	do_sync();
    }


    return 0;
}



/***********************************************
 *********  Change trustdb values **************
 ***********************************************/

int
update_ownertrust( ulong lid, unsigned new_trust )
{
    TRUSTREC rec;

    init_trustdb();
    read_record( lid, &rec, RECTYPE_DIR );
    if( DBG_TRUST )
	log_debug("update_ownertrust of %lu from %u to %u\n",
			   lid, (unsigned)rec.r.dir.ownertrust, new_trust );
    rec.r.dir.ownertrust = new_trust;
    write_record( &rec );
    do_sync();
    return 0;
}


int
clear_trust_checked_flag( PKT_public_key *pk )
{
    TRUSTREC rec;
    int rc;

    if( opt.dry_run )
	return 0;

    init_trustdb();
    rc = get_dir_record( pk, &rec );
    if( rc )
	return rc;

    /* check whether they are already reset */
    if( !(rec.r.dir.dirflags & DIRF_CHECKED) && !rec.r.dir.valcheck )
	return 0;

    /* reset the flag */
    rec.r.dir.dirflags &= ~DIRF_CHECKED;
    rec.r.dir.valcheck = 0;
    write_record( &rec );
    do_sync();
    return 0;
}





/***********************************************
 *********  Query trustdb values  **************
 ***********************************************/


/****************
 * This function simply looks for the key in the trustdb
 * and makes sure that pk->local_id is set to the correct value.
 * Return: 0 = found
 *	   -1 = not found
 *	  other = error
 */
int
query_trust_record( PKT_public_key *pk )
{
    TRUSTREC rec;
    init_trustdb();
    return get_dir_record( pk, &rec );
}


/****************
 * Get the trustlevel for this PK.
 * Note: This does not ask any questions
 * Returns: 0 okay of an errorcode
 *
 * It operates this way:
 *  locate the pk in the trustdb
 *	found:
 *	    Do we have a valid cache record for it?
 *		yes: return trustlevel from cache
 *		no:  make a cache record and all the other stuff
 *	not found:
 *	    try to insert the pubkey into the trustdb and check again
 *
 * Problems: How do we get the complete keyblock to check that the
 *	     cache record is actually valid?  Think we need a clever
 *	     cache in getkey.c	to keep track of this stuff. Maybe it
 *	     is not necessary to check this if we use a local pubring. Hmmmm.
 */
int
check_trust( PKT_public_key *pk, unsigned *r_trustlevel,
	     const byte *namehash, int (*add_fnc)(ulong), unsigned *retflgs )
{
    TRUSTREC rec;
    unsigned trustlevel = TRUST_UNKNOWN;
    int rc=0;
    u32 cur_time;
    u32 keyid[2];


    init_trustdb();
    keyid_from_pk( pk, keyid );

    /* get the pubkey record */
    if( pk->local_id ) {
	read_record( pk->local_id, &rec, RECTYPE_DIR );
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 ) {
	    log_error(_("check_trust: search dir record failed: %s\n"),
							    g10_errstr(rc));
	    return rc;
	}
	else if( rc == -1 && opt.dry_run )
	    return G10ERR_GENERAL;
	else if( rc == -1 ) { /* not found - insert */
	    rc = insert_trust_record_by_pk( pk );
	    if( rc ) {
		log_error(_("key %08lX: insert trust record failed: %s\n"),
					  (ulong)keyid[1], g10_errstr(rc));
		goto leave;
	    }
	    log_info(_("key %08lX.%lu: inserted into trustdb\n"),
					  (ulong)keyid[1], pk->local_id );
	    /* and re-read the dir record */
	    read_record( pk->local_id, &rec, RECTYPE_DIR );
	}
    }
    cur_time = make_timestamp();
    if( pk->timestamp > cur_time ) {
	log_info(_("key %08lX.%lu: created in future "
		   "(time warp or clock problem)\n"),
					  (ulong)keyid[1], pk->local_id );
	if( !opt.ignore_time_conflict )
	    return G10ERR_TIME_CONFLICT;
    }

    if( !(rec.r.dir.dirflags & DIRF_CHECKED) )
	check_trust_record( &rec, 0 );
    else if( rec.r.dir.checkat && rec.r.dir.checkat <= cur_time )
	check_trust_record( &rec, 0 );
    else if( (rec.r.dir.dirflags & DIRF_NEWKEYS) )
	check_trust_record( &rec, 1 );

    if( pk->expiredate && pk->expiredate <= cur_time ) {
	log_info(_("key %08lX.%lu: expired at %s\n"),
			(ulong)keyid[1], pk->local_id,
			     asctimestamp( pk->expiredate) );
	trustlevel = TRUST_EXPIRED;
    }
    else {
	rc = do_check( &rec, &trustlevel, namehash, add_fnc, retflgs );
	if( rc ) {
	    log_error(_("key %08lX.%lu: trust check failed: %s\n"),
			    (ulong)keyid[1], pk->local_id, g10_errstr(rc));
	    return rc;
	}
    }

    /* is a subkey has been requested, we have to check its keyflags */
    if( !rc ) {
	TRUSTREC krec;
	byte fpr[MAX_FINGERPRINT_LEN] = {0}; /* to avoid compiler warnings */
	size_t fprlen = 0;
	ulong recno;
	int kcount=0;

	for( recno = rec.r.dir.keylist; recno; recno = krec.r.key.next ) {
	    read_record( recno, &krec, RECTYPE_KEY );
	    if( ++kcount == 1 )
		continue; /* skip the primary key */
	    if( kcount == 2 ) /* now we need the fingerprint */
		fingerprint_from_pk( pk, fpr, &fprlen );

	    if( krec.r.key.fingerprint_len == fprlen
		&& !memcmp( krec.r.key.fingerprint, fpr, fprlen ) ) {
		/* found the subkey */
		if( (krec.r.key.keyflags & KEYF_REVOKED) )
		    trustlevel |= TRUST_FLAG_SUB_REVOKED;
		/* should we check for keybinding here??? */
		/* Hmmm: Maybe this whole checking stuff should not go
		 * into the trustdb, but be done direct from the keyblock.
		 * Chnage this all when we add an abstarction layer around
		 * the way certificates are handled by different standards */
		break;
	    }
	}
    }


  leave:
    if( DBG_TRUST )
	log_debug("check_trust() returns trustlevel %04x.\n", trustlevel);
    *r_trustlevel = trustlevel;
    return 0;
}


/****************
 * scan the whole trustdb and mark all signature records whose keys
 * are freshly imported.
 */
static void
mark_fresh_keys()
{
    TRUSTREC dirrec, rec;
    ulong recnum, lid;
    int i;

    memset( &dirrec, 0, sizeof dirrec );

    for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	if( rec.rectype != RECTYPE_SIG )
	    continue;
	/* if we have already have the dir record, we can check it now */
	if( dirrec.recnum == rec.r.sig.lid
	    && (dirrec.r.dir.dirflags & DIRF_NEWKEYS) )
	    continue; /* flag is already set */

	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    if( !(lid=rec.r.sig.sig[i].lid) )
		continue; /* skip deleted sigs */
	    if( !(rec.r.sig.sig[i].flag & SIGF_CHECKED) )
		continue; /* skip checked signatures */
	    if( qry_lid_table_flag( fresh_imported_keys, lid, NULL ) )
		continue; /* not in the list of new keys */
	    read_record( rec.r.sig.lid, &dirrec, RECTYPE_DIR );
	    if( !(dirrec.r.dir.dirflags & DIRF_NEWKEYS) ) {
		dirrec.r.dir.dirflags |= DIRF_NEWKEYS;
		write_record( &dirrec );
	    }
	    break;
	}
    }

    do_sync();

    clear_lid_table( fresh_imported_keys );
    fresh_imported_keys_count = 0;
}



int
query_trust_info( PKT_public_key *pk, const byte *namehash )
{
    unsigned trustlevel;
    int c;

    init_trustdb();
    if( check_trust( pk, &trustlevel, namehash, NULL, NULL ) )
	return '?';
    if( trustlevel & TRUST_FLAG_DISABLED )
	return 'd';
    if( trustlevel & TRUST_FLAG_REVOKED )
	return 'r';
    c = trust_letter( (trustlevel & TRUST_MASK) );
    if( !c )
	c = '?';
    return c;
}



/****************
 * Return the assigned ownertrust value for the given LID
 */
unsigned
get_ownertrust( ulong lid )
{
    TRUSTREC rec;

    init_trustdb();
    read_record( lid, &rec, RECTYPE_DIR );
    return rec.r.dir.ownertrust;
}

int
get_ownertrust_info( ulong lid )
{
    unsigned otrust;
    int c;

    init_trustdb();
    otrust = get_ownertrust( lid );
    c = trust_letter( (otrust & TRUST_MASK) );
    if( !c )
	c = '?';
    return c;
}



void
list_trust_path( const char *username )
{
    int rc;
    ulong lid;
    TRUSTREC rec;
    TN tree;
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

    init_trustdb();
    if( (rc = get_pubkey_byname(NULL, pk, username, NULL )) )
	log_error(_("user '%s' not found: %s\n"), username, g10_errstr(rc) );
    else if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 )
	log_error(_("problem finding '%s' in trustdb: %s\n"),
					    username, g10_errstr(rc));
    else if( rc == -1 ) {
	log_info(_("user '%s' not in trustdb - inserting\n"), username);
	rc = insert_trust_record_by_pk( pk );
	if( rc )
	    log_error(_("failed to put '%s' into trustdb: %s\n"),
						    username, g10_errstr(rc));
	else {
	    assert( pk->local_id );
	}
    }
    lid = pk->local_id;

    tree = build_cert_tree( lid, 0, opt.max_cert_depth, NULL );
    if( tree )
	propagate_validity( tree, tree, NULL, NULL );
    if( opt.with_colons )
	dump_tn_tree_with_colons( 0, tree );
    else
	dump_tn_tree( stdout, 0, tree );
    /*printf("(alloced tns=%d  max=%d)\n", alloced_tns, max_alloced_tns );*/
    release_tn_tree( tree );
    /*printf("Ownertrust=%c Validity=%c\n", get_ownertrust_info( lid ),
					  query_trust_info( pk, NULL ) ); */

    free_public_key( pk );

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
  #if 0
    struct enum_cert_paths_ctx *ctx;
    fixme: .....   tsl;

    init_trustdb();
    if( !lid ) {  /* release the context */
	if( *context ) {
	    FIXME: ........tsl2;

	    ctx = *context;
	    for(tsl = ctx->tsl_head; tsl; tsl = tsl2 ) {
		tsl2 = tsl->next;
		m_free( tsl );
	    }
	    *context = NULL;
	}
	return -1;
    }

    if( !*context ) {
	FIXME .... *tmppath;
	TRUSTREC rec;

	if( !*lid )
	    return -1;

	ctx = m_alloc_clear( sizeof *ctx );
	*context = ctx;
	/* collect the paths */
      #if 0
	read_record( *lid, &rec, RECTYPE_DIR );
	tmppath = m_alloc_clear( (opt.max_cert_depth+1)* sizeof *tmppath );
	tsl = NULL;
	collect_paths( 0, opt.max_cert_depth, 1, &rec, tmppath, &tsl );
	m_free( tmppath );
	sort_tsl_list( &tsl );
      #endif
	/* setup the context */
	ctx->tsl_head = tsl;
	ctx->tsl = ctx->tsl_head;
	ctx->idx = 0;
    }
    else
	ctx = *context;

    while( ctx->tsl && ctx->idx >= ctx->tsl->pathlen )	{
	ctx->tsl = ctx->tsl->next;
	ctx->idx = 0;
    }
    tsl = ctx->tsl;
    if( !tsl )
	return -1; /* eof */

    if( ownertrust )
	*ownertrust = tsl->path[ctx->idx].otrust;
    if( validity )
	*validity = tsl->path[ctx->idx].trust;
    *lid = tsl->path[ctx->idx].lid;
    ctx->idx++;
    return ctx->idx-1;
  #endif
}


/****************
 * Print the current path
 */
void
enum_cert_paths_print( void **context, FILE *fp,
				       int refresh, ulong selected_lid )
{
    return;
  #if 0
    struct enum_cert_paths_ctx *ctx;
    FIXME......... tsl;

    if( !*context )
	return;
    init_trustdb();
    ctx = *context;
    if( !ctx->tsl )
	return;
    tsl = ctx->tsl;

    if( !fp )
	fp = stderr;

    if( refresh ) { /* update the ownertrust and if possible the validity */
	int i;
	int match = tdbio_db_matches_options();

	for( i = 0; i < tsl->pathlen; i++ )  {
	    TRUSTREC rec;

	    read_record( tsl->path[i].lid, &rec, RECTYPE_DIR );
	    tsl->path[i].otrust = rec.r.dir.ownertrust;
	    /* update validity only if we have it in the cache
	     * calculation is too time consuming */
	    if( match && rec.r.dir.valcheck && rec.r.dir.validity ) {
		tsl->path[i].trust = rec.r.dir.validity;
		if( rec.r.dir.dirflags & DIRF_REVOKED )
		    tsl->path[i].trust = TRUST_FLAG_REVOKED;
	    }
	}
    }

    print_path( tsl->pathlen, tsl->path, fp, selected_lid );
  #endif
}


/*
 * Return an allocated buffer with the preference values for
 * the key with LID and the userid which is identified by the
 * HAMEHASH or the first one if namehash is NULL.  ret_n receives
 * the length of the allocated buffer.	Structure of the buffer is
 * a repeated sequences of 2 bytes; where the first byte describes the
 * type of the preference and the second one the value.  The constants
 * PREFTYPE_xxxx should be used to reference a type.
 */
byte *
get_pref_data( ulong lid, const byte *namehash, size_t *ret_n )
{
    TRUSTREC rec;
    ulong recno;

    init_trustdb();
    read_record( lid, &rec, RECTYPE_DIR );
    for( recno=rec.r.dir.uidlist; recno; recno = rec.r.uid.next ) {
	read_record( recno, &rec, RECTYPE_UID );
	if( rec.r.uid.prefrec
	    && ( !namehash || !memcmp(namehash, rec.r.uid.namehash, 20) ))  {
	    byte *buf;
	    /* found the correct one or the first one */
	    read_record( rec.r.uid.prefrec, &rec, RECTYPE_PREF );
	    if( rec.r.pref.next )
		log_info(_("WARNING: can't yet handle long pref records\n"));
	    buf = m_alloc( ITEMS_PER_PREF_RECORD );
	    memcpy( buf, rec.r.pref.data, ITEMS_PER_PREF_RECORD );
	    *ret_n = ITEMS_PER_PREF_RECORD;
	    return buf;
	}
    }
    return NULL;
}



/****************
 * Check whether the algorithm is in one of the pref records
 */
int
is_algo_in_prefs( ulong lid, int preftype, int algo )
{
    TRUSTREC rec;
    ulong recno;
    int i;
    byte *pref;

    init_trustdb();
    read_record( lid, &rec, RECTYPE_DIR );
    for( recno=rec.r.dir.uidlist; recno; recno = rec.r.uid.next ) {
	read_record( recno, &rec, RECTYPE_UID );
	if( rec.r.uid.prefrec ) {
	    read_record( rec.r.uid.prefrec, &rec, RECTYPE_PREF );
	    if( rec.r.pref.next )
		log_info(_("WARNING: can't yet handle long pref records\n"));
	    pref = rec.r.pref.data;
	    for(i=0; i+1 < ITEMS_PER_PREF_RECORD; i+=2 ) {
		if( pref[i] == preftype && pref[i+1] == algo )
		    return 1;
	    }
	}
    }
    return 0;
}

