/* trustdb.c
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

static void upd_pref_record( TRUSTREC *urec, u32 *keyid, PKT_signature *sig );
static void upd_cert_record( KBNODE keyblock, KBNODE signode, u32 *keyid,
		 TRUSTREC *drec, RECNO_LIST *recno_list, int recheck,
		 TRUSTREC *urec, const byte *uidhash, int revoked,
					int *mod_up, int *mod_down );

/* a table used to keep track of ultimately trusted keys
 * which are the ones from our secrings and the trusted keys */
static LOCAL_ID_TABLE ultikey_table;

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

/****************
 * Insert a new item into a recno list
 */
static void
ins_recno_list( RECNO_LIST *head, ulong recno, int type )
{
    RECNO_LIST item = m_alloc( sizeof *item );

    item->recno = recno;
    item->type = type;
    item->next = *head;
    *head = item;
}

static RECNO_LIST
qry_recno_list( RECNO_LIST list, ulong recno, int type	)
{
    for( ; list; list = list->next ) {
	if( list->recno == recno && (!type || list->type == type) )
	    return list;
    }
    return NULL;
}


static void
rel_recno_list( RECNO_LIST *head )
{
    RECNO_LIST r, r2;

    for(r = *head; r; r = r2 ) {
	r2 = r->next;
	m_free(r);
    }
    *head = NULL;
}

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

/****************
 * Get the LID of a public key.
 * Returns: The LID of the key (note, that this may be a shadow dir)
 *	    or 0 if not available.
 */
static ulong
lid_from_keyid( u32 *keyid )
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
	    else if( rc == -1 ) { /* see whether there is a sdir instead */
		u32 akid[2];

		keyid_from_pk( pk, akid );
		rc = tdbio_search_sdir( akid, pk->pubkey_algo, &rec );
		if( !rc )
		    lid = rec.recnum;
	    }
	}
    }
    free_public_key( pk );
    return lid;
}



/***********************************************
 *************	Initialization	****************
 ***********************************************/

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

    while( !(rc=enum_secret_keys( &enum_context, sk, 0 ) ) ) {
	int have_pk = 0;

	keyid_from_sk( sk, keyid );

	if( DBG_TRUST )
	    log_debug("key %08lX: checking secret key\n", (ulong)keyid[1] );

	if( is_secret_key_protected( sk ) < 1 )
	    log_info(_("NOTE: secret key %08lX is NOT protected.\n"),
							    (ulong)keyid[1] );


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

	/* make sure that the pubkey is in the trustdb */
	rc = query_trust_record( pk );
	if( rc == -1 ) { /* put it into the trustdb */
	    rc = insert_trust_record( pk );
	    if( rc ) {
		log_error(_("key %08lX: can't put it into the trustdb\n"),
							    (ulong)keyid[1] );
		goto skip;
	    }
	}
	else if( rc ) {
	    log_error(_("key %08lX: query record failed\n"), (ulong)keyid[1] );
	    goto skip;

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
      skip:
	release_secret_key_parts( sk );
	if( have_pk )
	    release_public_key_parts( pk );
    }
    if( rc != -1 )
	log_error(_("enumerate secret keys failed: %s\n"), g10_errstr(rc) );
    else
	rc = 0;

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
	print_string( fp, p, n, 0 );
	putc('\"', fp);
	putc('\n', fp);
    }
    else {
	tty_printf( "%s \"", text );
	tty_print_string( p, n );
	tty_printf( "\"\n" );
    }
    m_free(p);
}



int
trust_letter( unsigned value )
{
    switch( value ) {
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
	print_string( fp, p, n > 40? 40:n, 0 );
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


static void
check_hint_sig( ulong lid, KBNODE keyblock, u32 *keyid, byte *uidrec_hash,
		TRUSTREC *sigrec, int sigidx, ulong hint_owner )
{
    KBNODE node;
    int rc, state;
    byte uhash[20];
    int is_selfsig;
    PKT_signature *sigpkt = NULL;
    TRUSTREC tmp;
    u32 sigkid[2];
    int revoked = 0;

    if( sigrec->r.sig.sig[sigidx].flag & SIGF_CHECKED )
	log_info(_("NOTE: sig rec %lu[%d] in hintlist "
		   "of %lu but marked as checked\n"),
		    sigrec->recnum, sigidx, hint_owner );
    if( !(sigrec->r.sig.sig[sigidx].flag & SIGF_NOPUBKEY) )
	log_info(_("NOTE: sig rec %lu[%d] in hintlist "
		   "of %lu but not marked\n"),
		    sigrec->recnum, sigidx, hint_owner );

    read_record( sigrec->r.sig.sig[sigidx].lid, &tmp, 0 );
    if( tmp.rectype != RECTYPE_DIR ) {
	/* we need the dir record */
	log_error(_("sig rec %lu[%d] in hintlist "
		    "of %lu does not point to a dir record\n"),
		    sigrec->recnum, sigidx, hint_owner );
	return;
    }
    if( !tmp.r.dir.keylist ) {
	log_error(_("lid %lu: no primary key\n"), tmp.r.dir.lid );
	return;
    }
    read_record(tmp.r.dir.keylist, &tmp, RECTYPE_KEY );
    keyid_from_fingerprint( tmp.r.key.fingerprint,
			    tmp.r.key.fingerprint_len, sigkid );


    /* find the correct signature packet */
    state = 0;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uidpkt = node->pkt->pkt.user_id;

	    if( state )
		break;
	    rmd160_hash_buffer( uhash, uidpkt->name, uidpkt->len );
	    if( !memcmp( uhash, uidrec_hash, 20 ) )
		state = 1;
	}
	else if( state && node->pkt->pkttype == PKT_SIGNATURE ) {
	    sigpkt = node->pkt->pkt.signature;
	    if( sigpkt->keyid[0] == sigkid[0]
		&& sigpkt->keyid[1] == sigkid[1]
		&& ( (sigpkt->sig_class&~3) == 0x10
		     || ( revoked = (sigpkt->sig_class == 0x30)) ) ) {
		state = 2;
		break; /* found */
	    }
	}
    }

    if( !node ) {
	log_info(_("lid %lu: user id not found in keyblock\n"), lid );
	return ;
    }
    if( state != 2 ) {
	log_info(_("lid %lu: user id without signature\n"), lid );
	return ;
    }

    /* and check the sig */
    rc = check_key_signature( keyblock, node, &is_selfsig );
    if( is_selfsig ) {
	log_error(_("lid %lu: self-signature in hintlist\n"), lid );
	return;
    }

    /* FiXME: handling fo SIGF_REVOKED is not correct! */

    if( !rc ) { /* valid signature */
	if( opt.verbose )
	    log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
		    (ulong)keyid[1], lid, uhash[18], uhash[19],
		    (ulong)sigpkt->keyid[1],
		    revoked? _("Valid certificate revocation")
			   : _("Good certificate") );
	sigrec->r.sig.sig[sigidx].flag = SIGF_CHECKED | SIGF_VALID;
	if( revoked )
	    sigrec->r.sig.sig[sigidx].flag |= SIGF_REVOKED;
    }
    else if( rc == G10ERR_NO_PUBKEY ) {
	log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
	      (ulong)keyid[1], lid, uhash[18], uhash[19],
	       (ulong)sigpkt->keyid[1],
		 _("very strange: no public key\n") );
	sigrec->r.sig.sig[sigidx].flag = SIGF_NOPUBKEY;
    }
    else {
	log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
		    (ulong)keyid[1], lid, uhash[18], uhash[19],
		    (ulong)sigpkt->keyid[1], g10_errstr(rc) );
	sigrec->r.sig.sig[sigidx].flag = SIGF_CHECKED;
    }
    sigrec->dirty = 1;
}


/****************
 * Process a hintlist.
 * Fixme: this list is not anymore anchored to another
 *	  record, so it should be put elsewehere in case of an error
 * FIXME: add mod_up/down handling
 */
static void
process_hintlist( ulong hintlist, ulong hint_owner )
{
    ulong hlst_rn;
    int rc;

    for( hlst_rn = hintlist; hlst_rn; ) {
	TRUSTREC hlstrec;
	int hlst_idx;

	read_record( hlst_rn, &hlstrec, RECTYPE_HLST );

	for( hlst_idx=0; hlst_idx < ITEMS_PER_HLST_RECORD; hlst_idx++ ) {
	    TRUSTREC dirrec;
	    TRUSTREC uidrec;
	    TRUSTREC tmprec;
	    KBNODE keyblock = NULL;
	    u32 keyid[2];
	    ulong lid;
	    ulong r1, r2;

	    lid = hlstrec.r.hlst.rnum[hlst_idx];
	    if( !lid )
		continue;

	    read_record( lid, &dirrec, 0 );
	    /* make sure it points to a dir record:
	     * this should be true because it only makes sense to
	     * call this function if the dir record is available */
	    if( dirrec.rectype != RECTYPE_DIR )  {
		log_error(_("hintlist %lu[%d] of %lu "
			    "does not point to a dir record\n"),
			    hlst_rn, hlst_idx, hint_owner );
		continue;
	    }
	    if( !dirrec.r.dir.keylist ) {
		log_error(_("lid %lu does not have a key\n"), lid );
		continue;
	    }

	    /* get the keyblock */
	    read_record( dirrec.r.dir.keylist, &tmprec, RECTYPE_KEY );
	    rc = get_keyblock_byfprint( &keyblock,
					tmprec.r.key.fingerprint,
					tmprec.r.key.fingerprint_len );
	    if( rc ) {
		log_error(_("lid %lu: can't get keyblock: %s\n"),
						    lid, g10_errstr(rc) );
		continue;
	    }
	    keyid_from_fingerprint( tmprec.r.key.fingerprint,
				    tmprec.r.key.fingerprint_len, keyid );

	    /* Walk over all user ids and their signatures and check all
	     * the signature which are created by hint_owner */
	    for( r1 = dirrec.r.dir.uidlist; r1; r1 = uidrec.r.uid.next ) {
		TRUSTREC sigrec;

		read_record( r1, &uidrec, RECTYPE_UID );
		for( r2 = uidrec.r.uid.siglist; r2; r2 = sigrec.r.sig.next ) {
		    int i;

		    read_record( r2, &sigrec, RECTYPE_SIG );
		    sigrec.dirty = 0;
		    for(i=0; i < SIGS_PER_RECORD; i++ ) {
			if( !sigrec.r.sig.sig[i].lid )
			    continue; /* skip deleted sigs */
			if( sigrec.r.sig.sig[i].lid != hint_owner )
			    continue; /* not for us */
			/* some diagnostic messages */
			/* and do the signature check */
			check_hint_sig( lid, keyblock, keyid,
					uidrec.r.uid.namehash,
					&sigrec, i, hint_owner );
		    }
		    if( sigrec.dirty )
			write_record( &sigrec );
		}
	    }
	    release_kbnode( keyblock );
	} /* loop over hlst entries */

	/* delete this hlst record */
	hlst_rn = hlstrec.r.hlst.next;
	delete_record( hlstrec.recnum );
    } /* loop over hintlist */
}


/****************
 * Create or update shadow dir record and return the LID of the record
 */
static ulong
create_shadow_dir( PKT_signature *sig, ulong lid  )
{
    TRUSTREC sdir, hlst, tmphlst;
    ulong recno, newlid;
    int tmpidx=0; /* avoids gcc warnign - this is controlled by tmphlst */
    int rc;

    /* first see whether we already have such a record */
    rc = tdbio_search_sdir( sig->keyid, sig->pubkey_algo, &sdir );
    if( rc && rc != -1 ) {
	log_error(_("tdbio_search_dir failed: %s\n"), g10_errstr(rc));
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
	sdir.r.sdir.hintlist = 0;
	write_record( &sdir );
    }
    newlid = sdir.recnum;
    /* Put the record number into the hintlist.
     * (It is easier to use the lid and not the record number of the
     *	key to save some space (assuming that a signator has
     *	signed more than one user id - and it is easier to implement.)
     */
    tmphlst.recnum = 0;
    for( recno=sdir.r.sdir.hintlist; recno; recno = hlst.r.hlst.next) {
	int i;
	read_record( recno, &hlst, RECTYPE_HLST );
	for( i=0; i < ITEMS_PER_HLST_RECORD; i++ ) {
	    if( !hlst.r.hlst.rnum[i] ) {
		if( !tmphlst.recnum ) {
		    tmphlst = hlst;
		    tmpidx = i;
		}
	    }
	    else if( hlst.r.hlst.rnum[i] == lid )
		return newlid; /* the signature is already in the hintlist */
	}
    }
    /* not yet in the hint list, write it */
    if( tmphlst.recnum ) { /* we have an empty slot */
	tmphlst.r.hlst.rnum[tmpidx] = lid;
	write_record( &tmphlst );
    }
    else { /* must append a new hlst record */
	memset( &hlst, 0, sizeof hlst );
	hlst.recnum = tdbio_new_recnum();
	hlst.rectype = RECTYPE_HLST;
	hlst.r.hlst.next = sdir.r.sdir.hintlist;
	hlst.r.hlst.rnum[0] = lid;
	write_record( &hlst );
	sdir.r.sdir.hintlist = hlst.recnum;
	write_record( &sdir );
    }

    return newlid;
}


/****************
 * This function checks the given public key and inserts or updates
 * the keyrecord from the trustdb.  Revocation certificates
 * are handled here and the keybinding of subkeys is checked.
 * Hmmm: Should we check here, that the key has at least one valid
 * user ID or do we allow keys w/o user ID?
 *
 * keyblock points to the first node in the keyblock,
 * keynode is the node with the public key to check
 * (either primary or secondary), keyid is the keyid of
 * the primary key, drec is the directory record and recno_list
 * is a list used to keep track of visited records.
 * Existing keyflags are recalculated if recheck is true.
 */
static void
upd_key_record( KBNODE keyblock, KBNODE keynode, u32 *keyid,
		TRUSTREC *drec, RECNO_LIST *recno_list, int recheck )
{
    TRUSTREC krec;
    KBNODE  node;
    PKT_public_key *pk = keynode->pkt->pkt.public_key;
    ulong lid = drec->recnum;
    byte fpr[MAX_FINGERPRINT_LEN];
    size_t fprlen;
    ulong recno, newrecno;
    int keybind_seen = 0;
    int revoke_seen = 0;
    int rc;

    fingerprint_from_pk( pk, fpr, &fprlen );
    /* do we already have this key? */
    for( recno=drec->r.dir.keylist; recno; recno = krec.r.key.next ) {
	read_record( recno, &krec, RECTYPE_KEY );
	if( krec.r.key.fingerprint_len == fprlen
	    && !memcmp( krec.r.key.fingerprint, fpr, fprlen ) )
	    break;
    }
    if( recno ) { /* yes */
	ins_recno_list( recno_list, recno, RECTYPE_KEY );
    }
    else { /* no: insert this new key */
	recheck = 1; /* same as recheck */
	memset( &krec, 0, sizeof(krec) );
	krec.rectype = RECTYPE_KEY;
	krec.r.key.lid = lid;
	krec.r.key.pubkey_algo = pk->pubkey_algo;
	krec.r.key.fingerprint_len = fprlen;
	memcpy(krec.r.key.fingerprint, fpr, fprlen );
	krec.recnum = newrecno = tdbio_new_recnum();
	write_record( &krec );
	ins_recno_list( recno_list, newrecno, RECTYPE_KEY );
	/* and put this new record at the end of the keylist */
	if( !(recno=drec->r.dir.keylist) ) {
	    /* this is the first key */
	    drec->r.dir.keylist = newrecno;
	    drec->dirty = 1;
	}
	else { /* we already have a key, append the new one */
	    TRUSTREC save = krec;
	    for( ; recno; recno = krec.r.key.next )
		read_record( recno, &krec, RECTYPE_KEY );
	    krec.r.key.next = newrecno;
	    write_record( &krec );
	    krec = save;
	}
    }

    if( !recheck && (krec.r.key.keyflags & KEYF_CHECKED) )
	return;

    /* check keybindings and revocations */
    krec.r.key.keyflags = 0;
    if( keynode->pkt->pkttype == PKT_PUBLIC_KEY ) {
	/* we assume that a primary key is always valid
	 * and check later whether we have a revocation */
	krec.r.key.keyflags |= KEYF_CHECKED | KEYF_VALID;
    }

    for( node=keynode->next; node; node = node->next ) {
	PKT_signature *sig;

	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* ready (we check only one key at a time) */
	else if( node->pkt->pkttype != PKT_SIGNATURE )
	    continue;

	sig = node->pkt->pkt.signature;

	if( keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1] )
	    continue; /* here we only care about a self-signatures */

	if( sig->sig_class == 0x18 && !keybind_seen ) { /* a keybinding */
	    if( keynode->pkt->pkttype == PKT_PUBLIC_KEY )
		continue; /* oops, ignore subkey binding on main key */

	    /* we check until we find a valid keybinding */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info(_(
			"key %08lX.%lu: Good subkey binding\n"),
			 (ulong)keyid_from_pk(pk,NULL), lid );
		krec.r.key.keyflags |= KEYF_CHECKED | KEYF_VALID;
	    }
	    else {
		log_info(_(
		  "key %08lX.%lu: Invalid subkey binding: %s\n"),
		    (ulong)keyid_from_pk(pk,NULL), lid, g10_errstr(rc) );
		krec.r.key.keyflags |= KEYF_CHECKED;
		krec.r.key.keyflags &= ~KEYF_VALID;
	    }
	    keybind_seen = 1;
	}
	else if( sig->sig_class == 0x20 && !revoke_seen ) {
	    if( keynode->pkt->pkttype == PKT_PUBLIC_SUBKEY )
		continue; /* a subkey is not expected here */

	    /* This is a key revocation certificate: check it */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info(_(
			"key %08lX.%lu: Valid key revocation\n"),
			 (ulong)keyid_from_pk(pk,NULL), lid );
		krec.r.key.keyflags |= KEYF_REVOKED;
	    }
	    else {
		log_info(_(
		  "key %08lX.%lu: Invalid key revocation: %s\n"),
		  (ulong)keyid_from_pk(pk,NULL), lid, g10_errstr(rc) );
	    }
	    revoke_seen = 1;
	}
	else if( sig->sig_class == 0x28 && !revoke_seen ) {
	    if( keynode->pkt->pkttype == PKT_PUBLIC_KEY )
		continue; /* a mainkey is not expected here */
	    /* This is a subkey revocation certificate: check it */
	    /* fixme: we should also check the revocation
	     * is newer than the key (OpenPGP) */
	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc ) {
		if( opt.verbose )
		    log_info(_(
			"key %08lX.%lu: Valid subkey revocation\n"),
			 (ulong)keyid_from_pk(pk,NULL), lid );
		krec.r.key.keyflags |= KEYF_REVOKED;
	    }
	    else {
		log_info(_(
		  "key %08lX.%lu: Invalid subkey binding: %s\n"),
		  (ulong)keyid_from_pk(pk,NULL), lid, g10_errstr(rc) );
	    }
	    revoke_seen = 1;
	}
    }

    write_record( &krec );
}


/****************
 * This function checks the given user ID and inserts or updates
 * the uid record of the trustdb.  Revocation certificates
 * are handled here.
 *
 * keyblock points to the first node in the keyblock,
 * uidnode is the node with the user id to check
 * keyid is the keyid of
 * the primary key, drec is the directory record and recno_list
 * is a list used to keep track of visited records.
 * Existing uidflags are recalculated if recheck is true.
 */
static void
upd_uid_record( KBNODE keyblock, KBNODE uidnode, u32 *keyid,
		TRUSTREC *drec, RECNO_LIST *recno_list,
		int recheck, int *mod_up, int *mod_down )
{
    ulong lid = drec->recnum;
    PKT_user_id *uid = uidnode->pkt->pkt.user_id;
    TRUSTREC urec;
    PKT_signature *selfsig = NULL;
    byte uidhash[20];
    KBNODE node;
    ulong recno, newrecno;
    int rc;

    if( DBG_TRUST )
	log_debug("upd_uid_record for %08lX/%02X%02X\n",
			       (ulong)keyid[1], uidhash[18], uidhash[19]);

    /* see whether we already have an uid record */
    rmd160_hash_buffer( uidhash, uid->name, uid->len );
    for( recno=drec->r.dir.uidlist; recno; recno = urec.r.uid.next ) {
	read_record( recno, &urec, RECTYPE_UID );
	if( !memcmp( uidhash, urec.r.uid.namehash, 20 ) )
	    break;
    }
    if( recno ) { /* we already have this record */
	ins_recno_list( recno_list, recno, RECTYPE_UID );
    }
    else { /* new user id */
	recheck = 1; /* insert is the same as a recheck */
	memset( &urec, 0 , sizeof(urec) );
	urec.rectype = RECTYPE_UID;
	urec.r.uid.lid = drec->recnum;
	memcpy(urec.r.uid.namehash, uidhash, 20 );
	urec.recnum = newrecno = tdbio_new_recnum();
	write_record( &urec );
	ins_recno_list( recno_list, newrecno, RECTYPE_UID );
	/* and put this new record at the end of the uidlist */
	if( !(recno=drec->r.dir.uidlist) ) { /* this is the first uid */
	    drec->r.dir.uidlist = newrecno;
	    drec->dirty = 1;
	}
	else { /* we already have an uid, append it to the list */
	    TRUSTREC save = urec;
	    for( ; recno; recno = urec.r.key.next )
		read_record( recno, &urec, RECTYPE_UID );
	    urec.r.uid.next = newrecno;
	    write_record( &urec );
	    urec = save;
	}
    }

    if( recheck || !(urec.r.uid.uidflags & UIDF_CHECKED) ) {
	unsigned orig_uidflags = urec.r.uid.uidflags;

	urec.r.uid.uidflags = 0;
	/* first check regular self signatures */
	for( node=uidnode->next; node; node = node->next ) {
	    PKT_signature *sig;

	    if( node->pkt->pkttype == PKT_USER_ID )
		break; /* ready */
	    if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
		break; /* ready */
	    if( node->pkt->pkttype != PKT_SIGNATURE )
		continue;

	    sig = node->pkt->pkt.signature;

	    if( keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1] )
		continue; /* not a self signature */

	    if( (sig->sig_class&~3) == 0x10 ) { /* regular self signature */
		rc = check_key_signature( keyblock, node, NULL );
		if( !rc ) {
		    if( opt.verbose )
			log_info( "uid %08lX.%lu/%02X%02X: %s\n",
			   (ulong)keyid[1], lid, uidhash[18], uidhash[19],
				  _("Good self-signature") );
		    urec.r.uid.uidflags |= UIDF_CHECKED | UIDF_VALID;
		    if( !selfsig )
			selfsig = sig; /* use the first valid sig */
		    else if( sig->timestamp > selfsig->timestamp
			     && sig->sig_class >= selfsig->sig_class )
			selfsig = sig; /* but this one is newer */
		}
		else {
		    log_info( "uid %08lX/%02X%02X: %s: %s\n",
			       (ulong)keyid[1], uidhash[18], uidhash[19],
			      _("Invalid self-signature"),
			       g10_errstr(rc) );
		    urec.r.uid.uidflags |= UIDF_CHECKED;
		}
	    }
	}

	/* and now check for revocations- we must do this after the
	 * self signature check because a selfsignature which is newer
	 * than a revocation makes the revocation invalid.
	 * Fixme: Is this correct - check with rfc2440
	 */
	for( node=uidnode->next; node; node = node->next ) {
	    PKT_signature *sig;

	    if( node->pkt->pkttype == PKT_USER_ID )
		break; /* ready */
	    if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
		break; /* ready */
	    if( node->pkt->pkttype != PKT_SIGNATURE )
		continue;

	    sig = node->pkt->pkt.signature;

	    if( keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1] )
		continue; /* not a self signature */

	    if( sig->sig_class == 0x30 ) { /* cert revocation */
		rc = check_key_signature( keyblock, node, NULL );
		if( !rc && selfsig && selfsig->timestamp > sig->timestamp ) {
		    log_info( "uid %08lX.%lu/%02X%02X: %s\n",
			   (ulong)keyid[1], lid, uidhash[18], uidhash[19],
			   _("Valid user ID revocation skipped "
			     "due to a newer self signature\n") );
		}
		else if( !rc ) {
		    if( opt.verbose )
			log_info( "uid %08lX.%lu/%02X%02X: %s\n",
			   (ulong)keyid[1], lid, uidhash[18], uidhash[19],
				 _("Valid user ID revocation\n") );
		    urec.r.uid.uidflags |= UIDF_CHECKED | UIDF_VALID;
		    urec.r.uid.uidflags |= UIDF_REVOKED;
		}
		else {
		    log_info("uid %08lX/%02X%02X: %s: %s\n",
				(ulong)keyid[1], uidhash[18], uidhash[19],
			       _("Invalid user ID revocation"),
							g10_errstr(rc) );
		}
	    }

	}

	if( orig_uidflags != urec.r.uid.uidflags ) {
	    write_record( &urec );
	    if(   !( urec.r.uid.uidflags & UIDF_VALID )
		|| ( urec.r.uid.uidflags & UIDF_REVOKED ) )
		*mod_down=1;
	    else
		*mod_up=1; /*(maybe a new user id)*/
	    /* Hmmm, did we catch changed expiration dates? */
	}

    } /* end check self-signatures */


    if( (urec.r.uid.uidflags & (UIDF_CHECKED|UIDF_VALID))
	!= (UIDF_CHECKED|UIDF_VALID) )
	return; /* user ID is not valid, so no need to check more things */

    /* check the preferences */
    if( selfsig )
	upd_pref_record( &urec, keyid, selfsig );

    /* Now we va check the certication signatures */
    for( node=uidnode->next; node; node = node->next ) {
	PKT_signature *sig;

	if( node->pkt->pkttype == PKT_USER_ID )
	    break; /* ready */
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break; /* ready */
	if( node->pkt->pkttype != PKT_SIGNATURE )
	    continue;

	sig = node->pkt->pkt.signature;

	if( keyid[0] == sig->keyid[0] || keyid[1] == sig->keyid[1] )
	    continue; /* here we skip the self-signatures */

	if( (sig->sig_class&~3) == 0x10 ) { /* regular certification */
	    upd_cert_record( keyblock, node, keyid, drec, recno_list,
			     recheck, &urec, uidhash, 0, mod_up, mod_down );
	}
	else if( sig->sig_class == 0x30 ) { /* cert revocation */
	    upd_cert_record( keyblock, node, keyid, drec, recno_list,
			     recheck, &urec, uidhash, 1, mod_up, mod_down );
	}
    } /* end check certificates */

    write_record( &urec );
}


static void
upd_pref_record( TRUSTREC *urec, u32 *keyid, PKT_signature *sig )
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
    TRUSTREC prec;
    ulong lid = urec->r.uid.lid ;
    const byte *uidhash = urec->r.uid.namehash;
    const byte *s;
    size_t n;
    int k, i;
    ulong recno;
    byte prefs_sig[200];
    int n_prefs_sig = 0;
    byte prefs_rec[200];
    int n_prefs_rec = 0;

    if( DBG_TRUST )
	log_debug("upd_pref_record for %08lX.%lu/%02X%02X\n",
			  (ulong)keyid[1], lid, uidhash[18], uidhash[19] );


    /* check for changed preferences */
    for(k=0; ptable[k].subpkttype; k++ ) {
	s = parse_sig_subpkt2( sig, ptable[k].subpkttype, &n );
	if( s ) {
	    for( ; n; n--, s++ ) {
		if( n_prefs_sig >= DIM(prefs_sig)-1 ) {
		    log_info("uid %08lX.%lu/%02X%02X: %s\n",
			      (ulong)keyid[1], lid, uidhash[18], uidhash[19],
			      _("Too many preferences") );
		    break;
		}
		prefs_sig[n_prefs_sig++] = ptable[k].preftype;
		prefs_sig[n_prefs_sig++] = *s;
	    }
	}
    }
    for( recno=urec->r.uid.prefrec; recno; recno = prec.r.pref.next ) {
	read_record( recno, &prec, RECTYPE_PREF );
	for(i = 0; i < ITEMS_PER_PREF_RECORD; i +=2 )  {
	    if( n_prefs_rec >= DIM(prefs_rec)-1 ) {
		log_info("uid %08lX.%lu/%02X%02X: %s\n",
			  (ulong)keyid[1], lid, uidhash[18], uidhash[19],
			  _("Too many preference items") );
		break;
	    }
	    if( prec.r.pref.data[i] ) {
		prefs_rec[n_prefs_rec++] = prec.r.pref.data[i];
		prefs_rec[n_prefs_rec++] = prec.r.pref.data[i+1];
	    }
	}
    }
    if( n_prefs_sig == n_prefs_rec
	&& !memcmp( prefs_sig, prefs_rec, n_prefs_sig ) )
	return;  /* not changed */

    /* Preferences have changed:  Delete all pref records
     * This is much simpler than checking whether we have to
     * do update the record at all - the record cache may care about it
     */
    for( recno=urec->r.uid.prefrec; recno; recno = prec.r.pref.next ) {
	read_record( recno, &prec, RECTYPE_PREF );
	delete_record( recno );
    }

    if( n_prefs_sig > ITEMS_PER_PREF_RECORD )
	 log_info(_("WARNING: can't yet handle long pref records\n"));

    memset( &prec, 0, sizeof prec );
    prec.recnum = tdbio_new_recnum();
    prec.rectype = RECTYPE_PREF;
    prec.r.pref.lid = lid;
    if( n_prefs_sig <= ITEMS_PER_PREF_RECORD )
	memcpy( prec.r.pref.data, prefs_sig, n_prefs_sig );
    else { /* need more than one pref record */
	TRUSTREC tmp;
	ulong nextrn;
	byte *pp = prefs_sig;

	n = n_prefs_sig;
	memcpy( prec.r.pref.data, pp, ITEMS_PER_PREF_RECORD );
	n -= ITEMS_PER_PREF_RECORD;
	pp += ITEMS_PER_PREF_RECORD;
	nextrn = prec.r.pref.next = tdbio_new_recnum();
	do {
	    memset( &tmp, 0, sizeof tmp );
	    tmp.recnum = nextrn;
	    tmp.rectype = RECTYPE_PREF;
	    tmp.r.pref.lid = lid;
	    if( n <= ITEMS_PER_PREF_RECORD ) {
		memcpy( tmp.r.pref.data, pp, n );
		n = 0;
	    }
	    else {
		memcpy( tmp.r.pref.data, pp, ITEMS_PER_PREF_RECORD );
		n -= ITEMS_PER_PREF_RECORD;
		pp += ITEMS_PER_PREF_RECORD;
		nextrn = tmp.r.pref.next = tdbio_new_recnum();
	    }
	    write_record( &tmp );
	} while( n );
    }
    write_record( &prec );
    urec->r.uid.prefrec = prec.recnum;
    urec->dirty = 1;
}


static void
upd_cert_record( KBNODE keyblock, KBNODE signode, u32 *keyid,
		 TRUSTREC *drec, RECNO_LIST *recno_list, int recheck,
		 TRUSTREC *urec, const byte *uidhash, int revoked,
		 int *mod_up, int *mod_down )
{
    /* We simply insert the signature into the sig records but
     * avoid duplicate ones.  We do not check them here because
     * there is a big chance, that we import required public keys
     * later.  The problem with this is that we must somewhere store
     * the information about this signature (we need a record id).
     * We do this by using the record type shadow dir, which will
     * be converted to a dir record as when the missing public key
     * gets inserted into the trustdb.
     */
    ulong lid = drec->recnum;
    PKT_signature *sig = signode->pkt->pkt.signature;
    TRUSTREC rec;
    ulong recno;
    TRUSTREC delrec;
    int delrecidx=0;
    int newflag = 0;
    ulong newlid = 0;
    ulong pk_lid = 0;
    int found_sig = 0;
    int found_delrec = 0;
    int rc;


    if( DBG_TRUST )
	log_debug("upd_cert_record for %08lX.?/%02X%02X/%08lX\n",
			      (ulong)keyid[1], uidhash[18],
			       uidhash[19], (ulong)sig->keyid[1] );

    delrec.recnum = 0;

    /* get the LID of the pubkey of the signature under verification */
    pk_lid = lid_from_keyid( sig->keyid );

    /* Loop over all signatures just in case one is not correctly
     * marked.	If we see the correct signature, set a flag.
     * delete duplicate signatures (should not happen but...) */
    for( recno = urec->r.uid.siglist; recno; recno = rec.r.sig.next ) {
	int i;

	read_record( recno, &rec, RECTYPE_SIG );
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    TRUSTREC tmp;
	    if( !rec.r.sig.sig[i].lid ) {
		/* (remember this unused slot) */
		if( !found_delrec && !delrec.recnum ) {
		    delrec = rec;
		    delrecidx = i;
		    found_delrec=1;
		}
		continue; /* skip unused slots */
	    }

	    if( rec.r.sig.sig[i].lid == pk_lid ) {
		if( found_sig ) {
		    log_info( "sig %08lX.%lu/%02X%02X/%08lX: %s\n",
			      (ulong)keyid[1], lid, uidhash[18],
			       uidhash[19], (ulong)sig->keyid[1],
			     _("duplicated certificate - deleted") );
		    rec.r.sig.sig[i].lid = 0;
		    rec.dirty = 1;
		    continue;
		}
		found_sig = 1;
	    }
	    if( !recheck && !revoked && (rec.r.sig.sig[i].flag & SIGF_CHECKED))
		continue; /* we already checked this signature */
	    if( !recheck && (rec.r.sig.sig[i].flag & SIGF_NOPUBKEY) )
		continue; /* we do not have the public key */

	    read_record( rec.r.sig.sig[i].lid, &tmp, 0 );
	    if( tmp.rectype == RECTYPE_DIR ) {
		/* the public key is in the trustdb: check sig */
		rc = check_key_signature( keyblock, signode, NULL );
		if( !rc ) { /* valid signature */
		    if( opt.verbose )
			log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
				(ulong)keyid[1], lid, uidhash[18],
				uidhash[19], (ulong)sig->keyid[1],
				revoked? _("Valid certificate revocation")
				       : _("Good certificate") );
		    rec.r.sig.sig[i].flag = SIGF_CHECKED | SIGF_VALID;
		    if( revoked ) { /* we are investigating revocations */
			rec.r.sig.sig[i].flag |= SIGF_REVOKED;
			*mod_down = 1;
		    }
		    else
			*mod_up = 1;
		}
		else if( rc == G10ERR_NO_PUBKEY ) {
		    /* This may happen if the key is still in the trustdb
		     * but not available in the keystorage */
		    if( (rec.r.sig.sig[i].flag & SIGF_CHECKED) )
			log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
				  (ulong)keyid[1], lid, uidhash[18],
				 uidhash[19], (ulong)sig->keyid[1],
				 _("public key not anymore available") );
		    rec.r.sig.sig[i].flag = SIGF_NOPUBKEY;
		    *mod_down = 1;
		    if( revoked )
			rec.r.sig.sig[i].flag |= SIGF_REVOKED;
		}
		else {
		    log_info("sig %08lX.%lu/%02X%02X/%08lX: %s: %s\n",
				(ulong)keyid[1], lid, uidhash[18],
				uidhash[19], (ulong)sig->keyid[1],
				revoked? _("Invalid certificate revocation")
				       : _("Invalid certificate"),
						    g10_errstr(rc));
		    rec.r.sig.sig[i].flag = SIGF_CHECKED;
		    if( revoked ) {
			rec.r.sig.sig[i].flag |= SIGF_REVOKED;
			*mod_down = 1;
		    }
		}
		rec.dirty = 1;
	    }
	    else if( tmp.rectype == RECTYPE_SDIR ) {
		/* must check that it is the right one */
		if( tmp.r.sdir.keyid[0] == sig->keyid[0]
		    && tmp.r.sdir.keyid[1] == sig->keyid[1]
		    && (!tmp.r.sdir.pubkey_algo
			 || tmp.r.sdir.pubkey_algo == sig->pubkey_algo )) {
		    if( !(rec.r.sig.sig[i].flag & SIGF_NOPUBKEY) )
			log_info(_("uid %08lX.%lu/%02X%02X: "
				"has shadow dir %lu but is not yet marked.\n"),
				(ulong)keyid[1], lid,
				uidhash[18], uidhash[19], tmp.recnum );
		    rec.r.sig.sig[i].flag = SIGF_NOPUBKEY;
		    if( revoked )
			rec.r.sig.sig[i].flag |= SIGF_REVOKED;
		    rec.dirty = 1;
		    /* fixme: should we verify that the record is
		     * in the hintlist? - This case here should anyway
		     * never occur */
		}
	    }
	    else {
		log_error(_("sig record %lu[%d] points to wrong record.\n"),
			    rec.r.sig.sig[i].lid, i );
		tdbio_invalid();
	    }
	}
	if( found_delrec && delrec.recnum ) {
	    delrec = rec;
	    found_delrec = 0; /* we only want the first one */
	}
	if( rec.dirty ) {
	    write_record( &rec );
	    rec.dirty = 0;
	}
    }

    if( found_sig )
	return;

    /* at this point, we have verified, that the signature is not in
     * our list of signatures.	Add a new record with that signature
     * and if the public key is there, check the signature. */

    if( !pk_lid ) /* we have already seen that there is no pubkey */
	rc = G10ERR_NO_PUBKEY;
    else
	rc = check_key_signature( keyblock, signode, NULL );

    if( !rc ) { /* valid signature */
	if( opt.verbose )
	    log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
			  (ulong)keyid[1], lid, uidhash[18],
			   uidhash[19], (ulong)sig->keyid[1],
				revoked? _("Valid certificate revocation")
				       : _("Good certificate") );
	newlid = pk_lid;  /* this is the pk of the signature */
	newflag = SIGF_CHECKED | SIGF_VALID;
	if( revoked ) {
	    newflag |= SIGF_REVOKED;
	    *mod_down = 1;
	}
	else
	    *mod_up = 1;
    }
    else if( rc == G10ERR_NO_PUBKEY ) {
	if( opt.verbose > 1 || DBG_TRUST )
	    log_info("sig %08lX.%lu/%02X%02X/%08lX: %s\n",
		     (ulong)keyid[1], lid, uidhash[18],
		      uidhash[19], (ulong)sig->keyid[1], g10_errstr(rc) );
	newlid = create_shadow_dir( sig, lid );
	newflag = SIGF_NOPUBKEY;
	if( revoked )
	    newflag |= SIGF_REVOKED;
    }
    else {
	log_info( "sig %08lX.%lu/%02X%02X/%08lX: %s: %s\n",
		    (ulong)keyid[1], lid, uidhash[18], uidhash[19],
			      (ulong)sig->keyid[1],
		revoked? _("Invalid certificate revocation")
		       : _("Invalid certificate"),
					    g10_errstr(rc));
	newlid = create_shadow_dir( sig, lid );
	newflag = SIGF_CHECKED;
	if( revoked )
	    newflag |= SIGF_REVOKED;
	*mod_down = 1;
    }

    if( delrec.recnum ) { /* we can reuse an unused slot */
	delrec.r.sig.sig[delrecidx].lid = newlid;
	delrec.r.sig.sig[delrecidx].flag= newflag;
	write_record( &delrec );
    }
    else { /* we must insert a new sig record */
	TRUSTREC tmp;

	memset( &tmp, 0, sizeof tmp );
	tmp.recnum = tdbio_new_recnum();
	tmp.rectype = RECTYPE_SIG;
	tmp.r.sig.lid = lid;
	tmp.r.sig.next = urec->r.uid.siglist;
	tmp.r.sig.sig[0].lid = newlid;
	tmp.r.sig.sig[0].flag= newflag;
	write_record( &tmp );
	urec->r.uid.siglist = tmp.recnum;
	urec->dirty = 1;
    }
}


/****************
 * Update all the info from the public keyblock.
 * The key must already exist in the keydb.
 * This function is responsible for checking the signatures in cases
 * where the public key is already available.  If we do not have the public
 * key, the check is done by some special code in insert_trust_record().
 */
int
update_trust_record( KBNODE keyblock, int recheck, int *modified )
{
    PKT_public_key *primary_pk;
    KBNODE node;
    TRUSTREC drec;
    TRUSTREC krec;
    TRUSTREC urec;
    TRUSTREC prec;
    TRUSTREC helprec;
    int rc = 0;
    u32 keyid[2]; /* keyid of primary key */
    ulong recno, lastrecno;
    int mod_up = 0;
    int mod_down = 0;
    RECNO_LIST recno_list = NULL; /* list of verified records */
    /* fixme: replace recno_list by a lookup on node->recno */

    if( opt.dry_run )
	return 0;

    init_trustdb();
    if( modified )
	*modified = 0;

    node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    primary_pk = node->pkt->pkt.public_key;
    rc = get_dir_record( primary_pk, &drec );
    if( rc )
	return rc;
    if( !primary_pk->local_id )
	primary_pk->local_id = drec.recnum;

    keyid_from_pk( primary_pk, keyid );

    /* fixme: check that the keyblock has a valid structure */

    rc = tdbio_begin_transaction();
    if( rc )
	return rc;

    /* update the keys */
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    upd_key_record( keyblock, node, keyid,
			    &drec, &recno_list, recheck );
    }
    /* update the user IDs */
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID )
	    upd_uid_record( keyblock, node, keyid,
			    &drec, &recno_list, recheck, &mod_up, &mod_down );
    }

    /* delete keyrecords from the trustdb which are not anymore used */
    /* should we really do this, or is it better to keep them and */
    /* mark as unused? */
    /* And set the revocation flag into the dir record */
    drec.r.dir.dirflags &= ~DIRF_REVOKED;
    lastrecno = 0;
    for( recno=drec.r.dir.keylist; recno; recno = krec.r.key.next ) {
	read_record( recno, &krec, RECTYPE_KEY );
	if( recno == drec.r.dir.keylist ) { /* this is the primary key */
	    if( (krec.r.key.keyflags & KEYF_REVOKED) ) {
		drec.r.dir.dirflags |= DIRF_REVOKED;
		drec.dirty = 1;
	    }
	}

	if( !qry_recno_list( recno_list, recno, RECTYPE_KEY ) ) {
	    /* delete this one */
	    if( !lastrecno ) {
		drec.r.dir.keylist = krec.r.key.next;
		drec.dirty = 1;
	    }
	    else {
		read_record( lastrecno, &helprec, RECTYPE_KEY );
		helprec.r.key.next = krec.r.key.next;
		write_record( &helprec );
	    }
	    delete_record( recno );
	}
	else
	    lastrecno = recno;
    }
    /* delete uid records and sig and their pref records from the
     * trustdb which are not anymore used */
    lastrecno = 0;
    for( recno=drec.r.dir.uidlist; recno; recno = urec.r.uid.next ) {
	read_record( recno, &urec, RECTYPE_UID );
	if( !qry_recno_list( recno_list, recno, RECTYPE_UID ) ) {
	    ulong r2;
	    /* delete this one */
	    if( !lastrecno ) {
		drec.r.dir.uidlist = urec.r.uid.next;
		drec.dirty = 1;
	    }
	    else {
		read_record( lastrecno, &helprec, RECTYPE_UID );
		helprec.r.uid.next = urec.r.uid.next;
		write_record( &helprec );
	    }
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
	else
	    lastrecno = recno;
    }



    if( rc )
	rc = tdbio_cancel_transaction();
    else {
	if( modified && tdbio_is_dirty() )
	    *modified = 1;
	drec.r.dir.dirflags |= DIRF_CHECKED;
	drec.r.dir.valcheck = 0;
	write_record( &drec );
	tdbio_write_modify_stamp( mod_up, mod_down );
	rc = tdbio_end_transaction();
    }
    rel_recno_list( &recno_list );
    return rc;
}


/****************
 * Insert a trust record into the TrustDB
 * This function assumes that the record does not yet exist.
 */
int
insert_trust_record( PKT_public_key *orig_pk )
{
    TRUSTREC dirrec;
    TRUSTREC shadow;
    KBNODE keyblock = NULL;
    KBNODE node;
    byte fingerprint[MAX_FINGERPRINT_LEN];
    size_t fingerlen;
    int rc = 0;
    ulong hintlist = 0;
    PKT_public_key *pk;


    if( opt.dry_run )
	return 0;

    init_trustdb();

    fingerprint_from_pk( orig_pk, fingerprint, &fingerlen );

    /* fixme: assert that we do not have this record.
     * we can do this by searching for the primary keyid
     *
     * fixme: If there is no such key we should look whether one
     * of the subkeys has been used to sign another key and in this case
     * we got the key anyway - this is because a secondary key can't be used
     * without a primary key (it is needed to bind the secondary one
     * to the primary one which has the user ids etc.)
     */

    if( orig_pk->local_id )
	log_debug("insert_trust_record with pk->local_id=%lu (1)\n",
						   orig_pk->local_id );

    /* get the keyblock which has the key */
    rc = get_keyblock_byfprint( &keyblock, fingerprint, fingerlen );
    if( rc ) { /* that should never happen */
	log_error( _("insert_trust_record: keyblock not found: %s\n"),
							  g10_errstr(rc) );
	goto leave;
    }

    /* make sure that we use the primary key */
    pk = find_kbnode( keyblock, PKT_PUBLIC_KEY )->pkt->pkt.public_key;

    if( pk->local_id ) {
	orig_pk->local_id = pk->local_id;
	log_debug("insert_trust_record with pk->local_id=%lu (2)\n",
							pk->local_id );
	rc = update_trust_record( keyblock, 1, NULL );
	release_kbnode( keyblock );
	return rc;
    }

    /* We have to look for a shadow dir record which must be reused
     * as the dir record. And: check all signatures which are listed
     * in the hintlist of the shadow dir record.
     */
    rc = tdbio_search_sdir( pk->keyid, pk->pubkey_algo, &shadow );
    if( rc && rc != -1 ) {
	log_error(_("tdbio_search_dir failed: %s\n"), g10_errstr(rc));
	tdbio_invalid();
    }
    memset( &dirrec, 0, sizeof dirrec );
    dirrec.rectype = RECTYPE_DIR;
    if( !rc ) {
	/* hey, great: this key has already signed other keys
	 * convert this to a real directory entry */
	hintlist = shadow.r.sdir.hintlist;
	dirrec.recnum = shadow.recnum;
    }
    else {
	dirrec.recnum = tdbio_new_recnum();
    }
    dirrec.r.dir.lid = dirrec.recnum;
    write_record( &dirrec );

    /* out the LID into the keyblock */
    pk->local_id = dirrec.r.dir.lid;
    orig_pk->local_id = dirrec.r.dir.lid;
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
    rc = update_trust_record( keyblock, 1, NULL );
    if( !rc )
	process_hintlist( hintlist, dirrec.r.dir.lid );

  leave:
    if( rc && hintlist )
	; /* fixme: the hintlist is not anymore anchored */
    release_kbnode( keyblock );
    do_sync();
    return rc;
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
 * Fixme: add a fastscan mode which stops ad valid validity nodes.
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
    keynode->n.k.ownertrust = dirrec.r.dir.ownertrust;

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
	      #if 0 /* optimazation - fixme: reenable this later */
		if( tn->n.k.buckstop ) {
		    /* ultimately trusted key found:
		     * no need to check more signatures of this uid */
		    sigrec.r.sig.next = 0;
		    break;
		}
	      #endif
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
	if( new_trust > rec.r.dir.ownertrust )
	    *retflgs |= 16; /* modified up */
	else
	    *retflgs |= 32; /* modified down */
    }
    rec.r.dir.ownertrust = new_trust;
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
    for( ur=node->list; ur; ur = ur->next ) {
	assert( ur->is_uid );
	/* loop over all signators */
	for(kr=ur->list; kr; kr = kr->next ) {
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
	}
	/* fixme: We can move this test into the loop to stop as soon as
	 * we have a level of FULLY and return from this function
	 * We dont do this now to get better debug output */
	if( ur->n.u.fully_count >= opt.completes_needed
	    || ur->n.u.marginal_count >= opt.marginals_needed )
	    ur->n.u.validity = TRUST_FULLY;
	else if( ur->n.u.fully_count || ur->n.u.marginal_count )
	    ur->n.u.validity = TRUST_MARGINAL;

	if( ur->n.u.validity >= max_validity )
	    max_validity = ur->n.u.validity;
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
    if( namehash ) {
	/* find the matching user id.
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
	log_error(_("Ooops, no user ids\n"));
	return G10ERR_TRUSTDB;
    }

    if( retflgs )
	*retflgs &= ~(16|32);  /* reset the 2 special flags */


    if( namehash ) {
	/* Fixme: use the cache */
	*validity = verify_key( opt.max_cert_depth, dr, namehash,
							add_fnc, retflgs );
    }
    else if( !add_fnc
	&& tdbio_db_matches_options()
	&& dr->r.dir.valcheck
	    > tdbio_read_modify_stamp( (dr->r.dir.validity < TRUST_FULLY) )
	&& dr->r.dir.validity )
	*validity = dr->r.dir.validity;
    else
	*validity = verify_key( opt.max_cert_depth, dr, NULL,
							add_fnc, retflgs );

    if( !(*validity & TRUST_MASK) )
	*validity = TRUST_UNDEFINED;

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


/****************
 * Put new entries  from the pubrings into the trustdb.
 * This function honors the sig flags to speed up the check.
 */
void
update_trustdb( )
{
    KBNODE keyblock = NULL;
    KBPOS kbpos;
    int rc;

    if( opt.dry_run )
	return;

    init_trustdb();
    rc = enum_keyblocks( 0, &kbpos, &keyblock );
    if( !rc ) {
	ulong count=0, upd_count=0, err_count=0, new_count=0;

	while( !(rc = enum_keyblocks( 1, &kbpos, &keyblock )) ) {
	    int modified;

	    rc = update_trust_record( keyblock, 1, &modified );
	    if( rc == -1 ) { /* not yet in trustdb: insert */
		PKT_public_key *pk = keyblock->pkt->pkt.public_key;
		rc = insert_trust_record( pk );
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
		log_error(_("lid %lu: update failed: %s\n"),
			 lid_from_keyblock(keyblock), g10_errstr(rc) );
		err_count++;
	    }
	    else if( modified ) {
		if( opt.verbose )
		    log_info(_("lid %lu: updated\n"),
					lid_from_keyblock(keyblock));
		upd_count++;
	    }
	    else if( opt.verbose > 1 )
		log_info(_("lid %lu: okay\n"), lid_from_keyblock(keyblock) );

	    release_kbnode( keyblock ); keyblock = NULL;
	    if( !(++count % 100) )
		log_info(_("%lu keys so far processed\n"), count);
	}
	log_info(_("%lu keys processed\n"), count);
	if( err_count )
	    log_info(_("\t%lu keys with errors\n"), err_count);
	if( upd_count )
	    log_info(_("\t%lu keys updated\n"), upd_count);
	if( new_count )
	    log_info(_("\t%lu keys inserted\n"), new_count);
    }
    if( rc && rc != -1 )
	log_error(_("enumerate keyblocks failed: %s\n"), g10_errstr(rc));

    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
}

/****************
 * Check the complete trustdb or only the entries for the given username.
 * We check the complete database. If a username is given or the special
 * username "*" is used, a complete recheck is done.  With no user ID
 * only the records which are not yet checkd are now checked.
 */
void
check_trustdb( const char *username )
{
    TRUSTREC rec;
    KBNODE keyblock = NULL;
    KBPOS kbpos;
    int rc;
    int recheck = username && *username == '*' && !username[1];

    init_trustdb();
    if( username && !recheck ) {
	rc = find_keyblock_byname( &kbpos, username );
	if( !rc )
	    rc = read_keyblock( &kbpos, &keyblock );
	if( rc ) {
	    log_error(_("%s: keyblock read problem: %s\n"),
				    username, g10_errstr(rc));
	}
	else {
	    int modified;

	    rc = update_trust_record( keyblock, 1, &modified );
	    if( rc == -1 ) { /* not yet in trustdb: insert */
		rc = insert_trust_record(
			    find_kbnode( keyblock, PKT_PUBLIC_KEY
				       ) ->pkt->pkt.public_key );

	    }
	    if( rc )
		log_error(_("%s: update failed: %s\n"),
					   username, g10_errstr(rc) );
	    else if( modified )
		log_info(_("%s: updated\n"), username );
	    else
		log_info(_("%s: okay\n"), username );

	}
	release_kbnode( keyblock ); keyblock = NULL;
    }
    else {
	ulong recnum;
	ulong count=0, upd_count=0, err_count=0, skip_count=0;

	for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	    if( rec.rectype == RECTYPE_DIR ) {
		TRUSTREC tmp;
		int modified;

		if( !rec.r.dir.keylist ) {
		    log_info(_("lid %lu: dir record w/o key - skipped\n"),
								  recnum);
		    count++;
		    skip_count++;
		    continue;
		}

		read_record( rec.r.dir.keylist, &tmp, RECTYPE_KEY );

		rc = get_keyblock_byfprint( &keyblock,
					    tmp.r.key.fingerprint,
					    tmp.r.key.fingerprint_len );
		if( rc ) {
		    log_error(_("lid %lu: keyblock not found: %s\n"),
						 recnum, g10_errstr(rc) );
		    count++;
		    skip_count++;
		    continue;
		}

		rc = update_trust_record( keyblock, recheck, &modified );
		if( rc ) {
		    log_error(_("lid %lu: update failed: %s\n"),
						 recnum, g10_errstr(rc) );
		    err_count++;
		}
		else if( modified ) {
		    if( opt.verbose )
			log_info(_("lid %lu: updated\n"), recnum );
		    upd_count++;
		}
		else if( opt.verbose > 1 )
		    log_info(_("lid %lu: okay\n"), recnum );

		release_kbnode( keyblock ); keyblock = NULL;
		if( !(++count % 100) )
		    log_info(_("%lu keys so far processed\n"), count);
	    }
	}
	log_info(_("%lu keys processed\n"), count);
	if( skip_count )
	    log_info(_("\t%lu keys skipped\n"), skip_count);
	if( err_count )
	    log_info(_("\t%lu keys with errors\n"), err_count);
	if( upd_count )
	    log_info(_("\t%lu keys updated\n"), upd_count);
    }
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
	else if( rc == -1 ) { /* not found - insert */
	    rc = insert_trust_record( pk );
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
	return G10ERR_TIME_CONFLICT;
    }

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


int
query_trust_info( PKT_public_key *pk, const byte *namehash )
{
    unsigned trustlevel;
    int c;

    init_trustdb();
    if( check_trust( pk, &trustlevel, namehash, NULL, NULL ) )
	return '?';
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
	rc = insert_trust_record( pk );
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
 * HAMEHASH or the firstone if namehash is NULL.  ret_n receives
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

