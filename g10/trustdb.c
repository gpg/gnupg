/* trustdb.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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


#if MAX_FINGERPRINT_LEN > 20
  #error Must change structure of trustdb
#endif

typedef struct local_id_info *LOCAL_ID_INFO;
struct local_id_info {
    LOCAL_ID_INFO next;
    ulong lid;
    unsigned flag;
};


typedef struct trust_info TRUST_INFO;
struct trust_info {
    ulong    lid;
    unsigned trust;
};


typedef struct trust_seg_list *TRUST_SEG_LIST;
struct trust_seg_list {
    TRUST_SEG_LIST next;
    int   nseg;     /* number of segmens */
    int   dup;
    TRUST_INFO seg[1];	 /* segment list */
};


typedef struct {
    TRUST_SEG_LIST tsl;
    int index;
} ENUM_TRUST_WEB_CONTEXT;


struct recno_list_struct {
    struct recno_list_struct *next;
    ulong recno;
    int type;
};
typedef struct recno_list_struct *RECNO_LIST;


static int walk_sigrecs( SIGREC_CONTEXT *c, int create );

static LOCAL_ID_INFO *new_lid_table(void);
static void release_lid_table( LOCAL_ID_INFO *tbl );
static int ins_lid_table_item( LOCAL_ID_INFO *tbl, ulong lid, unsigned flag );
static int qry_lid_table_flag( LOCAL_ID_INFO *tbl, ulong lid, unsigned *flag );
static void upd_lid_table_flag( LOCAL_ID_INFO *tbl, ulong lid, unsigned flag );

static void print_user_id( const char *text, u32 *keyid );
static int do_list_path( TRUST_INFO *stack, int depth, int max_depth,
			 LOCAL_ID_INFO *lids, TRUST_SEG_LIST *tslist );
static int update_sigs_by_lid( ulong lid );

static int list_sigs( ulong pubkey_id );
static int propagate_trust( TRUST_SEG_LIST tslist );
static int do_check( TRUSTREC *drec, unsigned *trustlevel );


/* a table used to keep track of ultimately trusted keys
 * which are the ones from our secrings */
static LOCAL_ID_INFO *ultikey_table;

static ulong last_trust_web_key;
static TRUST_SEG_LIST last_trust_web_tslist;


#define HEXTOBIN(a) ( (a) >= '0' && (a) <= '9' ? ((a)-'0') : \
		      (a) >= 'A' && (a) <= 'F' ? ((a)-'A'+10) : ((a)-'a'+10))



/**********************************************
 ***********  record read write  **************
 **********************************************/

static void
die_invalid_db()
{
    log_error(_(
	"The trust DB is corrupted; please run \"gpgm --fix-trust-db\".\n") );
    g10_exit(2);
}

/****************
 * Read a record but die if it does not exist
 */
static void
read_record( ulong recno, TRUSTREC *rec, int rectype )
{
    int rc = tdbio_read_record( recno, rec, rectype );
    if( !rc )
	return;
    log_error("trust record %lu, req type %d: read failed: %s\n",
				    recno, rectype,  g10_errstr(rc) );
    die_invalid_db();
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
    log_error("trust record %lu, type %d: write failed: %s\n",
			    rec->recnum, rec->rectype, g10_errstr(rc) );
    die_invalid_db();
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
    log_error("trust record %lu: delete failed: %s\n",
					      recno, g10_errstr(rc) );
    die_invalid_db();
}



/**********************************************
 ************* list helpers *******************
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

static LOCAL_ID_INFO *
new_lid_table(void)
{
    return m_alloc_clear( 16 * sizeof(LOCAL_ID_INFO));
}

static void
release_lid_table( LOCAL_ID_INFO *tbl )
{
    LOCAL_ID_INFO a, a2;
    int i;

    for(i=0; i < 16; i++ ) {
	for(a=tbl[i]; a; a = a2 ) {
	    a2 = a->next;
	    m_free(a);
	}
    }
    m_free(tbl);
}

/****************
 * Add a new item to the table or return 1 if we already have this item
 * fixme: maybe it's a good idea to take items from an unused item list.
 */
static int
ins_lid_table_item( LOCAL_ID_INFO *tbl, ulong lid, unsigned flag )
{
    LOCAL_ID_INFO a;

    for( a = tbl[lid & 0x0f]; a; a = a->next )
	if( a->lid == lid )
	    return 1;
    a = m_alloc( sizeof *a );
    a->lid = lid;
    a->flag = flag;
    a->next = tbl[lid & 0x0f];
    tbl[lid & 0x0f] = a;
    return 0;
}

static int
qry_lid_table_flag( LOCAL_ID_INFO *tbl, ulong lid, unsigned *flag )
{
    LOCAL_ID_INFO a;

    for( a = tbl[lid & 0x0f]; a; a = a->next )
	if( a->lid == lid ) {
	    if( flag )
		*flag = a->flag;
	    return 0;
	}
    return -1;
}

static void
upd_lid_table_flag( LOCAL_ID_INFO *tbl, ulong lid, unsigned flag )
{
    LOCAL_ID_INFO a;

    for( a = tbl[lid & 0x0f]; a; a = a->next )
	if( a->lid == lid ) {
	    a->flag = flag;
	    return;
	}
    BUG();
}

/****************
 * If we do not have a local_id in a signature packet, find the owner of
 * the signature packet in our trustdb or insert them into the trustdb
 */
static int
set_signature_packets_lid( PKT_signature *sig )
{
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    TRUSTREC rec;
    int rc;

    rc = get_pubkey( pk, sig->keyid );
    if( rc)
	goto leave;
    if( !pk->local_id ) {
	rc = tdbio_search_dir_bypk( pk, &rec );
	if( rc == -1 )
	    rc = insert_trust_record( pk );
	if( rc )
	    goto leave;
    }
    sig->local_id = pk->local_id;

  leave:
    free_public_key( pk );
    return rc;
}



/****************
 * Return the keyid from the primary key identified by LID.
 */
int
keyid_from_lid( ulong lid, u32 *keyid )
{
    TRUSTREC rec;
    int rc;

    rc = tdbio_read_record( lid, &rec, RECTYPE_DIR );
    if( rc ) {
	log_error("error reading dir record for LID %lu: %s\n",
						    lid, g10_errstr(rc));
	return G10ERR_TRUSTDB;
    }
    if( !rec.r.dir.keylist ) {
	log_error("no primary key for LID %lu\n", lid );
	return G10ERR_TRUSTDB;
    }
    rc = tdbio_read_record( rec.r.dir.keylist, &rec, RECTYPE_KEY );
    if( rc ) {
	log_error("error reading primary key for LID %lu: %s\n",
						    lid, g10_errstr(rc));
	return G10ERR_TRUSTDB;
    }
    keyid_from_fingerprint( rec.r.key.fingerprint, rec.r.key.fingerprint_len,
			    keyid );

    return 0;
}



/****************
 * Walk through the signatures of a public key.
 * The caller must provide a context structure, with all fields set
 * to zero, but the local_id field set to the requested key;
 * This function does not change this field.  On return the context
 * is filled with the local-id of the signature and the signature flag.
 * No fields should be changed (clearing all fields and setting
 * pubkeyid is okay to continue with an other pubkey)
 * Returns: 0 - okay, -1 for eof (no more sigs) or any other errorcode
 */
static int
walk_sigrecs( SIGREC_CONTEXT *c, int create )
{
    int rc=0;
    TRUSTREC *r;
    ulong rnum;

    if( c->ctl.eof )
	return -1;
    r = &c->ctl.rec;
    if( !c->ctl.init_done ) {
	c->ctl.init_done = 1;
	read_record( c->lid, r, RECTYPE_DIR );
	c->ctl.nextuid = r->r.dir.uidlist;
	/* force a read (what a bad bad hack) */
	c->ctl.index = SIGS_PER_RECORD;
	r->r.sig.next = 0;
    }

    /* need a loop to skip over deleted sigs */
    do {
	if( c->ctl.index >= SIGS_PER_RECORD ) { /* read the record */
	    rnum = r->r.sig.next;
	    if( !rnum && c->ctl.nextuid ) { /* read next uid record */
		read_record( c->ctl.nextuid, r, RECTYPE_UID );
		if( !r->r.uid.siglist && create ) {
		    rc = update_sigs_by_lid( c->lid );
		    if( rc ) {
			if( rc == G10ERR_BAD_CERT )
			    rc = -1;  /* maybe no selfsignature */
			if( rc != -1 )
			    log_info("LID %lu: "
				     "error building sigs on the fly: %s\n",
				      c->lid, g10_errstr(rc) );
			c->ctl.eof = 1;
			return rc;
		    }
		    read_record( c->ctl.nextuid, r, RECTYPE_UID );
		}
		c->ctl.nextuid = r->r.uid.next;
		rnum = r->r.uid.siglist;
	    }
	    if( !rnum ) {
		c->ctl.eof = 1;
		return -1;  /* return eof */
	    }
	    read_record( rnum, r, RECTYPE_SIG );
	    if( r->r.sig.lid != c->lid ) {
		log_error(_("chained sigrec %lu has a wrong owner\n"), rnum );
		c->ctl.eof = 1;
		die_invalid_db();
	    }
	    c->ctl.index = 0;
	}
    } while( !r->r.sig.sig[c->ctl.index++].lid );

    c->sig_lid = r->r.sig.sig[c->ctl.index-1].lid;
    c->sig_flag = r->r.sig.sig[c->ctl.index-1].flag;
    return 0;
}




/***********************************************
 *************	Trust  stuff  ******************
 ***********************************************/


/****************
 * Verify that all our public keys are in the trustDB.
 */
static int
verify_own_keys()
{
    int rc;
    void *enum_context = NULL;
    PKT_secret_key *sk = m_alloc_clear( sizeof *sk );
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    u32 keyid[2];

    while( !(rc=enum_secret_keys( &enum_context, sk, 0 ) ) ) {
	keyid_from_sk( sk, keyid );

	if( DBG_TRUST )
	    log_debug("key %08lX: checking secret key\n", (ulong)keyid[1] );

	if( is_secret_key_protected( sk ) < 1 )
	    log_info("note: secret key %08lX is NOT protected.\n",
							    (ulong)keyid[1] );

	/* see whether we can access the public key of this secret key */
	memset( pk, 0, sizeof *pk );
	rc = get_pubkey( pk, keyid );
	if( rc ) {
	    log_error(_("key %08lX: secret key without public key\n"),
							    (ulong)keyid[1] );
	    goto leave;
	}
	if( cmp_public_secret_key( pk, sk ) ) {
	    log_error(_("key %08lX: secret and public key don't match\n"),
							    (ulong)keyid[1] );
	    rc = G10ERR_GENERAL;
	    goto leave;
	}

	/* make sure that the pubkey is in the trustdb */
	rc = query_trust_record( pk );
	if( rc == -1 ) { /* put it into the trustdb */
	    rc = insert_trust_record( pk );
	    if( rc ) {
		log_error(_("key %08lX: can't put it into the trustdb\n"),
							    (ulong)keyid[1] );
		goto leave;
	    }
	}
	else if( rc ) {
	    log_error(_("key %08lX: query record failed\n"), (ulong)keyid[1] );
	    goto leave;

	}

	if( DBG_TRUST )
	    log_debug("key %08lX.%lu: stored into ultikey_table\n",
				    (ulong)keyid[1], pk->local_id );
	if( ins_lid_table_item( ultikey_table, pk->local_id, 0 ) )
	    log_error(_("key %08lX: already in ultikey_table\n"),
							(ulong)keyid[1]);

	release_secret_key_parts( sk );
	release_public_key_parts( pk );
    }
    if( rc != -1 )
	log_error(_("enum_secret_keys failed: %s\n"), g10_errstr(rc) );
    else
	rc = 0;

  leave:
    enum_secret_keys( &enum_context, NULL, 0 ); /* free context */
    free_secret_key( sk );
    free_public_key( pk );
    return rc;
}


static void
print_user_id( const char *text, u32 *keyid )
{
    char *p;
    size_t n;

    p = get_user_id( keyid, &n );
    if( *text ) {
	fputs( text, stdout);
	putchar(' ');
    }
    putchar('\"');
    print_string( stdout, p, n, 0 );
    putchar('\"');
    putchar('\n');
    m_free(p);
}

static void
print_keyid( FILE *fp, ulong lid )
{
    u32 ki[2];
    if( keyid_from_lid( lid, ki ) )
	fprintf(fp, "????????.%lu", lid );
    else
	fprintf(fp, "%08lX.%lu", (ulong)ki[1], lid );
}

static void
print_trust( FILE *fp, unsigned trust )
{
    int c;
    switch( trust ) {
      case TRUST_UNKNOWN:   c = 'o'; break;
      case TRUST_EXPIRED:   c = 'e'; break;
      case TRUST_UNDEFINED: c = 'q'; break;
      case TRUST_NEVER:     c = 'n'; break;
      case TRUST_MARGINAL:  c = 'm'; break;
      case TRUST_FULLY:     c = 'f'; break;
      case TRUST_ULTIMATE:  c = 'u'; break;
      default: fprintf(fp, "%02x", trust ); return;
    }
    putc(c, fp);
}

/* (a non-recursive algorithm would be easier) */
static int
do_list_sigs( ulong root, ulong pubkey, int depth,
	      LOCAL_ID_INFO *lids, unsigned *lineno )
{
    SIGREC_CONTEXT sx;
    int rc;
    u32 keyid[2];

    memset( &sx, 0, sizeof sx );
    sx.lid = pubkey;
    for(;;) {
	rc = walk_sigrecs( &sx, 0 );
	if( rc )
	    break;
	rc = keyid_from_lid( sx.sig_lid, keyid );
	if( rc ) {
	    printf("%6u: %*s????????.%lu:%02x\n", *lineno, depth*4, "",
						   sx.sig_lid, sx.sig_flag );
	    ++*lineno;
	}
	else {
	    printf("%6u: %*s%08lX.%lu:%02x ", *lineno, depth*4, "",
			      (ulong)keyid[1], sx.sig_lid, sx.sig_flag );
	    /* check whether we already checked this pubkey */
	    if( !qry_lid_table_flag( ultikey_table, sx.sig_lid, NULL ) ) {
		print_user_id("[ultimately trusted]", keyid);
		++*lineno;
	    }
	    else if( sx.sig_lid == pubkey ) {
		printf("[self-signature]\n");
		++*lineno;
	    }
	    else if( sx.sig_lid == root ) {
		printf("[closed]\n");
		++*lineno;
	    }
	    else if( ins_lid_table_item( lids, sx.sig_lid, *lineno ) ) {
		unsigned refline;
		qry_lid_table_flag( lids, sx.sig_lid, &refline );
		printf("[see line %u]\n", refline);
		++*lineno;
	    }
	    else if( depth+1 >= MAX_LIST_SIGS_DEPTH  ) {
		print_user_id( "[too deeply nested]", keyid );
		++*lineno;
	    }
	    else {
		print_user_id( "", keyid );
		++*lineno;
		rc = do_list_sigs( root, sx.sig_lid, depth+1, lids, lineno );
		if( rc )
		    break;
	    }
	}
    }
    return rc==-1? 0 : rc;
}

/****************
 * List all signatures of a public key
 */
static int
list_sigs( ulong pubkey_id )
{
    int rc;
    u32 keyid[2];
    LOCAL_ID_INFO *lids;
    unsigned lineno = 1;

    rc = keyid_from_lid( pubkey_id, keyid );
    if( rc )
	return rc;
    printf("Signatures of %08lX.%lu ", (ulong)keyid[1], pubkey_id );
    print_user_id("", keyid);
    printf("----------------------\n");

    lids = new_lid_table();
    rc = do_list_sigs( pubkey_id, pubkey_id, 0, lids, &lineno );
    putchar('\n');
    release_lid_table(lids);
    return rc;
}

/****************
 * List all records of a public key
 */
static int
list_records( ulong lid )
{
    int rc;
    TRUSTREC dr, ur, rec;
    ulong recno;

    rc = tdbio_read_record( lid, &dr, RECTYPE_DIR );
    if( rc ) {
	log_error("lid %lu: read dir record failed: %s\n", lid, g10_errstr(rc));
	return rc;
    }
    tdbio_dump_record( &dr, stdout );

    for( recno=dr.r.dir.keylist; recno; recno = rec.r.key.next ) {
	rc = tdbio_read_record( recno, &rec, RECTYPE_KEY );
	if( rc ) {
	    log_error("lid %lu: read key record failed: %s\n",
						lid, g10_errstr(rc));
	    return rc;
	}
	tdbio_dump_record( &rec, stdout );
    }

    for( recno=dr.r.dir.uidlist; recno; recno = ur.r.uid.next ) {
	rc = tdbio_read_record( recno, &ur, RECTYPE_UID );
	if( rc ) {
	    log_error("lid %lu: read uid record failed: %s\n",
						lid, g10_errstr(rc));
	    return rc;
	}
	tdbio_dump_record( &ur, stdout );
	/* preference records */
	for(recno=ur.r.uid.prefrec; recno; recno = rec.r.pref.next ) {
	    rc = tdbio_read_record( recno, &rec, RECTYPE_PREF );
	    if( rc ) {
		log_error("lid %lu: read pref record failed: %s\n",
						    lid, g10_errstr(rc));
		return rc;
	    }
	    tdbio_dump_record( &rec, stdout );
	}
	/* sig records */
	for(recno=ur.r.uid.siglist; recno; recno = rec.r.sig.next ) {
	    rc = tdbio_read_record( recno, &rec, RECTYPE_SIG );
	    if( rc ) {
		log_error("lid %lu: read sig record failed: %s\n",
						    lid, g10_errstr(rc));
		return rc;
	    }
	    tdbio_dump_record( &rec, stdout );
	}
    }

    /* add cache record dump here */



    return rc;
}



/****************
 * Function to collect all trustpaths
 */
static int
do_list_path( TRUST_INFO *stack, int depth, int max_depth,
	      LOCAL_ID_INFO *lids, TRUST_SEG_LIST *tslist )
{
    SIGREC_CONTEXT sx;
    unsigned last_depth;
    int rc;

    assert(depth);

    /*printf("%2lu/%d: scrutinizig\n", stack[depth-1], depth);*/
    if( depth >= max_depth || depth >= MAX_LIST_SIGS_DEPTH-1 ) {
	/*printf("%2lu/%d: too deeply nested\n", stack[depth-1], depth);*/
	return 0;
    }
    memset( &sx, 0, sizeof sx );
    sx.lid = stack[depth-1].lid;
    /* loop over all signatures. If we do not have any, try to create them */
    while( !(rc = walk_sigrecs( &sx, 1 )) ) {
	TRUST_SEG_LIST tsl, t2, tl;
	int i;

	stack[depth].lid = sx.sig_lid;
	stack[depth].trust = 0;
	if( qry_lid_table_flag( lids, sx.sig_lid, &last_depth) ) {
	    /*printf("%2lu/%d: marked\n", sx.sig_lid, depth );*/
	    ins_lid_table_item( lids, sx.sig_lid, depth);
	    last_depth = depth;
	}
	else if( depth	< last_depth ) {
	    /*printf("%2lu/%d: last_depth=%u - updated\n", sx.sig_lid, depth, last_depth);*/
	    last_depth = depth;
	    upd_lid_table_flag( lids, sx.sig_lid, depth);
	}

	if( last_depth < depth )
	    /*printf("%2lu/%d: already visited\n", sx.sig_lid, depth)*/;
	else if( !qry_lid_table_flag( ultikey_table, sx.sig_lid, NULL ) ) {
	    /* found end of path; store it, ordered by path length */
	    tsl = m_alloc( sizeof *tsl + depth*sizeof(TRUST_INFO) );
	    tsl->nseg = depth+1;
	    tsl->dup = 0;
	    for(i=0; i <= depth; i++ )
		tsl->seg[i] = stack[i];
	    for(t2=*tslist,tl=NULL; t2; tl=t2, t2 = t2->next )
		if( depth < t2->nseg )
		    break;
	    if( !tl ) {
		tsl->next = t2;
		*tslist = tsl;
	    }
	    else {
		tsl->next = t2;
		tl->next = tsl;
	    }
	    /*putchar('.'); fflush(stdout);*/
	    /*printf("%2lu/%d: found\n", sx.sig_lid, depth);*/
	}
	else {
	    rc = do_list_path( stack, depth+1, max_depth, lids, tslist);
	    if( rc && rc != -1 )
		break;
	}
    }
    return rc==-1? 0 : rc;
}


/****************
 * find the uid record given the uid packet and the dir-record.
 * Returns: 0 = found
 *	   -1 = No such uid-record
 *	   or other error
 */
static int
find_urec( TRUSTREC *dir, PKT_user_id *uid, TRUSTREC *urec )
{
    byte nhash[20];
    ulong recno;

    assert(dir->rectype == RECTYPE_DIR );
    rmd160_hash_buffer( nhash, uid->name, uid->len );
    for( recno=dir->r.dir.uidlist; recno; recno = urec->r.uid.next ) {
	read_record( recno, urec, RECTYPE_UID );
	if( !memcmp( nhash, urec->r.uid.namehash, 20 ) )
	    return 0;
    }

    return -1;
}


/****************
 * Test whether zthe signature lid is already in the (in mem) list.
 * Returns: True if it is a duplicate
 */
static int
test_dupsig( TRUSTREC *rec, ulong lid )
{
    int i;
    ulong alid;

    for( ; rec; rec = rec->next ) {
	for(i=0; i < SIGS_PER_RECORD && (alid = rec->r.sig.sig[i].lid); i++ )
	    if( alid == lid )
		return 1;
    }
    return 0;
}


/****************
 * release the sigrec from the uidlist
 */
static void
rel_uidsigs( TRUSTREC *urec )
{
    TRUSTREC *r2, *rec;
    assert( urec->rectype == RECTYPE_UID );

    for(rec=urec->next ; rec; rec = r2 ) {
	assert( rec->rectype == RECTYPE_SIG );
	r2 = rec->next;
	m_free( rec );
    }
    urec->next = NULL;
}

static int
no_selfsig_del( ulong lid, u32 *keyid, TRUSTREC *urec )
{
    int rc;

    log_error("key %08lX.%lu, uid %02X%02X: "
	      "no self-signature - user id removed\n",
	      (ulong)keyid[1], lid, urec->r.uid.namehash[18],
	      urec->r.uid.namehash[19] );
    rel_uidsigs( urec );
    rc = tdbio_delete_uidrec( lid, urec->recnum );
    if( rc )
	log_error("no_selfsig_del: delete_uid %lu failed: %s\n",
					lid, g10_errstr(rc) );
    return rc;
}

/****************
 * Write the signature records from the in-mem list at urec
 * (The sequence of signatures does not matter)
 */
static int
write_sigs_from_urec( ulong lid, u32 *keyid, TRUSTREC *urec )
{
    TRUSTREC *rec, srec;
    ulong nextrecno;
    ulong recno;

    nextrecno = urec->r.uid.siglist;
    urec->r.uid.siglist = 0; /* end of list marker */
    for( rec = urec->next; rec; rec = rec->next ) {
	assert( rec->rectype == RECTYPE_SIG );
	if( nextrecno ) { /* read the sig record, so it can be reused */
	    read_record( nextrecno, &srec, RECTYPE_SIG );
	    recno = nextrecno;
	    nextrecno = srec.r.sig.next;
	}
	else
	    recno = tdbio_new_recnum();

	/* link together (the sequence of signatures does not matter) */
	rec->r.sig.next = urec->r.uid.siglist;
	urec->r.uid.siglist = recno;
	rec->r.sig.lid = lid;
	/* and write */
	rec->recnum = recno;
	write_record( rec );
    }

    /* write the urec back */
    write_record( urec );

    /* delete remaining old sigrecords */
    while( nextrecno ) {
	read_record( nextrecno, &srec, RECTYPE_SIG );
	delete_record( nextrecno );
	nextrecno = srec.r.sig.next;
    }

    return 0;
}

/****************
 * If we do not have sigrecs for the given key, build them and write them
 * to the trustdb
 */
static int
update_sigs( TRUSTREC *dir )
{
    TRUSTREC *rec, krec;
    TRUSTREC urec;
    TRUSTREC *sigrec_list;
    KBNODE keyblock = NULL;
    KBNODE node;
    int i, sigidx, have_urec ;
    ulong lid = dir->r.dir.lid;
    u32 keyid[2];
    int miskey=0;
    int rc=0;

    if( DBG_TRUST )
	log_debug("update_sigs for %lu\n", lid );

    read_record( dir->r.dir.keylist, &krec, RECTYPE_KEY );
    rc = get_keyblock_byfprint( &keyblock, krec.r.key.fingerprint,
					   krec.r.key.fingerprint_len );
    if( rc ) {
	log_error( "update_sigs: keyblock for %lu not found: %s\n",
						    lid, g10_errstr(rc) );
	goto leave;
    }

    /* check all key signatures */
    assert( keyblock->pkt->pkttype == PKT_PUBLIC_KEY );
    have_urec = 0;
    sigrec_list = NULL;
    sigidx = 0;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY )
	    keyid_from_pk( node->pkt->pkt.public_key, keyid );
	else if( node->pkt->pkttype == PKT_USER_ID ) {
	    if( have_urec && !(urec.mark & 1) ) {
	       if( (rc = no_selfsig_del(lid, keyid, &urec )) )
		   goto leave;
		have_urec = 0;
	    }
	    if( have_urec ) {
		rc = write_sigs_from_urec( lid, keyid, &urec );
		if( rc )
		    goto leave;
		rel_uidsigs( &urec );
	    }
	    rc = find_urec( dir, node->pkt->pkt.user_id, &urec );
	    urec.next = NULL;
	    urec.mark = 0;
	    have_urec = sigidx = 0;
	    if( rc == -1 ) {
		log_info("update_sigs: new user id for %lu\n", lid );
		/* fixme: we should add the new user id here */
	    }
	    else if( rc ) {
		log_error("update_sigs: find_urec %lu failed: %s\n",
						lid, g10_errstr(rc) );
		goto leave;
	    }
	    else
		have_urec = 1;
	}
	else if( have_urec && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    if( (sig->sig_class&~3) == 0x10 ) {
		rc = check_key_signature( keyblock, node, &i );
		if( rc == G10ERR_NO_PUBKEY ) {
		    if( opt.verbose )
			log_info(_("key %08lX.%lu, uid %02X%02X: "
				   "no public key for signature %08lX\n"),
			      (ulong)keyid[1], lid, urec.r.uid.namehash[18],
			      urec.r.uid.namehash[19], (ulong)sig->keyid[1] );
		    miskey = 1;
		}
		else if( rc )
		    log_info(_("key %08lX.%lu, uid %02X%02X: "
			       "invalid %ssignature: %s\n"),
			      (ulong)keyid[1], lid, urec.r.uid.namehash[18],
			      urec.r.uid.namehash[19],
			      i?"self-":"",g10_errstr(rc));
		else if( i ) /* mark that we have a valid selfsignature */
		    urec.mark |= 1;
		else if( (rc = set_signature_packets_lid( sig )) )
		    log_error("key %08lX.%lu, uid %02X%02X: "
			      "can't get LID of signer: %s\n",
			      (ulong)keyid[1], lid, urec.r.uid.namehash[18],
			      urec.r.uid.namehash[19], g10_errstr(rc));
		else if( !test_dupsig( urec.next, sig->local_id ) ) {
		    /* put the valid signature into a list */
		    rec = urec.next;
		    if( !rec || sigidx == SIGS_PER_RECORD ) {
			rec = m_alloc_clear( sizeof *rec );
			rec->rectype = RECTYPE_SIG;
			rec->next = urec.next;
			urec.next = rec;
			sigidx = 0;
		    }
		    rec->r.sig.sig[sigidx].lid = sig->local_id;
		    rec->r.sig.sig[sigidx].flag = 0;
		    sigidx++;
		    if( DBG_TRUST )
			log_debug("key %08lX.%lu, uid %02X%02X: "
			      "signed by LID %lu\n",
			      (ulong)keyid[1], lid, urec.r.uid.namehash[18],
			      urec.r.uid.namehash[19], sig->local_id);
		}
		else if( DBG_TRUST )
		    log_debug("key %08lX.%lu, uid %02X%02X: "
			      "duplicate signature by LID %lu\n",
			      (ulong)keyid[1], lid, urec.r.uid.namehash[18],
			      urec.r.uid.namehash[19], sig->local_id );
		rc = 0;
	    }
	    else {
		/* fixme: handle other sig classes here */
		/* FIXME: Revocations!!! */
	    }
	}
    }
    if( have_urec && !(urec.mark & 1) ) {
	if( (rc = no_selfsig_del(lid, keyid, &urec )) )
	    goto leave;
	have_urec = 0;
    }
    if( have_urec ) {
	rc = write_sigs_from_urec( lid, keyid, &urec );
	if( rc )
	    goto leave;
	rel_uidsigs( &urec );
    }
    dir->r.dir.dirflags |= DIRF_CHECKED;
    if( miskey )
	dir->r.dir.dirflags |= DIRF_MISKEY;
    else
	dir->r.dir.dirflags &= ~DIRF_MISKEY;
    write_record( dir );

  leave:
    /* fixme: need more cleanup in case of an error */
    release_kbnode( keyblock );
    if( DBG_TRUST )
	log_debug("update_sigs for %lu: %s\n", lid, g10_errstr(rc) );
    return rc;
}


static int
update_sigs_by_lid( ulong lid )
{
    int rc;
    TRUSTREC rec;

    read_record( lid, &rec, RECTYPE_DIR );
    if( !(rec.r.dir.dirflags & DIRF_CHECKED) )
	rc = update_sigs( &rec );
    return rc;
}

/****************
 * Make a list of trust paths
 */
static int
make_tsl( ulong lid, TRUST_SEG_LIST *ret_tslist )
{
    int i, rc;
    LOCAL_ID_INFO *lids = new_lid_table();
    TRUST_INFO stack[MAX_LIST_SIGS_DEPTH];
    TRUST_SEG_LIST tsl, tslist;
    int max_depth = 4;

    tslist = *ret_tslist = NULL;

    if( !qry_lid_table_flag( ultikey_table, lid, NULL ) ) {
	tslist = m_alloc( sizeof *tslist );
	tslist->nseg = 1;
	tslist->dup = 0;
	tslist->seg[0].lid = lid;
	tslist->seg[0].trust = 0;
	tslist->next = NULL;
	rc = 0;
    }
    else {
	stack[0].lid = lid;
	stack[0].trust = 0;
	rc = do_list_path( stack, 1, max_depth, lids, &tslist );
    }
    if( !rc ) { /* wipe out duplicates */
	LOCAL_ID_INFO *work = new_lid_table();
	for( tsl=tslist; tsl; tsl = tsl->next ) {
	    for(i=1; i < tsl->nseg-1; i++ ) {
		if( ins_lid_table_item( work, tsl->seg[i].lid, 0 ) ) {
		    tsl->dup = 1; /* mark as duplicate */
		    break;
		}
	    }
	}
	release_lid_table(work);
	*ret_tslist = tslist;
    }
    else
	; /* FIXME: release tslist */
    release_lid_table(lids);
    return rc;
}


/****************
 * Given a trust segment list tslist, walk over all paths and fill in
 * the trust information for each segment.  What this function does is
 * to assign a trustvalue to the first segment (which is the requested key)
 * of each path.
 *
 * FIXME: We have to do more thinking here. e.g. we should never increase
 *	  the trust value.
 *
 * Do not do it for duplicates.
 */
static int
propagate_trust( TRUST_SEG_LIST tslist )
{
    int i;
    unsigned trust, tr;
    TRUST_SEG_LIST tsl;

    for(tsl = tslist; tsl; tsl = tsl->next ) {
	if( tsl->dup )
	    continue;
	assert( tsl->nseg );
	/* the last segment is always an ultimately trusted one, so we can
	 * assign a fully trust to the next one */
	i = tsl->nseg-1;
	tsl->seg[i].trust = TRUST_ULTIMATE;
	trust = TRUST_FULLY;
	for(i-- ; i >= 0; i-- ) {
	    tsl->seg[i].trust = trust;
	    if( i > 0 ) {
		/* get the trust of this pubkey */
		tr = get_ownertrust( tsl->seg[i].lid );
		if( tr < trust )
		    trust = tr;
	    }
	}
    }
    return 0;
}


/****************
 * we have the pubkey record and all needed informations are in the trustdb
 * but nothing more is known.
 * (this function may re-read the dir record dr)
 */
static int
do_check( TRUSTREC *dr, unsigned *trustlevel )
{
    int i, rc=0;
    TRUST_SEG_LIST tsl, tsl2, tslist;
    int marginal, fully;
    int fully_needed = opt.completes_needed;
    int marginal_needed = opt.marginals_needed;
    unsigned tflags = 0;

    assert( fully_needed > 0 && marginal_needed > 1 );


    *trustlevel = TRUST_UNDEFINED;

    if( !dr->r.dir.keylist ) {
	log_error("Ooops, no keys\n");
	return G10ERR_TRUSTDB;
    }
    if( !dr->r.dir.uidlist ) {
	log_error("Ooops, no user ids\n");
	return G10ERR_TRUSTDB;
    }

    /* did we already check the signatures */
    if( !(dr->r.dir.dirflags & DIRF_CHECKED) ) /* no - do it now */
	rc = update_sigs( dr );

    if( dr->r.dir.dirflags & DIRF_REVOKED )
	tflags |= TRUST_FLAG_REVOKED;

  #if 0
    if( !rc && !dr->r.dir.siglist ) {
	/* We do not have any signatures; check whether it is one of our
	 * secret keys */
	if( !qry_lid_table_flag( ultikey_table, dr->r.dir.lid, NULL ) )
	    *trustlevel = tflags | TRUST_ULTIMATE;
	return 0;
    }
  #endif
    if( rc )
	return rc;  /* error while looking for sigrec or building sigrecs */

    /* fixme: take it from the cache if it is valid */

    /* Make a list of all possible trust-paths */
    rc = make_tsl( dr->r.dir.lid, &tslist );
    if( rc )
	return rc;
    rc = propagate_trust( tslist );
    if( rc )
	return rc;
    for(tsl = tslist; tsl; tsl = tsl->next ) {
	if( tsl->dup )
	    continue;

	if( opt.verbose ) {
	    log_info("trust path:" );
	    for(i=0; i < tsl->nseg; i++ ) {
		putc(' ',stderr);
		print_keyid( stderr, tsl->seg[i].lid );
		putc(':',stderr);
		print_trust( stderr, tsl->seg[i].trust );
	    }
	    putc('\n',stderr);
	}
    }

    /* and see whether there is a trusted path.
     * We only have to look at the first segment, because
     * propagate_trust has investigated all other segments */
    marginal = fully = 0;
    for(tsl = tslist; tsl; tsl = tsl->next ) {
	if( tsl->dup )
	    continue;
	if( tsl->seg[0].trust == TRUST_ULTIMATE ) {
	    *trustlevel = tflags | TRUST_ULTIMATE; /* our own key */
	    break;
	}
	if( tsl->seg[0].trust == TRUST_FULLY ) {
	    marginal++;
	    fully++;
	}
	else if( tsl->seg[0].trust == TRUST_MARGINAL )
	    marginal++;

	if( fully >= fully_needed ) {
	    *trustlevel = tflags | TRUST_FULLY;
	    break;
	}
    }
    if( !tsl && marginal >= marginal_needed )
	*trustlevel = tflags | TRUST_MARGINAL;

    /* cache the tslist */
    if( last_trust_web_key ) {
	for( tsl = last_trust_web_tslist; tsl; tsl = tsl2 ) {
	    tsl2 = tsl->next;
	    m_free(tsl);
	}
    }
    last_trust_web_key = dr->r.dir.lid;
    last_trust_web_tslist = tslist;
    return 0;
}


/***********************************************
 ****************  API	************************
 ***********************************************/

/****************
 * Perform some checks over the trustdb
 *  level 0: only open the db
 *	  1: used for initial program startup
 */
int
init_trustdb( int level, const char *dbname )
{
    int rc=0;

    if( !ultikey_table )
	ultikey_table = new_lid_table();

    if( !level || level==1 ) {
	rc = tdbio_set_dbname( dbname, !!level );
	if( rc )
	    return rc;
	if( !level )
	    return 0;

	/* verify that our own keys are in the trustDB
	 * or move them to the trustdb. */
	rc = verify_own_keys();

	/* should we check whether there is no other ultimately trusted
	 * key in the database? */

    }
    else
	BUG();

    return rc;
}


void
list_trustdb( const char *username )
{
    TRUSTREC rec;

    if( username && *username == '#' ) {
	int rc;
	ulong lid = atoi(username+1);

	if( (rc = list_records( lid)) )
	    log_error("user '%s' read problem: %s\n", username, g10_errstr(rc));
	else if( (rc = list_sigs( lid )) )
	    log_error("user '%s' list problem: %s\n", username, g10_errstr(rc));
    }
    else if( username ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	int rc;

	if( (rc = get_pubkey_byname( pk, username )) )
	    log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
	else if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 )
	    log_error("problem finding '%s' in trustdb: %s\n",
						username, g10_errstr(rc));
	else if( rc == -1 )
	    log_error("user '%s' not in trustdb\n", username);
	else if( (rc = list_records( pk->local_id)) )
	    log_error("user '%s' read problem: %s\n", username, g10_errstr(rc));
	else if( (rc = list_sigs( pk->local_id )) )
	    log_error("user '%s' list problem: %s\n", username, g10_errstr(rc));
	free_public_key( pk );
    }
    else {
	ulong recnum;
	int i;

	printf("TrustDB: %s\n", tdbio_get_dbname() );
	for(i=9+strlen(tdbio_get_dbname()); i > 0; i-- )
	    putchar('-');
	putchar('\n');
	for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ )
	    tdbio_dump_record( &rec, stdout );
    }
}

/****************
 * Print a list of all defined owner trust value.
 */
void
export_ownertrust()
{
    TRUSTREC rec;
    TRUSTREC rec2;
    ulong recnum;
    int i;
    byte *p;
    int rc;

    for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	if( rec.rectype == RECTYPE_DIR ) {
	    if( !rec.r.dir.keylist ) {
		log_error("Oops; directory record w/o primary key\n");
		continue;
	    }
	    if( !rec.r.dir.ownertrust )
		continue;
	    rc = tdbio_read_record( rec.r.dir.keylist, &rec2, RECTYPE_KEY);
	    if( rc ) {
		log_error("error reading key record: %s\n", g10_errstr(rc));
		continue;
	    }
	    p = rec2.r.key.fingerprint;
	    for(i=0; i < rec2.r.key.fingerprint_len; i++, p++ )
		printf("%02X", *p );
	    printf(":%u:\n", (unsigned)rec.r.dir.ownertrust );
	}
    }
}


void
import_ownertrust( const char *fname )
{
    FILE *fp;
    int is_stdin=0;
    char line[256];
    char *p;
    size_t n, fprlen;
    unsigned otrust;

    if( !fname || (*fname == '-' && !fname[1]) ) {
	fp = stdin;
	fname = "[stdin]";
	is_stdin = 1;
    }
    else if( !(fp = fopen( fname, "r" )) ) {
	log_error_f(fname, _("can't open file: %s\n"), strerror(errno) );
	return;
    }

    while( fgets( line, DIM(line)-1, fp ) ) {
	TRUSTREC rec;
	int rc;

	if( !*line || *line == '#' )
	    continue;
	n = strlen(line);
	if( line[n-1] != '\n' ) {
	    log_error_f(fname, "line to long\n" );
	    break; /* can't continue */
	}
	for(p = line; *p && *p != ':' ; p++ )
	    if( !isxdigit(*p) )
		break;
	if( *p != ':' ) {
	    log_error_f(fname, "error: missing colon\n" );
	    continue;
	}
	fprlen = p - line;
	if( fprlen != 32 && fprlen != 40 ) {
	    log_error_f(fname, "error: invalid fingerprint\n" );
	    continue;
	}
	if( sscanf(p, ":%u:", &otrust ) != 1 ) {
	    log_error_f(fname, "error: no otrust value\n" );
	    continue;
	}
	if( !otrust )
	    continue; /* no otrust defined - no need to update or insert */
	/* convert the ascii fingerprint to binary */
	for(p=line, fprlen=0; *p != ':'; p += 2 )
	    line[fprlen++] = HEXTOBIN(p[0]) * 16 + HEXTOBIN(p[1]);
	line[fprlen] = 0;

      repeat:
	rc = tdbio_search_dir_byfpr( line, fprlen, 0, &rec );
	if( !rc ) { /* found: update */
	    if( rec.r.dir.ownertrust )
		log_info("LID %lu: changing trust from %u to %u\n",
			  rec.r.dir.lid, rec.r.dir.ownertrust, otrust );
	    else
		log_info("LID %lu: setting trust to %u\n",
				   rec.r.dir.lid, otrust );
	    rec.r.dir.ownertrust = otrust;
	    write_record( &rec );
	}
	else if( rc == -1 ) { /* not found; get the key from the ring */
	    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

	    log_info_f(fname, "key not in trustdb, searching ring.\n");
	    rc = get_pubkey_byfprint( pk, line, fprlen );
	    if( rc )
		log_info_f(fname, "key not in ring: %s\n", g10_errstr(rc));
	    else {
		rc = query_trust_record( pk );	/* only as assertion */
		if( rc != -1 )
		    log_error_f(fname, "Oops: key is now in trustdb???\n");
		else {
		    rc = insert_trust_record( pk );
		    if( !rc )
			goto repeat; /* update the ownertrust */
		    log_error_f(fname, "insert trust record failed: %s\n",
							   g10_errstr(rc) );
		}
	    }
	}
	else /* error */
	    log_error_f(fname, "error finding dir record: %s\n",
						    g10_errstr(rc));
    }
    if( ferror(fp) )
	log_error_f(fname, _("read error: %s\n"), strerror(errno) );
    if( !is_stdin )
	fclose(fp);
}


void
list_trust_path( int max_depth, const char *username )
{
    int rc;
    int wipe=0;
    int i;
    TRUSTREC rec;
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

    if( max_depth < 0 ) {
	wipe = 1;
	max_depth = -max_depth;
    }

    if( (rc = get_pubkey_byname( pk, username )) )
	log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
    else if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 )
	log_error("problem finding '%s' in trustdb: %s\n",
					    username, g10_errstr(rc));
    else if( rc == -1 ) {
	log_info("user '%s' not in trustdb - inserting\n", username);
	rc = insert_trust_record( pk );
	if( rc )
	    log_error("failed to put '%s' into trustdb: %s\n", username, g10_errstr(rc));
	else {
	    assert( pk->local_id );
	}
    }

    if( !rc ) {
	TRUST_SEG_LIST tsl, tslist = NULL;

	if( !qry_lid_table_flag( ultikey_table, pk->local_id, NULL ) ) {
	    tslist = m_alloc( sizeof *tslist );
	    tslist->nseg = 1;
	    tslist->dup = 0;
	    tslist->seg[0].lid = pk->local_id;
	    tslist->seg[0].trust = 0;
	    tslist->next = NULL;
	    rc = 0;
	}
	else {
	    LOCAL_ID_INFO *lids = new_lid_table();
	    TRUST_INFO stack[MAX_LIST_SIGS_DEPTH];

	    stack[0].lid = pk->local_id;
	    stack[0].trust = 0;
	    rc = do_list_path( stack, 1, max_depth, lids, &tslist );
	    if( wipe ) { /* wipe out duplicates */
		LOCAL_ID_INFO *work;

		work = new_lid_table();
		for( tsl=tslist; tsl; tsl = tsl->next ) {
		    for(i=1; i < tsl->nseg-1; i++ ) {
			if( ins_lid_table_item( work, tsl->seg[i].lid, 0 ) ) {
			    tsl->dup = 1; /* mark as duplicate */
			    break;
			}
		    }
		}
		release_lid_table(work);
	    }
	    release_lid_table(lids);
	}
	if( rc )
	    log_error("user '%s' list problem: %s\n", username, g10_errstr(rc));
	rc = propagate_trust( tslist );
	if( rc )
	    log_error("user '%s' trust problem: %s\n", username, g10_errstr(rc));
	for(tsl = tslist; tsl; tsl = tsl->next ) {
	    int i;

	    if( tsl->dup )
		continue;
	    printf("trust path:" );
	    for(i=0; i < tsl->nseg; i++ ) {
		putc(' ',stdout);
		print_keyid( stdout, tsl->seg[i].lid );
		putc(':',stdout);
		print_trust( stdout, tsl->seg[i].trust );
	    }
	    putchar('\n');
	}
    }

    free_public_key( pk );
}


/****************
 * Check the complete trustdb or only the entries for the given username
 * FIXME: We need a mode which only looks at keys with the MISKEY flag set.
 */
void
check_trustdb( const char *username )
{
    TRUSTREC rec;
    int rc;

    if( username && *username == '#' ) {
	int rc;
	ulong lid = atoi(username+1);

	if( (rc = update_sigs_by_lid( lid )) )
	    log_error("lid %lu: check failed: %s\n",
					lid, g10_errstr(rc));
	else
	    log_info("lid %lu: checked: %s\n", lid, g10_errstr(rc));
    }
    else if( username ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );

	if( (rc = get_pubkey_byname( pk, username )) )
	    log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
	else if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 )
	    log_error("problem finding '%s' in trustdb: %s\n",
						username, g10_errstr(rc));
	else if( rc == -1 )
	    log_error("user '%s' not in trustdb\n", username);
	else if( (rc = update_sigs( &rec )) )
	    log_error("lid %lu: check failed: %s\n",
					rec.recnum, g10_errstr(rc));
	else
	    log_info("lid %lu: checked: %s\n", rec.recnum, g10_errstr(rc));
	free_public_key( pk );
    }
    else {
	ulong recnum;

	for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	    if( rec.rectype == RECTYPE_DIR ) {
		rc = update_sigs( &rec );
		if( rc )
		    log_error("lid %lu: check failed: %s\n",
						 recnum, g10_errstr(rc) );
		else
		    log_info("lid %lu: checked\n", recnum );
	    }
	}
    }
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
check_trust( PKT_public_key *pk, unsigned *r_trustlevel )
{
    TRUSTREC rec;
    unsigned trustlevel = TRUST_UNKNOWN;
    int rc=0;
    u32 cur_time;
    u32 keyid[2];


    keyid_from_pk( pk, keyid );

    /* get the pubkey record */
    if( pk->local_id ) {
	read_record( pk->local_id, &rec, RECTYPE_DIR );
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 ) {
	    log_error("check_trust: search dir record failed: %s\n",
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

    if( pk->valid_days && add_days_to_timestamp(pk->timestamp,
						pk->valid_days) < cur_time ) {
	log_info(_("key %08lX.%lu: expired at %s\n"),
			(ulong)keyid[1], pk->local_id,
		    asctimestamp( add_days_to_timestamp(pk->timestamp,
							pk->valid_days)));
	 trustlevel = TRUST_EXPIRED;
    }
    else {
	rc = do_check( &rec, &trustlevel );
	if( rc ) {
	    log_error(_("key %08lX.%lu: trust check failed: %s\n"),
			    (ulong)keyid[1], pk->local_id, g10_errstr(rc));
	    return rc;
	}
    }


  leave:
    if( DBG_TRUST )
	log_debug("check_trust() returns trustlevel %04x.\n", trustlevel);
    *r_trustlevel = trustlevel;
    return 0;
}


int
query_trust_info( PKT_public_key *pk )
{
    unsigned trustlevel;
    int c;

    if( check_trust( pk, &trustlevel ) )
	return '?';
    if( trustlevel & TRUST_FLAG_REVOKED )
	return 'r';
    switch( (trustlevel & TRUST_MASK) ) {
      case TRUST_UNKNOWN:   c = 'o'; break;
      case TRUST_EXPIRED:   c = 'e'; break;
      case TRUST_UNDEFINED: c = 'q'; break;
      case TRUST_NEVER:     c = 'n'; break;
      case TRUST_MARGINAL:  c = 'm'; break;
      case TRUST_FULLY:     c = 'f'; break;
      case TRUST_ULTIMATE:  c = 'u'; break;
      default: BUG();
    }
    return c;
}



/****************
 * Enumerate all keys, which are needed to build all trust paths for
 * the given key.  This function does not return the key itself or
 * the ultimate key.
 *
 *  1) create a void pointer and initialize it to NULL
 *  2) pass this void pointer by reference to this function.
 *     Set lid to the key you want to enumerate and pass it by reference.
 *  3) call this function as long as it does not return -1
 *     to indicate EOF. LID does contain the next key used to build the web
 *  4) Always call this function a last time with LID set to NULL,
 *     so that it can free its context.
 */
int
enum_trust_web( void **context, ulong *lid )
{
    ENUM_TRUST_WEB_CONTEXT *c = *context;

    if( !c ) { /* make a new context */
	c = m_alloc_clear( sizeof *c );
	*context = c;
	if( *lid == last_trust_web_key && last_trust_web_tslist )
	    c->tsl = last_trust_web_tslist;
	else {
	    TRUST_SEG_LIST tsl, tsl2, tslist;
	    int rc;

	    rc = make_tsl( *lid, &tslist );
	    if( rc ) {
		log_error("failed to build the TSL\n");
		return rc;
	    }
	    /* cache the tslist, so that we do not need to free it */
	    if( last_trust_web_key ) {
		for( tsl = last_trust_web_tslist; tsl; tsl = tsl2 ) {
		    tsl2 = tsl->next;
		    m_free(tsl);
		}
	    }
	    last_trust_web_key = *lid;
	    last_trust_web_tslist = tslist;
	    c->tsl = last_trust_web_tslist;
	}
	c->index = 1;
    }

    if( !lid ) { /* free the context */
	m_free( c );
	*context = NULL;
	return 0;
    }

    while( c->tsl ) {
	if( !c->tsl->dup && c->index < c->tsl->nseg-1 ) {
	    *lid = c->tsl->seg[c->index].lid;
	    c->index++;
	    return 0;
	}
	c->index = 1;
	c->tsl = c->tsl->next;
    }
    return -1; /* eof */
}


/****************
 * Return the assigned ownertrust value for the given LID
 */
unsigned
get_ownertrust( ulong lid )
{
    TRUSTREC rec;

    read_record( lid, &rec, RECTYPE_DIR );
    return rec.r.dir.ownertrust;
}

int
get_ownertrust_info( ulong lid )
{
    unsigned otrust;
    int c;

    otrust = get_ownertrust( lid );
    switch( (otrust & TRUST_MASK) ) {
      case TRUST_NEVER:     c = 'n'; break;
      case TRUST_MARGINAL:  c = 'm'; break;
      case TRUST_FULLY:     c = 'f'; break;
      case TRUST_ULTIMATE:  c = 'u'; break;
      default:		    c = '-'; break;
    }
    return c;
}


byte *
get_pref_data( ulong lid, const byte *namehash, size_t *ret_n )
{
    TRUSTREC rec;
    ulong recno;

    read_record( lid, &rec, RECTYPE_DIR );
    for( recno=rec.r.dir.uidlist; recno; recno = rec.r.uid.next ) {
	read_record( recno, &rec, RECTYPE_UID );
	if( rec.r.uid.prefrec
	    && ( !namehash || !memcmp(namehash, rec.r.uid.namehash, 20) ))  {
	    byte *buf;
	    /* found the correct one or the first one */
	    read_record( rec.r.uid.prefrec, &rec, RECTYPE_PREF );
	    if( rec.r.pref.next )
		log_info("warning: can't yet handle long pref records\n");
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

    read_record( lid, &rec, RECTYPE_DIR );
    for( recno=rec.r.dir.uidlist; recno; recno = rec.r.uid.next ) {
	read_record( recno, &rec, RECTYPE_UID );
	if( rec.r.uid.prefrec ) {
	    read_record( rec.r.uid.prefrec, &rec, RECTYPE_PREF );
	    if( rec.r.pref.next )
		log_info("warning: can't yet handle long pref records\n");
	    pref = rec.r.pref.data;
	    for(i=0; i+1 < ITEMS_PER_PREF_RECORD; i+=2 ) {
		if( pref[i] == preftype && pref[i+1] == algo )
		    return 1;
	    }
	}
    }
    return 0;
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
	    log_error("get_dir_record: search_record failed: %s\n",
							    g10_errstr(rc));
    }
    return rc;
}



/****************
 * This function simply looks for the key in the trustdb
 * and makes sure that pk->local_id is set to the coreect value.
 * Return: 0 = found
 *	   -1 = not found
 *	  other = error
 */
int
query_trust_record( PKT_public_key *pk )
{
    TRUSTREC rec;
    return get_dir_record( pk, &rec );
}


int
clear_trust_checked_flag( PKT_public_key *pk )
{
    TRUSTREC rec;
    int rc;

    rc = get_dir_record( pk, &rec );
    if( rc )
	return rc;

    if( !(rec.r.dir.dirflags & DIRF_CHECKED) )
	return 0;

    /* reset the flag */
    rec.r.dir.dirflags &= ~DIRF_CHECKED;
    write_record( &rec );
    return 0;
}



/****************
 * Update all the info from the public keyblock,  the signatures-checked
 * flag is reset. The key must already exist in the keydb.
 *
 * Implementation of this function needs a cache for tdbio record updates
 */
int
update_trust_record( KBNODE keyblock )
{
    PKT_public_key *primary_pk;
    KBNODE node;
    TRUSTREC drec;
    TRUSTREC krec;
    TRUSTREC prec;
    TRUSTREC urec;
    TRUSTREC helprec;
    int modified = 0;
    int rc = 0;
    u32 keyid[2]; /* keyid of primary key */
    ulong recno, newrecno, lastrecno;
    ulong uidrecno = 0;
    byte uidhash[20];
    RECNO_LIST recno_list = NULL; /* list of verified records */

    node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    primary_pk = node->pkt->pkt.public_key;
    rc = get_dir_record( primary_pk, &drec );
    if( rc )
	return rc;

    keyid_from_pk( primary_pk, keyid );

    /* fixme: start a transaction */
    /* now update keys and user ids */
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    byte fpr[MAX_FINGERPRINT_LEN];
	    size_t fprlen;

	    uidrecno = 0;

	    fingerprint_from_pk( pk, fpr, &fprlen );
	    /* do we already have this key? */
	    for( recno=drec.r.dir.keylist; recno; recno = krec.r.key.next ) {
		read_record( recno, &krec, RECTYPE_KEY );
		if( krec.r.key.fingerprint_len == fprlen
		    && !memcmp( krec.r.key.fingerprint, fpr, fprlen ) )
		    break;
	    }
	    if( recno ) { /* yes */
		ins_recno_list( &recno_list, recno, RECTYPE_KEY );
		/* here we would compare/update the keyflags */
	    }
	    else { /* no: insert this new key */
		memset( &krec, 0, sizeof(krec) );
		krec.rectype = RECTYPE_KEY;
		krec.r.key.lid = drec.recnum;
		krec.r.key.pubkey_algo = pk->pubkey_algo;
		krec.r.key.fingerprint_len = fprlen;
		memcpy(krec.r.key.fingerprint, fpr, fprlen );
		krec.recnum = newrecno = tdbio_new_recnum();
		write_record( &krec );
		ins_recno_list( &recno_list, newrecno, RECTYPE_KEY );
		/* and put this new record at the end of the keylist */
		if( !(recno=drec.r.dir.keylist) ) {
		    /* this is the first key */
		    drec.r.dir.keylist = newrecno;
		    modified = 1;
		}
		else { /* we already have key, append it to the list */
		    for( ; recno; recno = krec.r.key.next )
			read_record( recno, &krec, RECTYPE_KEY );
		    krec.r.key.next = newrecno;
		    write_record( &krec );
		}
	    } /* end insert new key */
	} /* end packet type public key packet */
	else if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;
	    TRUSTREC urec;

	    rmd160_hash_buffer( uidhash, uid->name, uid->len );
	    for( recno=drec.r.dir.uidlist; recno; recno = urec.r.uid.next ) {
		read_record( recno, &urec, RECTYPE_UID );
		if( !memcmp( uidhash, urec.r.uid.namehash, 20 ) )
		    break;
	    }
	    if( recno ) {
		ins_recno_list( &recno_list, recno, RECTYPE_UID );
		uidrecno = recno;
	    }
	    else { /* new user id */
		memset( &urec, 0 , sizeof(urec) );
		urec.rectype = RECTYPE_UID;
		urec.r.uid.lid = drec.recnum;
		memcpy(urec.r.uid.namehash, uidhash, 20 );
		urec.recnum = newrecno = tdbio_new_recnum();
		write_record( &urec );
		ins_recno_list( &recno_list, newrecno, RECTYPE_UID );
		/* and put this new record at the end of the uidlist */
		if( !(recno=drec.r.dir.uidlist) ) {
		    /* this is the first uid */
		    drec.r.dir.uidlist = newrecno;
		    modified = 1;
		}
		else { /* we already have an uid, append it to the list */
		    for( ; recno; recno = urec.r.key.next )
			read_record( recno, &urec, RECTYPE_UID );
		    urec.r.uid.next = newrecno;
		    write_record( &urec );
		}
		uidrecno = newrecno;
	    }
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
		&& (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
		/* must verify this selfsignature here, so that we can
		 * build the preference record and validate the uid record
		 */
		if( !uidrecno ) {
		    log_error("key %08lX: self-signature without user id\n",
			      (ulong)keyid[1] );
		}
		else if( (rc = check_key_signature( keyblock, node, NULL ))) {
		    log_error("key %08lX, uid %02X%02X: "
			      "invalid self-signature: %s\n", (ulong)keyid[1],
				    uidhash[18], uidhash[19], g10_errstr(rc) );
		    rc = 0;
		}
		else { /* build the prefrecord */
		    static struct {
			sigsubpkttype_t subpkttype;
			int preftype;
		    } prefs[] = {
			{ SIGSUBPKT_PREF_SYM,	PREFTYPE_SYM	},
			{ SIGSUBPKT_PREF_HASH,	PREFTYPE_HASH	},
			{ SIGSUBPKT_PREF_COMPR, PREFTYPE_COMPR	},
			{ 0, 0 }
		    };
		    const byte *s;
		    size_t n;
		    int k, i;
		    ulong recno_tbl[10];
		    int recno_idx = 0;

		    read_record( uidrecno, &urec, RECTYPE_UID );

		    /* first delete all pref records */
		    for(recno=urec.r.uid.prefrec ; recno;
						   recno = prec.r.pref.next ) {
			read_record( recno, &prec, RECTYPE_PREF );
			delete_record( recno );
		    }

		    /* and write the new ones */
		    i = 0;
		    for(k=0; prefs[k].subpkttype; k++ ) {
			s = parse_sig_subpkt2( sig, prefs[k].subpkttype, &n );
			if( s ) {
			    while( n ) {
				if( !i || i >= ITEMS_PER_PREF_RECORD ) {
				    if( recno_idx >= DIM(recno_tbl)-1 ) {
					log_info("too many preferences\n");
					break;
				    }
				    if( i ) {
					recno_tbl[recno_idx]=tdbio_new_recnum();
					prec.recnum = recno_tbl[recno_idx++];
					write_record( &prec );
				    }
				    memset( &prec, 0, sizeof prec );
				    prec.rectype = RECTYPE_PREF;
				    prec.r.pref.lid = drec.recnum;
				    i = 0;
				}
				prec.r.pref.data[i++] = prefs[k].preftype;
				prec.r.pref.data[i++] = *s++;
				n--;
			    }
			}
		    }
		    if( i ) { /* write the last one */
			recno_tbl[recno_idx]=tdbio_new_recnum();
			prec.recnum = recno_tbl[recno_idx++];
			write_record( &prec );
		    }
		    /* now link them together */
		    for(i=0; i < recno_idx-1; i++ ) {
			read_record( recno_tbl[i], &prec, RECTYPE_PREF );
			prec.r.pref.next = recno_tbl[i+1];
			write_record( &prec );
		    }
		    /* don't need to write the last one, but update the uid */
		    urec.r.uid.prefrec = recno_idx? recno_tbl[0] : 0;
		    write_record( &urec );
		}
	    }
	    else if( 0 /* is revocation sig etc */ ) {
		/* handle it here */
	    }
	    else { /* not a selfsignature */
	    }
	}
    } /* end loop over all nodes */


    /* now delete keyrecords from the trustdb which are not anymore used */
    lastrecno = 0;
    for( recno=drec.r.dir.keylist; recno; recno = krec.r.key.next ) {
	read_record( recno, &krec, RECTYPE_KEY );
	if( !qry_recno_list( recno_list, recno, RECTYPE_KEY ) ) {
	    /* delete this one */
	    if( !lastrecno ) {
		drec.r.dir.keylist = krec.r.key.next;
		modified = 1;
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
    /* now delete uid records and their pref records from the
     * trustdb which are not anymore used */
    lastrecno = 0;
    for( recno=drec.r.dir.uidlist; recno; recno = urec.r.uid.next ) {
	read_record( recno, &urec, RECTYPE_UID );
	if( !qry_recno_list( recno_list, recno, RECTYPE_UID ) ) {
	    ulong r2;
	    /* delete this one */
	    if( !lastrecno ) {
		drec.r.dir.uidlist = urec.r.uid.next;
		modified = 1;
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
	    delete_record( recno );
	}
	else
	    lastrecno = recno;
    }



    if( rc )
	; /* fixme: cancel transaction */
    else if( modified ) {
	drec.r.dir.dirflags &= ~DIRF_CHECKED; /* reset flag */
	write_record( &drec );
	/* fixme: commit_transaction */
    }
    rel_recno_list( &recno_list );
    return rc;
}


/****************
 * Insert a trust record into the TrustDB
 * This function fails if this record already exists.
 *
 * We build everything we can do at this point. We cannot build
 * the sig records, because their LIDs are needed and we may not have them.
 */
int
insert_trust_record( PKT_public_key *pk )
{
    TRUSTREC dirrec;
    KBNODE keyblock = NULL;
    KBNODE node;
    byte *fingerprint;
    size_t fingerlen;
    int rc = 0;


    if( pk->local_id )
	log_bug("pk->local_id=%lu\n", pk->local_id );

    fingerprint = fingerprint_from_pk( pk, NULL, &fingerlen );

    /* fixme: assert that we do not have this record.
     * we can do this by searching for the primary keyid
     */

    /* get the keyblock which has the key */
    rc = get_keyblock_byfprint( &keyblock, fingerprint, fingerlen );
    if( rc ) { /* that should never happen */
	log_error( "insert_trust_record: keyblock not found: %s\n",
							  g10_errstr(rc) );
	goto leave;
    }

    memset( &dirrec, 0, sizeof dirrec );
    dirrec.rectype = RECTYPE_DIR;
    dirrec.recnum = tdbio_new_recnum();
    dirrec.r.dir.lid = dirrec.recnum;
    write_record( &dirrec );

    /* store the LID */
    pk->local_id = dirrec.r.dir.lid;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    pk->local_id = dirrec.r.dir.lid;
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    sig->local_id = dirrec.r.dir.lid;
	}
    }

    /* and put all the other stuff into the keydb */
    rc = update_trust_record( keyblock );


  leave:
    m_free(fingerprint);
    release_kbnode( keyblock );
    return rc;
}


int
update_ownertrust( ulong lid, unsigned new_trust )
{
    TRUSTREC rec;

    read_record( lid, &rec, RECTYPE_DIR );
    rec.r.dir.ownertrust = new_trust;
    write_record( &rec );
    return 0;
}


