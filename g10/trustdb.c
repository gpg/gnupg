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
 ************* list helpers *******************
 **********************************************/

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
	rc = tdbio_read_record( c->lid, r, RECTYPE_DIR );
	if( rc ) {
	    log_error("LID %lu: error reading dir record: %s\n",
				    c->lid, g10_errstr(rc));
	    return rc;
	}
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
		rc = tdbio_read_record( c->ctl.nextuid, r, RECTYPE_UID );
		if( rc ) {
		    log_error("error reading next uidrec: %s\n",
						    g10_errstr(rc));
		    c->ctl.eof = 1;
		    return rc;
		}
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
		    rc = tdbio_read_record( c->ctl.nextuid, r, RECTYPE_UID );
		    if( rc ) {
			log_error("LID %lu: error re-reading uid record: %s\n",
						c->lid, g10_errstr(rc));
			return rc;
		    }
		}
		c->ctl.nextuid = r->r.uid.next;
		rnum = r->r.uid.siglist;
	    }
	    if( !rnum ) {
		c->ctl.eof = 1;
		return -1;  /* return eof */
	    }
	    rc = tdbio_read_record( rnum, r, RECTYPE_SIG );
	    if( rc ) {
		log_error(_("error reading sigrec: %s\n"), g10_errstr(rc));
		c->ctl.eof = 1;
		return rc;
	    }
	    if( r->r.sig.lid != c->lid ) {
		log_error(_("chained sigrec %lu has a wrong owner\n"), rnum );
		c->ctl.eof = 1;
		return G10ERR_TRUSTDB;
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
    int rc;

    assert(dir->rectype == RECTYPE_DIR );
    rmd160_hash_buffer( nhash, uid->name, uid->len );
    for( recno=dir->r.dir.uidlist; recno; recno = urec->r.uid.next ) {
	rc = tdbio_read_record( recno, urec, RECTYPE_UID );
	if( rc )
	    return rc == -1 ? G10ERR_READ_FILE : rc;
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
    int rc;
    TRUSTREC *rec, srec;
    ulong nextrecno;
    ulong recno;

    nextrecno = urec->r.uid.siglist;
    urec->r.uid.siglist = 0; /* end of list marker */
    for( rec = urec->next; rec; rec = rec->next ) {
	assert( rec->rectype == RECTYPE_SIG );
	if( nextrecno ) { /* read the sig record, so it can be reused */
	    rc = tdbio_read_record( nextrecno, &srec, RECTYPE_SIG );
	    if( rc ) {
		log_error("write_sig_from_urec: read sigrecno %lu failed: %s\n",
						  nextrecno, g10_errstr(rc) );
		return rc;
	    }
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
	rc = tdbio_write_record( rec );
	if( rc ) {
	    log_error("write_sig_from_urec: write sigrecno %lu failed: %s\n",
						  recno, g10_errstr(rc) );
	    return rc;
	}
    }

    /* write the urec back */
    rc = tdbio_write_record( urec );
    if( rc ) {
	log_error("write_sig_from_urec: write urec %lu failed: %s\n",
					    urec->recnum, g10_errstr(rc) );
	return rc;
    }

    /* delete remaining old sigrecords */
    while( nextrecno ) {
	rc = tdbio_read_record( nextrecno, &srec, RECTYPE_SIG );
	if( rc ) {
	    log_error("write_sig_from_urec: read sigrecno %lu failed: %s\n",
					      nextrecno, g10_errstr(rc) );
	    return rc;
	}
	rc = tdbio_delete_record( nextrecno );
	if( rc ) {
	    log_error("write_sig_from_urec: delete old %lu failed: %s\n",
					      nextrecno, g10_errstr(rc) );
	    return rc;

	}
	nextrecno = srec.r.sig.next;
    }

    return rc;
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

    if( (rc=tdbio_read_record( dir->r.dir.keylist, &krec, RECTYPE_KEY )) ) {
	log_error("update_sigs: can't read primary key for %lu\n", lid);
	goto leave;
    }
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
    rc = tdbio_write_record( dir );
    if( rc ) {
	log_error("update_sigs: write dir record failed: %s\n", g10_errstr(rc));
	return rc;
    }

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

    rc = tdbio_read_record( lid, &rec, RECTYPE_DIR );
    if( rc ) {
	log_error("LID %lu: error reading dir record: %s\n",
				lid, g10_errstr(rc));
	return rc;
    }
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
    int i, rc;
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
		rc = get_ownertrust( tsl->seg[i].lid, &tr );
		if( rc )
		    return rc;
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
	    rc = tdbio_write_record( &rec );
	    if( rc )
		log_error_f(fname, "error updating otrust: %s\n",
						    g10_errstr(rc));
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
	if( tdbio_read_record( pk->local_id, &rec, RECTYPE_DIR ) ) {
	    log_error("check_trust: read dir record failed\n");
	    return G10ERR_TRUSTDB;
	}
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
	    if( tdbio_read_record( pk->local_id, &rec, RECTYPE_DIR ) ) {
		log_error("check_trust: reread dir record failed\n");
		return G10ERR_TRUSTDB;
	    }
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
int
get_ownertrust( ulong lid, unsigned *r_otrust )
{
    TRUSTREC rec;

    if( tdbio_read_record( lid, &rec, RECTYPE_DIR ) ) {
	log_error("get_ownertrust: read dir record failed\n");
	return G10ERR_TRUSTDB;
    }
    if( r_otrust )
	*r_otrust = rec.r.dir.ownertrust;
    return 0;
}

int
get_ownertrust_info( ulong lid )
{
    unsigned otrust;
    int c;

    if( get_ownertrust( lid, &otrust ) )
	return '?';
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
    int rc;

    if( tdbio_read_record( lid, &rec, RECTYPE_DIR ) ) {
	log_error("get_pref_data: read dir record failed\n");
	return NULL;
    }

    for( recno=rec.r.dir.uidlist; recno; recno = rec.r.uid.next ) {
	rc = tdbio_read_record( recno, &rec, RECTYPE_UID );
	if( rc ) {
	    log_error("get_pref_data: read uid record failed: %s\n",
						     g10_errstr(rc));
	    return NULL;
	}
	if( rec.r.uid.prefrec
	    && ( !namehash || !memcmp(namehash, rec.r.uid.namehash, 20) ))  {
	    byte *buf;
	    /* found the correct one or the first one */
	    rc = tdbio_read_record( rec.r.uid.prefrec, &rec, RECTYPE_PREF );
	    if( rc ) {
		log_error("get_pref_data: read pref record failed: %s\n",
							 g10_errstr(rc));
		return NULL;
	    }
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
    int i, rc;
    byte *pref;

    if( tdbio_read_record( lid, &rec, RECTYPE_DIR ) ) {
	log_error("is_algo_in_prefs: read dir record failed\n");
	return 0;
    }

    for( recno=rec.r.dir.uidlist; recno; recno = rec.r.uid.next ) {
	rc = tdbio_read_record( recno, &rec, RECTYPE_UID );
	if( rc ) {
	    log_error("is_algo_in_prefs: read uid record failed: %s\n",
						     g10_errstr(rc));
	    return 0;
	}
	if( rec.r.uid.prefrec ) {
	    rc = tdbio_read_record( rec.r.uid.prefrec, &rec, RECTYPE_PREF );
	    if( rc ) {
		log_error("is_algo_in_prefs: read pref record failed: %s\n",
							 g10_errstr(rc));
		return 0;
	    }
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
    int rc=0;

    if( pk->local_id ) {
	if( tdbio_read_record( pk->local_id, &rec, RECTYPE_DIR ) ) {
	    log_error("query_trust_record: read record failed\n");
	    return G10ERR_TRUSTDB;
	}
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=tdbio_search_dir_bypk( pk, &rec )) && rc != -1 ) {
	    log_error("query_trust_record: search_record failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
    }
    return rc;
}


int
clear_trust_checked_flag( PKT_public_key *pk )
{
    TRUSTREC rec;
    int rc;

    if( !pk->local_id ) {
	query_trust_record( pk );
	if( !pk->local_id )
	    log_bug("clear_trust_checked_flag: Still no LID\n");
    }

    if( (rc=tdbio_read_record( pk->local_id, &rec, RECTYPE_DIR ))) {
	log_error("clear_trust_checked_flag: read record failed: %s\n",
							      g10_errstr(rc));
	return rc;
    }

    if( !(rec.r.dir.dirflags & DIRF_CHECKED) )
	return 0;

    /* reset the flag */
    rec.r.dir.dirflags &= ~DIRF_CHECKED;
    rc = tdbio_write_record( &rec );
    if( rc ) {
	log_error("clear_trust_checked_flag: write dir record failed: %s\n",
							      g10_errstr(rc));
	return rc;
    }
    return 0;
}


/****************
 * helper function for insert_trust_record()
 */
static void
rel_mem_uidnode( u32 *keyid, int err, TRUSTREC *rec )
{
    TRUSTREC *r, *r2;

    if( err )
	log_error("key %08lX, uid %02X%02X: invalid user id - removed\n",
	    (ulong)keyid[1], rec->r.uid.namehash[18], rec->r.uid.namehash[19] );
    for(r=rec->help_pref; r; r = r2 ) {
	r2 = r->next;
	m_free(r);
    }

    m_free(rec);
}


/****************
 * Insert a trust record into the TrustDB
 * This function fails if this record already exists.
 *
 * We build everything we can do at this point. We cannot build
 * the sig records, because their LIDs are needed and we may not have them.
 */
int
insert_trust_record( PKT_public_key *orig_pk )
{
    TRUSTREC dirrec, *rec, *rec2;
    TRUSTREC *keylist_head, **keylist_tail, *keylist;
    TRUSTREC *uidlist_head, **uidlist_tail, *uidlist;
    KBNODE keyblock = NULL;
    KBNODE node;
    u32 keyid[2]; /* of primary key */
    byte *fingerprint;
    size_t fingerlen;
    int rc = 0;

    keylist_head = NULL; keylist_tail = &keylist_head; keylist = NULL;
    uidlist_head = NULL; uidlist_tail = &uidlist_head; uidlist = NULL;

    /* prepare dir record */
    memset( &dirrec, 0, sizeof dirrec );
    dirrec.rectype = RECTYPE_DIR;

    if( orig_pk->local_id )
	log_bug("pk->local_id=%lu\n", (ulong)orig_pk->local_id );

    fingerprint = fingerprint_from_pk( orig_pk, NULL, &fingerlen );

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

    /* build data structure as linked lists in memory */
    keyid[0] = keyid[1] = 0;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;

	    if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
		if( keylist_head )
		    BUG();  /* more than one primary key */
		keyid_from_pk( pk, keyid );
	    }
	    fingerprint = fingerprint_from_pk( pk, NULL, &fingerlen );
	    rec = m_alloc_clear( sizeof *rec );
	    rec->rectype = RECTYPE_KEY;
	    rec->r.key.pubkey_algo = pk->pubkey_algo;
	    rec->r.key.fingerprint_len = fingerlen;
	    memcpy(rec->r.key.fingerprint, fingerprint, fingerlen );

	    *keylist_tail = rec; keylist_tail = &rec->next;
	}
	else if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;

	    rec = m_alloc_clear( sizeof *rec );
	    rec->rectype = RECTYPE_UID;
	    rmd160_hash_buffer( rec->r.uid.namehash, uid->name, uid->len );

	    uidlist = rec;
	    *uidlist_tail = rec; uidlist_tail = &rec->next;
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
		&& (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
		/* must verify this selfsignature here, so that we can
		 * build the preference record and validate the uid record
		 */
		if( !uidlist ) {
		    log_error("key %08lX: self-signature without user id\n",
			      (ulong)keyid[1] );
		}
		else if( (rc = check_key_signature( keyblock, node, NULL ))) {
		    log_error("key %08lX, uid %02X%02X: "
			      "invalid self-signature: %s\n",
			      (ulong)keyid[1], uidlist->r.uid.namehash[18],
			      uidlist->r.uid.namehash[19], g10_errstr(rc) );
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
		    assert(uidlist);
		    assert(!uidlist->help_pref);
		    uidlist->mark |= 1; /* mark valid */

		    i = 0;
		    for(k=0; prefs[k].subpkttype; k++ ) {
			s = parse_sig_subpkt2( sig, prefs[k].subpkttype, &n );
			if( s ) {
			    while( n ) {
				if( !i || i >= ITEMS_PER_PREF_RECORD ) {
				    rec = m_alloc_clear( sizeof *rec );
				    rec->rectype = RECTYPE_PREF;
				    rec->next = uidlist->help_pref;
				    uidlist->help_pref = rec;
				    i = 0;
				}
				rec->r.pref.data[i++] = prefs[k].preftype;
				rec->r.pref.data[i++] = *s++;
				n--;
			    }
			}
		    }
		}
	    }
	    else if( 0 /* is revocation sig etc */ ) {
		/* handle it here */
	    }
	    else { /* not a selfsignature */
	    }
	}
    }

    /* delete all invalid marked userids and their preferences and sigs */
    /* (ugly code - I know) */
    while( (rec=uidlist_head) && !(rec->mark & 1) ) {
	uidlist_head = rec->next;
	rel_mem_uidnode(keyid, 1, rec);
    }
    for( ; rec; rec = rec->next ) {
	if( rec->next && !(rec->next->mark & 1) ) {
	    TRUSTREC *r = rec->next;
	    rec->next = r->next;
	    rel_mem_uidnode(keyid, 1, r);
	}
    }

    /* check that we have at least one userid */
    if( !uidlist_head ) {
	log_error("key %08lX: no user ids - rejected\n", (ulong)keyid[1] );
	rc = G10ERR_BAD_CERT;
	goto leave;
    }

    /* insert the record numbers to build the real (on disk) list */
    /* fixme: should start a transaction here */
    dirrec.recnum = tdbio_new_recnum();
    dirrec.r.dir.lid = dirrec.recnum;
    /* (list of keys) */
    for(rec=keylist_head; rec; rec = rec->next ) {
	rec->r.key.lid = dirrec.recnum;
	rec->recnum = tdbio_new_recnum();
    }
    for(rec=keylist_head; rec; rec = rec->next )
	rec->r.key.next = rec->next? rec->next->recnum : 0;
    dirrec.r.dir.keylist = keylist_head->recnum;
    /* (list of user ids) */
    for(rec=uidlist_head; rec; rec = rec->next ) {
	rec->r.uid.lid = dirrec.recnum;
	rec->recnum = tdbio_new_recnum();
	/* (preference records) */
	if( rec->help_pref ) {
	    for( rec2 = rec->help_pref; rec2; rec2 = rec2->next ) {
		rec2->r.pref.lid = dirrec.recnum;
		rec2->recnum = tdbio_new_recnum();
	    }
	    for( rec2 = rec->help_pref; rec2->next; rec2 = rec2->next )
		rec2->next->r.pref.next = rec2->recnum;
	    rec->r.uid.prefrec = rec2->recnum;
	}
    }
    for(rec=uidlist_head; rec; rec = rec->next )
	rec->r.uid.next = rec->next? rec->next->recnum : 0;
    dirrec.r.dir.uidlist = uidlist_head->recnum;

    /* write all records */
    for(rec=keylist_head; rec; rec = rec->next ) {
	assert( rec->rectype == RECTYPE_KEY );
	if( tdbio_write_record( rec ) ) {
	    log_error("writing key record failed\n");
	    rc = G10ERR_TRUSTDB;
	    goto leave;
	}
    }
    for(rec=uidlist_head; rec; rec = rec->next ) {
	assert( rec->rectype == RECTYPE_UID );
	if( tdbio_write_record( rec ) ) {
	    log_error("writing uid record failed\n");
	    rc = G10ERR_TRUSTDB;
	    goto leave;
	}
	for( rec2=rec->help_pref; rec2; rec2 = rec2->next ) {
	    assert( rec2->rectype == RECTYPE_PREF );
	    if( tdbio_write_record( rec2 ) ) {
		log_error("writing pref record failed\n");
		rc = G10ERR_TRUSTDB;
		goto leave;
	    }
	}
    }
    if( tdbio_write_record( &dirrec ) ) {
	log_error("writing dir record failed\n");
	return G10ERR_TRUSTDB;
    }

    /* and store the LID */
    orig_pk->local_id = dirrec.r.dir.lid;
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


  leave:
    for(rec=uidlist_head; rec; rec = rec2 ) {
	rec2 = rec->next;
	rel_mem_uidnode(NULL, 0, rec );
    }
    for(rec=keylist_head; rec; rec = rec2 ) {
	rec2 = rec->next;
	m_free(rec);
    }

    return rc;
}


int
update_ownertrust( ulong lid, unsigned new_trust )
{
    TRUSTREC rec;

    if( tdbio_read_record( lid, &rec, RECTYPE_DIR ) ) {
	log_error("update_ownertrust: read dir failed\n");
	return G10ERR_TRUSTDB;
    }
    rec.r.dir.ownertrust = new_trust;
    if( tdbio_write_record( &rec ) ) {
	log_error("update_ownertrust: write failed\n");
	return G10ERR_TRUSTDB;
    }
    return 0;
}


