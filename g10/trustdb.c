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

static int list_sigs( ulong pubkey_id );
static int build_sigrecs( ulong local_id );
static int propagate_trust( TRUST_SEG_LIST tslist );
static int do_check( TRUSTREC *drec, unsigned *trustlevel );


/* a table used to keep track of ultimately trusted keys
 * which are the ones from our secrings */
static LOCAL_ID_INFO *ultikey_table;

static ulong last_trust_web_key;
static TRUST_SEG_LIST last_trust_web_tslist;


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
set_signature_packets_local_id( PKT_signature *sig )
{
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    TRUSTREC rec;
    int rc;

    rc = get_pubkey( pk, sig->keyid );
    if( rc)
	goto leave;
    if( !pk->local_id ) {
	rc = tdbio_search_dir_record( pk, &rec );
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



static int
keyid_from_local_id( ulong lid, u32 *keyid )
{
    TRUSTREC rec;
    int rc;

    rc = tdbio_read_record( lid, &rec, RECTYPE_DIR );
    if( rc ) {
	log_error(_("error reading record with local_id %lu: %s\n"),
						    lid, g10_errstr(rc));
	return G10ERR_TRUSTDB;
    }
    if( rec.rectype != RECTYPE_DIR ) {
	log_error(_("record with local_id %lu is not a dir record\n"), lid);
	return G10ERR_TRUSTDB;
    }
    keyid[0] = rec.r.dir.keyid[0];
    keyid[1] = rec.r.dir.keyid[1];
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
	if( !c->sigrec ) {
	    rc = tdbio_read_record( c->local_id, r, RECTYPE_DIR );
	    if( rc ) {
		log_error(_("%lu: error reading dir record: %s\n"),
					c->local_id, g10_errstr(rc));
		return rc;
	    }
	    c->sigrec = r->r.dir.sigrec;
	    if( !c->sigrec && create && !r->r.dir.no_sigs ) {
		rc = build_sigrecs( c->local_id );
		if( rc ) {
		    if( rc == G10ERR_BAD_CERT )
			rc = -1;  /* maybe no selcficnature */
		    if( rc != -1 )
			log_info(_("%lu: error building sigs on the fly: %s\n"),
			       c->local_id, g10_errstr(rc) );
		    c->ctl.eof = 1;
		    return rc;
		}
		rc = tdbio_read_record( c->local_id, r, RECTYPE_DIR );
		if( rc ) {
		    log_error(_("%lu: error re-reading dir record: %s\n"),
					    c->local_id, g10_errstr(rc));
		    return rc;
		}
		c->sigrec = r->r.dir.sigrec;
	    }
	    if( !c->sigrec ) {
		c->ctl.eof = 1;
		return -1;
	    }
	}
	/* force a read */
	c->ctl.index = SIGS_PER_RECORD;
	r->r.sig.chain = c->sigrec;
    }

    /* enter loop to skip deleted sigs */
    do {
	if( c->ctl.index >= SIGS_PER_RECORD ) {
	    /* read the record */
	    rnum = r->r.sig.chain;
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
	    if( r->r.sig.owner != c->local_id ) {
		log_error(_("chained sigrec %lu has a wrong owner\n"), rnum );
		c->ctl.eof = 1;
		return G10ERR_TRUSTDB;
	    }
	    c->ctl.index = 0;
	}
    } while( !r->r.sig.sig[c->ctl.index++].local_id );
    c->sig_id = r->r.sig.sig[c->ctl.index-1].local_id;
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

    while( !(rc=enum_secret_keys( &enum_context, sk) ) ) {
	/* To be sure that it is a secret key of our own,
	 * we should check it, but this needs a passphrase
	 * for every key and this is boring for the user.
	 * Anyway, access to the seret keyring should be
	 * granted to the user only as it is poosible to
	 * crack it with dictionary attacks.
	 */
	keyid_from_sk( sk, keyid );

	if( DBG_TRUST )
	    log_debug("key %08lX: checking secret key\n", (ulong)keyid[1] );

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
    if( keyid_from_trustdb( lid, ki ) )
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
    sx.local_id = pubkey;
    for(;;) {
	rc = walk_sigrecs( &sx, 0 );
	if( rc )
	    break;
	rc = keyid_from_local_id( sx.sig_id, keyid );
	if( rc ) {
	    printf("%6u: %*s????????.%lu:%02x\n", *lineno, depth*4, "",
						   sx.sig_id, sx.sig_flag );
	    ++*lineno;
	}
	else {
	    printf("%6u: %*s%08lX.%lu:%02x ", *lineno, depth*4, "",
			      (ulong)keyid[1], sx.sig_id, sx.sig_flag );
	    /* check whether we already checked this pubkey */
	    if( !qry_lid_table_flag( ultikey_table, sx.sig_id, NULL ) ) {
		print_user_id("[ultimately trusted]", keyid);
		++*lineno;
	    }
	    else if( sx.sig_id == pubkey ) {
		printf("[self-signature]\n");
		++*lineno;
	    }
	    else if( sx.sig_id == root ) {
		printf("[closed]\n");
		++*lineno;
	    }
	    else if( ins_lid_table_item( lids, sx.sig_id, *lineno ) ) {
		unsigned refline;
		qry_lid_table_flag( lids, sx.sig_id, &refline );
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
		rc = do_list_sigs( root, sx.sig_id, depth+1, lids, lineno );
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

    rc = keyid_from_local_id( pubkey_id, keyid );
    if( rc ) {
	log_error("Hmmm, no pubkey record for local_id %lu\n", pubkey_id);
	return rc;
    }
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
    sx.local_id = stack[depth-1].lid;
    /* loop over all signatures. If we do not have any, try to
     * create them */
    while( !(rc = walk_sigrecs( &sx, 1 )) ) {
	TRUST_SEG_LIST tsl, t2, tl;
	int i;

	stack[depth].lid = sx.sig_id;
	stack[depth].trust = 0;
	if( qry_lid_table_flag( lids, sx.sig_id, &last_depth) ) {
	    /*printf("%2lu/%d: marked\n", sx.sig_id, depth );*/
	    ins_lid_table_item( lids, sx.sig_id, depth);
	    last_depth = depth;
	}
	else if( depth	< last_depth ) {
	    /*printf("%2lu/%d: last_depth=%u - updated\n", sx.sig_id, depth, last_depth);*/
	    last_depth = depth;
	    upd_lid_table_flag( lids, sx.sig_id, depth);
	}

	if( last_depth < depth )
	    /*printf("%2lu/%d: already visited\n", sx.sig_id, depth)*/;
	else if( !qry_lid_table_flag( ultikey_table, sx.sig_id, NULL ) ) {
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
	    /*printf("%2lu/%d: found\n", sx.sig_id, depth);*/
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
 * Check all the sigs of the given keyblock and mark them
 * as checked. Valid signatures which are duplicates are
 * also marked [shall we check them at all?]
 * FIXME: what shall we do if we have duplicate signatures where only
 *	  some of them are bad?
 */
static int
check_sigs( KBNODE keyblock, int *selfsig_okay, int *revoked )
{
    KBNODE node;
    int rc;
    LOCAL_ID_INFO *dups = NULL;

    *selfsig_okay = 0;
    *revoked = 0;
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_SIGNATURE
	    && ( (node->pkt->pkt.signature->sig_class&~3) == 0x10
		  || node->pkt->pkt.signature->sig_class == 0x20
		  || node->pkt->pkt.signature->sig_class == 0x30) ) {
	    int selfsig;
	    rc = check_key_signature( keyblock, node, &selfsig );
	    if( !rc ) {
		rc = set_signature_packets_local_id( node->pkt->pkt.signature );
		if( rc )
		    log_fatal("set_signature_packets_local_id failed: %s\n",
							      g10_errstr(rc));
		if( selfsig ) {
		    node->flag |= 2; /* mark signature valid */
		    *selfsig_okay = 1;
		}
		else if( node->pkt->pkt.signature->sig_class == 0x20 )
		    *revoked = 1;
		else
		    node->flag |= 1; /* mark signature valid */

		if( node->pkt->pkt.signature->sig_class != 0x20 ) {
		    if( !dups )
			dups = new_lid_table();
		    if( ins_lid_table_item( dups,
					node->pkt->pkt.signature->local_id, 0) )
			node->flag |= 4; /* mark as duplicate */
		}
	    }
	    if( DBG_TRUST )
		log_debug("trustdb: sig from %08lX.%lu: %s%s\n",
				(ulong)node->pkt->pkt.signature->keyid[1],
				node->pkt->pkt.signature->local_id,
				g10_errstr(rc), (node->flag&4)?"  (dup)":"" );
	}
    }
    if( dups )
	release_lid_table(dups);
    return 0;
}


/****************
 * If we do not have sigrecs for the given key, build them and write them
 * to the trustdb
 */
static int
build_sigrecs( ulong lid )
{
    TRUSTREC rec, krec, rec2;
   KBNODE keyblock = NULL;
   KBNODE node;
    int rc=0;
    int i, selfsig, revoked;
    ulong rnum, rnum2;
    ulong first_sigrec = 0;

    if( DBG_TRUST )
	log_debug("trustdb: build_sigrecs for LID %lu\n", lid );

    /* get the keyblock */
    if( (rc=tdbio_read_record( lid, &rec, RECTYPE_DIR )) ) {
	log_error( "build_sigrecs: can't read dir record %lu\n"), lid );
	goto leave;
    }
    if( (rc=tdbio_read_record( rec.r.dir.keylist, &krec, RECTYPE_KEY )) ) {
	log_error("build_sigrecs: can't read primary key record %lu\n"), lid);
	goto leave;
    }
    rc = get_keyblock_byfprint( &keyblock, krec.r.key.fingerprint,
					   krec.r.key.fingerprint_len );
    if( rc ) {
	log_error( "build_sigrecs: keyblock for %lu not found: %s\n",
						    lid, g10_errstr(rc) );
	goto leave;
    }

    /* check all key signatures */
    rc = check_sigs( keyblock, &selfsig, &revoked );
    if( rc ) {
	log_error(_("build_sigrecs: check_sigs failed\n") );
	goto leave;
    }
    if( !selfsig ) {
	log_error(_("build_sigrecs: self-signature missing\n") );
	tdbio_update_sigflag( lid, 2 );
	rc = G10ERR_BAD_CERT;
	goto leave;
    }
    if( revoked ) {
	log_info(_("build_sigrecs: key has been revoked\n") );
	tdbio_update_sigflag( lid, 3 );
    }
    else
	tdbio_update_sigflag( lid, 0 ); /* assume we have sigs */

    /* valid key signatures are now marked; we can now build the sigrecs */
    memset( &rec, 0, sizeof rec );
    rec.rectype = RECTYPE_SIG;
    i = 0;
    rnum = rnum2 = 0;
    for( node=keyblock; node; node = node->next ) {
	/* insert sigs which are not a selfsig nor a duplicate */
	if( (node->flag & 1) && !(node->flag & 4) ) {
	    assert( node->pkt->pkttype == PKT_SIGNATURE );
	    if( !node->pkt->pkt.signature->local_id )  {
		/* the next function should always succeed, because
		 * we have already checked the signature, and for this
		 * it was necessary to have the pubkey. The only reason
		 * this can fail are I/O errors of the trustdb or a
		 * remove operation on the pubkey database - which should
		 * not disturb us, because we have to change them anyway. */
		rc = set_signature_packets_local_id( node->pkt->pkt.signature );
		if( rc )
		    log_fatal(_("set_signature_packets_local_id failed: %s\n"),
							      g10_errstr(rc));
	    }
	    if( i == SIGS_PER_RECORD ) {
		/* write the record */
		rnum = tdbio_new_recnum();
		if( rnum2 ) { /* write the stored record */
		    rec2.r.sig.lid  = lid;
		    rec2.r.sig.next = rnum; /* the next record number */
		    rc = tdbio_write_record( rnum2, &rec2 );
		    if( rc ) {
			log_error(_("build_sigrecs: write_record failed\n") );
			goto leave;
		    }
		    if( !first_sigrec )
			first_sigrec = rnum2;
		}
		rec2 = rec;
		rnum2 = rnum;
		memset( &rec, 0, sizeof rec );
		rec.rectype = RECTYPE_SIG;
		i = 0;
	    }
	    rec.r.sig.sig[i].lid  = node->pkt->pkt.signature->local_id;
	    rec.r.sig.sig[i].flag = 0;
	    i++;
	}
    }
    if( i || rnum2 ) {
	/* write the record */
	rnum = tdbio_new_recnum();
	if( rnum2 ) { /* write the stored record */
	    rec2.r.sig.lid  = lid;
	    rec2.r.sig.next = rnum;
	    rc = tdbio_write_record( rnum2, &rec2 );
	    if( rc ) {
		log_error(_("build_sigrecs: write_record failed\n") );
		goto leave;
	    }
	    if( !first_sigrec )
		first_sigrec = rnum2;
	}
	if( i ) { /* write the pending record */
	    rec.r.sig.lid = lid;
	    rec.r.sig.next = 0;
	    rc = tdbio_write_record( rnum, &rec );
	    if( rc ) {
		log_error(_("build_sigrecs: write_record failed\n") );
		goto leave;
	    }
	    if( !first_sigrec )
		first_sigrec = rnum;
	}
    }
    if( first_sigrec ) { /* update the uid records */
	if( (rc =tdbio_read_record( pubkeyid, &rec, RECTYPE_DIR )) ) {
	    log_error(_("update_dir_record: read failed\n"));
	    goto leave;
	}
	rec.r.dir.sigrec = first_sigrec;
	if( (rc=tdbio_write_record( pubkeyid, &rec )) ) {
	    log_error(_("update_dir_record: write failed\n"));
	    goto leave;
	}
    }
    else
	tdbio_update_sigflag( lid, revoked? 3:1 ); /* no signatures */

  leave:
    release_kbnode( keyblock );
    if( DBG_TRUST )
	log_debug(_("trustdb: build_sigrecs: %s\n"), g10_errstr(rc) );
    return rc;
}

/****************
 * Make a list of trust paths
 */
static int
make_tsl( ulong pubkey_id, TRUST_SEG_LIST *ret_tslist )
{
    int i, rc;
    LOCAL_ID_INFO *lids = new_lid_table();
    TRUST_INFO stack[MAX_LIST_SIGS_DEPTH];
    TRUST_SEG_LIST tsl, tslist;
    int max_depth = 4;

    tslist = *ret_tslist = NULL;

    if( !qry_lid_table_flag( ultikey_table, pubkey_id, NULL ) ) {
	tslist = m_alloc( sizeof *tslist );
	tslist->nseg = 1;
	tslist->dup = 0;
	tslist->seg[0].lid = pubkey_id;
	tslist->seg[0].trust = 0;
	tslist->next = NULL;
	rc = 0;
    }
    else {
	stack[0].lid = pubkey_id;
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
 * check whether we already build signature records
 * Return: true if we have.
 */
static int
do_we_have_sigs( TRUSTREC *dr )
{
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
	return G10ERR_TRUSTDB
    }
    if( !dr->r.dir.uidlist ) {
	log_error("Ooops, no user ids\n");
	return G10ERR_TRUSTDB
    }

    /* verify the cache */

    /* do we have sigrecs */
    if( !do_we_have_sigs( dr ) ) { /* no sigrecs, so build them */
	rc = build_sigrecs( dr->lid );
	if( !rc ) /* and read again */
	    rc = tdbio_read_record( dr->lid, dr, RECTYPE_DIR );
    }


   !!!!WORK!!!!

    if( dr->r.dir.no_sigs == 3 )
	tflags |= TRUST_FLAG_REVOKED;

    if( !rc && !dr->r.dir.sigrec ) {
	/* See whether this is our own key */
	if( !qry_lid_table_flag( ultikey_table, pubkeyid, NULL ) )
	    *trustlevel = tflags | TRUST_ULTIMATE;
	return 0;
    }
    if( rc )
	return rc;  /* error while looking for sigrec or building sigrecs */

    /* fixme: take it from the cache if it is valid */

    /* Make a list of all possible trust-paths */
    rc = make_tsl( pubkeyid, &tslist );
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
    last_trust_web_key = pubkeyid;
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

    if( username ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	int rc;

	if( (rc = get_pubkey_byname( pk, username )) )
	    log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
	else if( (rc=tdbio_search_record( pk, &rec )) && rc != -1 )
	    log_error("problem finding '%s' in trustdb: %s\n",
						username, g10_errstr(rc));
	else if( rc == -1 )
	    log_error("user '%s' not in trustdb\n", username);
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
	    tdbio_dump_record( recnum, &rec, stdout );
    }
}

/****************
 * make a list of all owner trust value.
 */
void
list_ownertrust()
{
    TRUSTREC rec;
    ulong recnum;
    int i;
    byte *p;

    for(recnum=0; !tdbio_read_record( recnum, &rec, 0); recnum++ ) {
	if( rec.rectype == RECTYPE_KEY ) {
	    p = rec.r.key.fingerprint;
	    for(i=0; i < rec.r.key.fingerprint_len; i++, p++ )
		printf("%02X", *p );
	    printf(":%u:\n", (unsigned)rec.r.key.ownertrust );
	}
    }
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
    else if( (rc=tdbio_search_record( pk, &rec )) && rc != -1 )
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


    if( DBG_TRUST )
	log_info("check_trust() called.\n");
    keyid_from_pk( pk, keyid );

    /* get the pubkey record */
    if( pk->local_id ) {
	if( tdbio_read_record( pk->local_id, &rec, RECTYPE_DIR ) ) {
	    log_error("check_trust: read dir record failed\n");
	    return G10ERR_TRUSTDB;
	}
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=tdbio_search_dir_record( pk, &rec )) && rc != -1 ) {
	    log_error("check_trust: search dir record failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
	else if( rc == -1 ) { /* not found - insert */
	    rc = insert_trust_record( pk );
	    if( rc ) {
		log_error(_("key %08lX: insert trust record failed: %s\n"),
						keyid[1], g10_errstr(rc));
		goto leave;
	    }
	    log_info(_("key %08lX.%lu: inserted into trustdb\n"),
					  keyid[1], pk->local_id );
	}
    }
    cur_time = make_timestamp();
    if( pk->timestamp > cur_time ) {
	log_info(_("key %08lX.%lu: created in future "
		   "(time warp or clock problem)\n"),
					  keyid[1], pk->local_id );
	return G10ERR_TIME_CONFLICT;
    }

    if( pk->valid_days && add_days_to_timestamp(pk->timestamp,
						pk->valid_days) < cur_time ) {
	log_info(_("key %08lX.%lu: expired at %s\n"),
			keyid[1], pk->local_id,
		    strtimestamp( add_days_to_timestamp(pk->timestamp,
							pk->valid_days)));
	 trustlevel = TRUST_EXPIRED;
    }
    else {
	rc = do_check( &rec, &trustlevel );
	if( rc ) {
	    log_error(_("key %08lX.%lu: trust check failed: %s\n"),
			    keyid[1], pk->local_id, g10_errstr(rc));
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
	if( *lid != last_trust_web_key && last_trust_web_key )
	    log_bug("enum_trust_web: nyi\n"); /* <--- FIXME */
	c->tsl = last_trust_web_tslist;
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
    if( tdbio_read_record( rec.r.dir.keyrec, &rec, RECTYPE_KEY ) ) {
	log_error("get_ownertrust: read key record failed\n");
	return G10ERR_TRUSTDB;
    }
    if( r_otrust )
	*r_otrust = rec.r.key.ownertrust;
    return 0;
}

int
keyid_from_trustdb( ulong lid, u32 *keyid )
{
    TRUSTREC rec;

    if( tdbio_read_record( lid, &rec, RECTYPE_DIR ) ) {
	log_error("keyid_from_trustdb: read record failed\n");
	return G10ERR_TRUSTDB;
    }
    if( keyid ) {
	keyid[0] = rec.r.dir.keyid[0];
	keyid[1] = rec.r.dir.keyid[1];
    }
    return 0;
}


/****************
 * This function simply looks for the key in the trustdb
 * and sets PK->local_id.
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
	if( (rc=tdbio_search_record( pk, &rec )) && rc != -1 ) {
	    log_error("query_trust_record: search_record failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
    }
    return rc;
}


/****************
 * Insert a trust record into the TrustDB
 * This function fails if this record already exists.
 */
int
insert_trust_record( PKT_public_key *orig_pk )
{
    TRUSTREC dirrec, *rec;
    TRUSTREC **keylist_tail, *keylist;
    TRUSTREC **uidlist_tail, *uidlist;
    KBNODE keyblock = NULL;
    KBNODE node;
    u32 keyid[2];
    ulong knum, dnum;
    byte *fingerprint;
    size_t fingerlen;
    int rc = 0;


    if( orig_pk->local_id )
	log_bug("pk->local_id=%lu\n", (ulong)pk->local_id );

    fingerprint = fingerprint_from_pk( orig_pk, &fingerlen );

    /* fixme: assert that we do not have this record.
     * we can do this by searching for the primary keyid
     */

    /* get the keyblock which has the key */
    rc = get_keyblock_byfprint( &keyblock, fingerprint, fingerlen );
    if( rc ) { /* that should never happen */
	log_error( "insert_trust_record: keyblock not found: %s\n",
							  g10_errstr(rc) );
	return rc;
    }

    /* prepare dir record */
    memset( &dirrec, 0, sizeof dirrec );
    dirrec.rectype = RECTYPE_DIR;
    dirrec.r.dir.lid = tdbio_new_recnum();

    keylist = NULL;
    keylist_tail = &dirrec.r.dir.keylist;
    uidlist = NULL;
    uidlist_tail = &dirrec.r.dir.uidlist;
    /* loop over the keyblock */
    for( node=keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;

	    if( keylist && node->pkt->pkttype == PKT_PUBLIC_KEY )
		BUG();	/* more than one primary key */
	    fingerprint = fingerprint_from_pk( orig_pk, &fingerlen );
	    rec = m_alloc_clear( sizeof *rec );
	    rec->r.key.pubkey_algo = pk->pubkey_algo;
	    rec->r.key.fingerprint_len = fingerlen;
	    memcpy(rec->r.key.fingerprint, fingerprint, fingerlen );

	    if( keylist )
		keylist_tail = &keylist->next;
	    *keylist_tail = keylist = rec;
	}
	else if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;

	    rec = m_alloc_clear( sizeof *rec );
	    rmd160_hash_buffer( rec->r.uid.namehash, uid->name, uid->len );

	    if( uidlist )
		uidlist_tail = &uidlist->next;
	    *uidlist_tail = uidlist = rec;
	}
	if( node->pkt->pkttype == PKT_SIGNATURE
	    && ( (node->pkt->pkt.signature->sig_class&~3) == 0x10
		  || node->pkt->pkt.signature->sig_class == 0x20
		  || node->pkt->pkt.signature->sig_class == 0x30) ) {
	    int selfsig;
	    rc = check_key_signature( keyblock, node, &selfsig );
	    if( !rc ) {
		rc = set_signature_packets_local_id( node->pkt->pkt.signature );
		if( rc )
		    log_fatal("set_signature_packets_local_id failed: %s\n",
							      g10_errstr(rc));
		if( selfsig ) {
		    node->flag |= 2; /* mark signature valid */
		    *selfsig_okay = 1;
		}
		else if( node->pkt->pkt.signature->sig_class == 0x20 )
		    *revoked = 1;
		else
		    node->flag |= 1; /* mark signature valid */

		if( node->pkt->pkt.signature->sig_class != 0x20 ) {
		    if( !dups )
			dups = new_lid_table();
		    if( ins_lid_table_item( dups,
					node->pkt->pkt.signature->local_id, 0) )
			node->flag |= 4; /* mark as duplicate */
		}
	    }
	    if( DBG_TRUST )
		log_debug("trustdb: sig from %08lX.%lu: %s%s\n",
				(ulong)node->pkt->pkt.signature->keyid[1],
				node->pkt->pkt.signature->local_id,
				g10_errstr(rc), (node->flag&4)?"  (dup)":"" );
	}
    }










    knum = tdbio_new_recnum();
    /* build dir record */
    memset( &rec, 0, sizeof rec );
    rec.rectype = RECTYPE_DIR;
    rec.r.dir.local_id = dnum;
    rec.r.dir.keyid[0] = keyid[0];
    rec.r.dir.keyid[1] = keyid[1];
    rec.r.dir.keyrec   = knum;
    rec.r.dir.no_sigs = 0;
    /* and the key record */
    memset( &rec, 0, sizeof rec );
    rec.rectype = RECTYPE_KEY;
    rec.r.key.owner    = dnum;
    rec.r.key.keyid[0] = keyid[0];
    rec.r.key.keyid[1] = keyid[1];
    rec.r.key.pubkey_algo = pk->pubkey_algo;
    rec.r.key.fingerprint_len = fingerlen;
    memcpy(rec.r.key.fingerprint, fingerprint, fingerlen );
    rec.r.key.ownertrust = 0;
    if( tdbio_write_record( knum, &rec ) ) {
	log_error("wrinting key record failed\n");
	return G10ERR_TRUSTDB;
    }

    if( tdbio_write_record( dirrec.r.dir.lid, &dirrec ) ) {
	log_error("writing dir record failed\n");
	return G10ERR_TRUSTDB;
    }

    /* and store the LID */
    orig_pk->local_id = dnum;

    return 0;
}


int
update_ownertrust( ulong lid, unsigned new_trust )
{
    TRUSTREC rec;
    ulong recnum;

    if( tdbio_read_record( lid, &rec, RECTYPE_DIR ) ) {
	log_error("update_ownertrust: read dir failed\n");
	return G10ERR_TRUSTDB;
    }
    recnum = rec.r.dir.keyrec;
    if( tdbio_read_record( recnum, &rec, RECTYPE_KEY ) ) {
	log_error("update_ownertrust: read key failed\n");
	return G10ERR_TRUSTDB;
    }
    /* check keyid, fingerprint etc ? */

    rec.r.key.ownertrust = new_trust;
    if( tdbio_write_record( recnum, &rec ) ) {
	log_error("update_ownertrust: write failed\n");
	return G10ERR_TRUSTDB;
    }

    return 0;
}





