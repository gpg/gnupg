/* trustdb.c
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"
#include "options.h"
#include "packet.h"
#include "main.h"


#define TRUST_RECORD_LEN 40
#define SIGS_PER_RECORD ((TRUST_RECORD_LEN-10)/5)
#define MAX_LIST_SIGS_DEPTH  20


#define RECTYPE_VER  1
#define RECTYPE_DIR  2
#define RECTYPE_KEY  3
#define RECTYPE_CTL  4
#define RECTYPE_SIG  5


struct trust_record {
    int  rectype;
    union {
	struct {	    /* version record: */
	    byte version;   /* should be 1 */
	    ulong locked;    /* pid of process which holds a lock */
	    ulong created;   /* timestamp of trustdb creation  */
	    ulong modified;  /* timestamp of last modification */
	    ulong validated; /* timestamp of last validation   */
	    byte marginals_needed;
	    byte completes_needed;
	    byte max_cert_depth;
	} ver;
	struct {	    /* directory record */
	    ulong local_id;
	    u32  keyid[2];
	    ulong keyrec;   /* recno of public key record */
	    ulong ctlrec    /* recno of control record */
	    ulong sigrec;   /* recno of first signature record */
	    byte no_sigs;   /* does not have sigature and checked */
	} dir;
	struct {	    /* public key record */
	    ulong owner;
	    u32  keyid[2];
	    byte pubkey_algo;
	    byte fingerprint[20];
	    byte ownertrust;
	} key;
	struct {	    /* control record */
	    ulong owner;
	    byte blockhash[20];
	    byte trustlevel;   /* calculated trustlevel */
	} ctl;
	struct {	    /* signature record */
	    ulong owner;  /* local_id of record owner (pubkey record) */
	    ulong chain;  /* offset of next record or NULL for last one */
	    struct {
		ulong  local_id; /* of pubkey record of signator (0=unused) */
		byte flag;     /* reserved */
	    } sig[SIGS_PER_RECORD];
	} sig;
    } r;
};
typedef struct trust_record TRUSTREC;

typedef struct {
    ulong     local_id;    /* localid of the pubkey */
    ulong     sig_id;	   /* returned signature id */
    unsigned  sig_flag;    /* returned signature record flag */
    struct {		   /* internal data */
	int eof;
	TRUSTREC rec;
	int index;
    } ctl;
} SIGREC_CONTEXT;

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


static void create_db( const char *fname );
static void open_db(void);
static void dump_record( ulong rnum, TRUSTREC *rec, FILE *fp );
static int  read_record( ulong recnum, TRUSTREC *rec );
static int  write_record( ulong recnum, TRUSTREC *rec );
static ulong new_recnum(void);
static int search_record( PKT_public_cert *pkc, TRUSTREC *rec );
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
static int build_sigrecs( ulong pubkeyid, int kludge );
static int propagate_trust( TRUST_SEG_LIST tslist );
static int do_check( ulong pubkeyid, unsigned *trustlevel );

static int update_no_sigs( ulong lid, int no_sigs );

static char *db_name;
static int  db_fd = -1;
/* a table used to keep track of ultimately trusted keys
 * which are the ones from our secrings */
static LOCAL_ID_INFO *ultikey_table;

static ulong last_trust_web_key;
static TRUST_SEG_LIST last_trust_web_tslist;

#define buftoulong( p )  ((*(byte*)(p) << 24) | (*((byte*)(p)+1)<< 16) | \
		       (*((byte*)(p)+2) << 8) | (*((byte*)(p)+3)))
#define buftoushort( p )  ((*((byte*)(p)) << 8) | (*((byte*)(p)+1)))
#define ulongtobuf( p, a ) do { 			  \
			    ((byte*)p)[0] = a >> 24;	\
			    ((byte*)p)[1] = a >> 16;	\
			    ((byte*)p)[2] = a >>  8;	\
			    ((byte*)p)[3] = a	   ;	\
			} while(0)
#define ushorttobuf( p, a ) do {			   \
			    ((byte*)p)[0] = a >>  8;	\
			    ((byte*)p)[1] = a	   ;	\
			} while(0)
#define buftou32( p)	buftoulong( (p) )
#define u32tobuf( p, a) ulongtobuf( (p), (a) )


/**************************************************
 ************** read and write helpers ************
 **************************************************/

static void
fwrite_8(FILE *fp, byte a)
{
    if( putc( a & 0xff, fp ) == EOF )
	log_fatal("error writing byte to trustdb: %s\n", strerror(errno) );
}


static void
fwrite_32( FILE*fp, ulong a)
{
    putc( (a>>24) & 0xff, fp );
    putc( (a>>16) & 0xff, fp );
    putc( (a>> 8) & 0xff, fp );
    if( putc( a & 0xff, fp ) == EOF )
	log_fatal("error writing ulong to trustdb: %s\n", strerror(errno) );
}

static void
fwrite_zeros( FILE *fp, size_t n)
{
    while( n-- )
	if( putc( 0, fp ) == EOF )
	    log_fatal("error writing zeros to trustdb: %s\n", strerror(errno) );
}


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
 * fixme: maybe its a good idea to take items from an unused item list.
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


/**************************************************
 ************** read and write stuff **************
 **************************************************/


/****************
 * Create a new trustdb
 */
static void
create_db( const char *fname )
{
    FILE *fp;

    fp =fopen( fname, "w" );
    if( !fp )
	log_fatal("can't create %s: %s\n", fname, strerror(errno) );
    fwrite_8( fp, 1 );
    fwrite_8( fp, 'g' );
    fwrite_8( fp, '1' );
    fwrite_8( fp, '0' );
    fwrite_8( fp, 1 );	/* version */
    fwrite_zeros( fp, 3 ); /* reserved */
    fwrite_32( fp, 0 ); /* not locked */
    fwrite_32( fp, make_timestamp() ); /* created */
    fwrite_32( fp, 0 ); /* not yet modified */
    fwrite_32( fp, 0 ); /* not yet validated*/
    fwrite_32( fp, 0 ); /* reserved */
    fwrite_8( fp, 3 );	/* marginals needed */
    fwrite_8( fp, 1 );	/* completes needed */
    fwrite_8( fp, 4 );	/* max_cet_depth */
    fwrite_zeros( fp, 9 ); /* filler */
    fclose(fp);
}

static void
open_db()
{
    TRUSTREC rec;
    assert( db_fd == -1 );

    db_fd = open( db_name, O_RDWR );
    if( db_fd == -1 )
	log_fatal("can't open %s: %s\n", db_name, strerror(errno) );
    if( read_record( 0, &rec ) )
	log_fatal("TrustDB %s is invalid\n", db_name );
    /* fixme: check ->locked and other stuff */
}


static void
dump_record( ulong rnum, TRUSTREC *rec, FILE *fp  )
{
    int i, any;

    fprintf(fp, "trust record %lu, type=", rnum );

    switch( rec->rectype ) {
      case 0: fprintf(fp, "free\n");
	break;
      case RECTYPE_VER: fprintf(fp, "version\n");
	break;
      case RECTYPE_DIR:
	fprintf(fp, "dir keyid=%08lx, key=%lu, ctl=%lu, sig=%lu%s\n",
		    rec->r.dir.keyid[1],
		    rec->r.dir.keyrec, rec->r.dir.ctlrec, rec->r.dir.sigrec,
		    rec->r.dir.no_sigs?"  (inv sigs)":"");
	break;
      case RECTYPE_KEY: fprintf(fp, "key keyid=%08lx, own=%lu, ownertrust=%02x\n",
		   rec->r.key.keyid[1],
		   rec->r.key.owner, rec->r.key.ownertrust );
	break;
      case RECTYPE_CTL: fprintf(fp, "ctl\n");
	break;
      case RECTYPE_SIG:
	fprintf(fp, "sigrec, owner=%lu, chain=%lu%s\n",
			 rec->r.sig.owner, rec->r.sigrec.chain,
			 rec->rectype == 4?"":" (extend)");
	for(i=any=0; i < SIGS_PER_RECORD; i++ ) {
	    if( rec->r.sigrec.sig[i].local_id ) {
		if( !any ) {
		    putc('\t', fp);
		    any++;
		}
		fprintf(fp, "  %lu:%02x", rec->r.sigrec.sig[i].local_id,
					      rec->r.sigrec.sig[i].flag );
	    }
	}
	if( any )
	    putc('\n', fp);
	break;
      default:
	fprintf(fp, "%d (unknown)\n", rec->rectype );
	break;
    }
}

/****************
 * read the record with number recnum
 * returns: -1 on error, 0 on success
 */
static int
read_record( ulong recnum, TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int n, i;

    if( db_fd == -1 )
	open_db();
    if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	log_error("trustdb: lseek failed: %s\n", strerror(errno) );
	return G10ERR_READ_FILE;
    }
    n = read( db_fd, buf, TRUST_RECORD_LEN);
    if( !n ) {
	return -1; /* eof */
    }
    else if( n != TRUST_RECORD_LEN ) {
	log_error("trustdb: read failed (n=%d): %s\n", n, strerror(errno) );
	return G10ERR_READ_FILE;
    }
    p = buf;
    rec->rectype = *p++;
    p++;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case RECTYPE_VER: /* version record */
	if( memcmp(buf+1, "g10", 3 ) {
	    log_error("%s: not a trustdb file\n", db_name );
	    rc = G10ERR_TRUSTDB;
	}
	p += 2; /* skip magic */
	rec->r.ver.version  = *p++;
	memcpy( rec->r.ver.reserved, p, 3); p += 3;
	rec->r.ver.locked   = buftoulong(p); p += 4;
	rec->r.ver.created  = buftoulong(p); p += 4;
	rec->r.ver.modified = buftoulong(p); p += 4;
	rec->r.ver.validated= buftoulong(p); p += 4;
	rec->r.ver.local_id_counter = buftoulong(p); p += 4;
	rec->r.ver.marginals_needed = *p++;
	rec->r.ver.completes_needed = *p++;
	rec->r.ver.max_cert_depth = *p++;
	if( recnum ) {
	    log_error("%s: version record with recnum %lu\n",
						    db_name, (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	if( rec->r.ver.version != 1 ) {
	    log_error("%s: invalid file version %d\n",
				       db_name, rec->r.version.version );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_DIR:   /*directory record */
	rec->r.dir.local_id = buftoulong(p); p += 4;
	rec->r.dir.keyid[0] = buftou32(p); p += 4;
	rec->r.dir.keyid[1] = buftou32(p); p += 4;
	rec->r.dir.keyrec   = buftoulong(p); p += 4;
	rec->r.dir.ctlrec   = buftoulong(p); p += 4;
	rec->r.dir.sigrec   = buftoulong(p); p += 4;
	rec->r.dir.no_sigs = *p++;
	if( rec->r.dir.local_id != recnum ) {
	    log_error("%s: dir local_id != recnum (%lu,%lu)\n",
					db_name,
					(ulong)rec->r.dir.local_id,
					(ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case RECTYPE_KEY:   /* public key record */
	rec->r.key.owner    = buftoulong(p); p += 4;
	rec->r.dir.keyid[0] = buftou32(p); p += 4;
	rec->r.dir.keyid[1] = buftou32(p); p += 4;
	rec->r.key.pubkey_algo = *p++; p++;
	memcpy( rec->r.pubkey.fingerprint, p, 20); p += 20;
	rec->r.pubkey.ownertrust = *p++;
	break;
      case RECTYPE_CTL:   /* control record */
	rec->r.ctl.owner    = buftoulong(p); p += 4;
	memcpy(rec->r.ctl.blockhash, p, 20); p += 20;
	rec->r.ctl.trustlevel = *p++;
	break;
      case RECTYPE_SIG:
	rec->r.sig.owner   = buftoulong(p); p += 4;
	rec->r.sig.chain   = buftoulong(p); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    rec->r.sig.sig[i].local_id = buftoulong(p); p += 4;
	    rec->r.sig.sig[i].flag = *p++;
	}
	break;
      default:
	log_error("%s: invalid record type %d at recnum %lu\n",
					db_name, rec->rectype, (ulong)recnum );
	rc = G10ERR_TRUSTDB;
	break;
    }

    return rc;
}

/****************
 * Write the record at RECNUM
 */
static int
write_record( ulong recnum, TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int i, n;

    if( db_fd == -1 )
	open_db();

    memset(buf, 0, TRUST_RECORD_LEN);
    p = buf;
    *p++ = rec->rectype;
    *p++ = rec->reserved;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case 1: /* version record */
	BUG();
	break;

      case RECTYPE_DIR:   /*directory record */
	ulongtobuf(p, rec->r.dir.local_id); p += 4;
	u32tobuf(p, rec->r.key.keyid[0]); p += 4;
	u32tobuf(p, rec->r.key.keyid[1]); p += 4;
	ulongtobuf(p, rec->r.dir.keyrec); p += 4;
	ulongtobuf(p, rec->r.dir.ctlrec); p += 4;
	ulongtobuf(p, rec->r.dir.sigrec); p += 4;
	*p++ = rec->r.dir.no_sigs;
	assert( rec->r.dir.local_id == recnum );
	break;

      case RECTYPE_KEY:
	ulongtobuf(p, rec->r.key.owner); p += 4;
	u32tobuf(p, rec->r.key.keyid[0]); p += 4;
	u32tobuf(p, rec->r.key.keyid[1]); p += 4;
	*p++ = rec->r.pubkey.pubkey_algo; p++;
	memcpy( p, rec->r.key.fingerprint, 20); p += 20;
	*p++ = rec->r.pubkey.ownertrust;
	break;

      case RECTYPE_CTL:   /* control record */
	ulongtobuf(p, rec->r.ctl.owner); p += 4;
	memcpy(p, rec->r.ctl.blockhash, 20); p += 20;
	*p++ = rec->r.ctl.trustlevel;
	break;

      case RECTYPE_SIG:
	ulongtobuf(p, rec->r.sig.owner); p += 4;
	ulongtobuf(p, rec->r.sig.chain); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    ulongtobuf(p, rec->r.sig.sig[i].local_id); p += 4;
	    *p++ = rec->r.sig.sig[i].flag;
	}
	break;
      default:
	BUG();
    }

    if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	log_error("trustdb: lseek failed: %s\n", strerror(errno) );
	return G10ERR_WRITE_FILE;
    }
    n = write( db_fd, buf, TRUST_RECORD_LEN);
    if( n != TRUST_RECORD_LEN ) {
	log_error("trustdb: write failed (n=%d): %s\n", n, strerror(errno) );
	return G10ERR_WRITE_FILE;
    }

    return rc;
}


/****************
 * create a new record and return its record number
 */
static ulong
new_recnum()
{
    off_t offset;
    ulong recnum;
    TRUSTREC rec;
    int rc;

    /* fixme: look for unused records */
    offset = lseek( db_fd, 0, SEEK_END );
    if( offset == -1 )
	log_fatal("trustdb: lseek to end failed: %s\n", strerror(errno) );
    recnum = offset / TRUST_RECORD_LEN;
    assert(recnum); /* this is will never be the first record */

    /* we must write a record, so that the next call to this function
     * returns another recnum */
    memset( &rec, 0, sizeof rec );
    rec.rectype = 0; /* free record */
    rc = write_record(recnum, &rec );
    if( rc )
	log_fatal("%s: failed to append a record: %s\n",
					    db_name, g10_errstr(rc));
    return recnum ;
}

/****************
 * Search the trustdb for a key which matches PKC and return the dir record
 * The local_id of PKC is set to the correct value
 *
 * Note: To increase performance, we could use a index search here.
 */
static int
search_record( PKT_public_cert *pkc, TRUSTREC *rec )
{
    ulong recnum;
    u32 keyid[2];
    byte *fingerprint;
    size_t fingerlen;
    int rc;

    keyid_from_pkc( pkc, keyid );
    fingerprint = fingerprint_from_pkc( pkc, &fingerlen );
    assert( fingerlen == 20 || fingerlen == 16 );

    for(recnum=1; !(rc=read_record( recnum, rec)); recnum++ ) {
	if( rec->rectype != RECTYPE_DIR )
	    continue;
	if( rec->r.dir.keyid[0] == keyid[0]
	    && rec->r.dir.keyid[1] == keyid[1]){
	    TRUSTREC keyrec;

	    if( read_record( rec->r.dir.keyrec, keyrec ) ) {
		log_error("%lu: ooops: invalid dir record\n", recnum );
		break;
	    }
	    if( keyrec.key.pubkey_algo == pkc->pubkey_algo
		&& !memcmp(keyrec.r.key.fingerprint, fingerprint, fingerlen) ){
		if( pkc->local_id && pkc->local_id != recnum )
		    log_error("%s: found record, but local_id from mem does "
			       "not match recnum (%lu,%lu)\n", db_name,
				     (ulong)pkc->local_id, (ulong)recnum );
		pkc->local_id = recnum;
		return 0;
	    }
	}
    }
    if( rc != -1 )
	log_error("%s: search_db failed: %s\n",db_name, g10_errstr(rc) );
    return rc;
}


/****************
 * If we do not have a local_id in a signature packet, find the owner of
 * the signature packet in our trustdb or insert him into the trustdb
 */
static int
set_signature_packets_local_id( PKT_signature *sig )
{
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
    TRUSTREC rec;
    int rc;

    rc = get_pubkey( pkc, sig->keyid );
    if( rc)
	goto leave;
    if( !pkc->local_id ) {
	rc = search_record( pkc, &rec );
	if( rc == -1 )
	    rc = insert_trust_record( pkc );
	if( rc )
	    goto leave;
	/* fixme: we should propagate the local_id to all copies of the PKC */
    }
    sig->local_id = pkc->local_id;

  leave:
    free_public_cert( pkc );
    return rc;
}



static int
keyid_from_local_id( ulong lid, u32 *keyid )
{
    TRUSTREC rec;
    int rc;

    rc = read_record( lid, &rec );
    if( rc ) {
	log_error("error reading record with local_id %lu: %s\n",
						    lid, g10_errstr(rc));
	return G10ERR_TRUSTDB;
    }
    if( rec.rectype != RECTYPE_DIR ) {
	log_error("record with local_id %lu is not a dir record\n", lid);
	return G10ERR_TRUSTDB;
    }
    keyid[0] = rec.r.dir.keyid[0];
    keyid[1] = rec.r.dir.keyid[1];
    return 0;
}

/****************
 * Walk throug the signatures of a public key.
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
!!!!!!FIXME!!!!!!!

    int rc=0;
    TRUSTREC *r;
    ulong rnum;

    if( c->ctl.eof )
	return -1;
    r = &c->ctl.rec;
    if( !r->rectype ) { /* this is the first call */

	rc = scan_record( c->pubkey_id, r, 4, &rnum );
	if( rc == -1 && create ) { /* no signature records */
	    rc = build_sigrecs( c->pubkey_id, 1 );
	    if( rc ) {
		if( rc != -1 )
		    log_info("%lu: error building sigs on the fly: %s\n",
			   c->pubkey_id, g10_errstr(rc) );
		rc = -1;
	    }
	    else /* once more */
		rc = scan_record( c->pubkey_id, r, 4, &rnum );
	}
	if( rc == -1 ) { /* no signature records */
	    c->ctl.eof = 1;
	    return -1;	/* return eof */
	}
	if( rc ) {
	    log_error("scan_record(sigrec) failed: %s\n", g10_errstr(rc));
	    c->ctl.eof = 1;
	    return rc;
	}
	c->ctl.index = 0;
    }
    /* enter loop to skip deleted sigs */
    do {
	if( c->ctl.index >= SIGS_PER_RECORD ) {
	    /* read the next record */
	    if( !r->r.sigrec.chain ) {
		c->ctl.eof = 1;
		return -1;  /* return eof */
	    }
	    rnum = r->r.sigrec.chain;
	    rc = read_record( rnum, r );
	    if( rc ) {
		log_error("error reading next sigrec: %s\n", g10_errstr(rc));
		c->ctl.eof = 1;
		return rc;
	    }
	    if( r->r.sigrec.owner != c->pubkey_id ) {
		log_error("chained sigrec %lu has a wrong owner\n", rnum );
		c->ctl.eof = 1;
		return G10ERR_TRUSTDB;
	    }
	    c->ctl.index = 0;
	}
    } while( !r->r.sigrec.sig[c->ctl.index++].local_id );
    c->sig_id = r->r.sigrec.sig[c->ctl.index-1].local_id;
    c->sig_flag = r->r.sigrec.sig[c->ctl.index-1].flag;
    return 0;
}




/***********************************************
 *************	Trust  stuff  ******************
 ***********************************************/


/****************
 * Verify, that all our public keys are in the trustDB.
 */
static int
verify_own_certs()
{
    int rc;
    void *enum_context = NULL;
    PKT_secret_cert *skc = m_alloc_clear( sizeof *skc );
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
    u32 keyid[2];

    while( !(rc=enum_secret_keys( &enum_context, skc) ) ) {
	/* fixed: to be sure that it is a secret key of our own,
	 *	  we should check it, but this needs a passphrase
	 *	  for every key and this boring for the user.
	 *	  Solution:  Sign the secring and the trustring
	 *		     and verify this signature during
	 *		     startup
	 */

	keyid_from_skc( skc, keyid );

	if( DBG_TRUST )
	    log_debug("checking secret key %08lX\n", (ulong)keyid[1] );

	/* look wether we can access the public key of this secret key */
	rc = get_pubkey( pkc, keyid );
	if( rc ) {
	    log_error("keyid %08lX: secret key without public key\n",
							    (ulong)keyid[1] );
	    goto leave;
	}
	if( cmp_public_secret_cert( pkc, skc ) ) {
	    log_error("keyid %08lX: secret and public key don't match\n",
							    (ulong)keyid[1] );
	    rc = G10ERR_GENERAL;
	    goto leave;
	}

	/* make sure that the pubkey is in the trustdb */
	rc = query_trust_record( pkc );
	if( rc == -1 ) { /* put it into the trustdb */
	    rc = insert_trust_record( pkc );
	    if( rc ) {
		log_error("keyid %08lX: can't put it into the trustdb\n",
							    (ulong)keyid[1] );
		goto leave;
	    }
	}
	else if( rc ) {
	    log_error("keyid %08lX: query record failed\n", (ulong)keyid[1] );
	    goto leave;

	}

	if( DBG_TRUST )
	    log_debug("putting %08lX(%lu) into ultikey_table\n",
				    (ulong)keyid[1], pkc->local_id );
	if( ins_lid_table_item( ultikey_table, pkc->local_id, 0 ) )
	    log_error("keyid %08lX: already in ultikey_table\n",
							(ulong)keyid[1]);


	release_secret_cert_parts( skc );
	release_public_cert_parts( pkc );
    }
    if( rc != -1 )
	log_error("enum_secret_keys failed: %s\n", g10_errstr(rc) );
    else
	rc = 0;

  leave:
    free_secret_cert( skc );
    free_public_cert( pkc );
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
    print_string( stdout, p, n );
    putchar('\"');
    putchar('\n');
    m_free(p);
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
	    printf("%6u: %*s????????(%lu:%02x)\n", *lineno, depth*4, "",
						   sx.sig_id, sx.sig_flag );
	    ++*lineno;
	}
	else {
	    printf("%6u: %*s%08lX(%lu:%02x) ", *lineno, depth*4, "",
			      (ulong)keyid[1], sx.sig_id, sx.sig_flag );
	    /* check wether we already checked this pubkey */
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
    printf("Signatures of %08lX(%lu) ", (ulong)keyid[1], pubkey_id );
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
	/*printf("%2lu/%d: to deeply nested\n", stack[depth-1], depth);*/
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
 * FIXME: what shall we do if we have duplicate signatures were only
 *	  some of them are bad?
 */
static int
check_sigs( KBNODE keyblock, int *selfsig_okay )
{
    KBNODE kbctx;
    KBNODE node;
    int rc;
    LOCAL_ID_INFO *dups = NULL;

    *selfsig_okay = 0;
    for( kbctx=NULL; (node=walk_kbtree( keyblock, &kbctx)) ; ) {
	if( node->pkt->pkttype == PKT_SIGNATURE
	    && (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
	    int selfsig;
	    rc = check_key_signature( keyblock, node, &selfsig );
	    if( !rc ) {
		if( selfsig ) {
		    node->flag |= 2; /* mark signature valid */
		    *selfsig_okay = 1;
		}
		else
		    node->flag |= 1; /* mark signature valid */
		if( !dups )
		    dups = new_lid_table();
		if( ins_lid_table_item( dups,
				    node->pkt->pkt.signature->local_id, 0) )
		    node->flag |= 4; /* mark as duplicate */
	    }
	    if( DBG_TRUST )
		log_debug("trustdb: sig from %08lX: %s\n",
				(ulong)node->pkt->pkt.signature->keyid[1],
						    g10_errstr(rc) );
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
build_sigrecs( ulong pubkeyid, int kludge )
{
    TRUSTREC rec, krec, rec2;
    PUBKEY_FIND_INFO finfo=NULL;
    KBPOS kbpos;
    KBNODE keyblock = NULL;
    KBNODE kbctx;
    KBNODE node;
    int rc=0;
    int i, selfsig;
    ulong rnum, rnum2;

    if( DBG_TRUST )
	log_debug("trustdb: build_sigrecs for pubkey %lu\n", (ulong)pubkeyid );

    /* get the keyblock */
    if( (rc=read_record( pubkeyid, &rec )) ) {
	log_error("%lu: build_sigrecs: can't read dir record\n", pubkeyid );
	goto leave;
    }
    if( kludge && rec.r.dir.no_sigs ) {
	rc = -1;
	goto leave;
    }
    finfo = m_alloc_clear( sizeof *finfo );
    finfo->keyid[0] = rec.r.dir.keyid[0];
    finfo->keyid[1] = rec.r.dir.keyid[1];
    if( (rc=read_record( rec.r.dir.keyrec, &krec )) ) {
	log_error("%lu: build_sigrecs: can't read key record\n", pubkeyid);
	goto leave;
    }
    finfo->pubkey_algo = krec.r.key.pubkey_algo;
    memcpy( finfo->fingerprint, krec.r.key.fingerprint, 20);
    rc = find_keyblock( finfo, &kbpos );
    if( rc ) {
	log_error("build_sigrecs: find_keyblock failed\n" );
	goto leave;
    }
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("build_sigrecs: read_keyblock failed\n" );
	goto leave;
    }
    /* check all key signatures */
    rc = check_sigs( keyblock, &selfsig );
    if( rc ) {
	log_error("build_sigrecs: check_sigs failed\n" );
	goto leave;
    }
    if( !selfsig ) {
	log_error("build_sigrecs: self-certificate missing\n" );
	update_no_sigs( pubkeyid, 1 );
	rc = G10ERR_BAD_CERT;
	goto leave;
    }

    update_no_sigs( pubkeyid, 0 );
    /* valid key signatures are now marked; we can now build the
     * sigrecs */
    memset( &rec, 0, sizeof rec );
    rec.rectype = RECTYPE_SIG;
    i = 0;
    rnum = rnum2 = 0;
    for( kbctx=NULL; (node=walk_kbtree( keyblock, &kbctx)) ; ) {
	/* insert sigs which are not a selfsig nor a duplicate */
	if( (node->flag & 1) && !(node->flag & 4) ) {
	    assert( node->pkt->pkttype == PKT_SIGNATURE );
	    if( !node->pkt->pkt.signature->local_id )  {
		/* the next function should always succeed, because
		 * we have already checked the signature, and for this
		 * it was necessary to have the pubkey. The only reason
		 * this can fail are I/o errors of the trustdb or a
		 * remove operation on the pubkey database - which should
		 * not disturb us, because we have to chace them anyway. */
		rc = set_signature_packets_local_id( node->pkt->pkt.signature );
		if( rc )
		    log_fatal("set_signature_packets_local_id failed: %s\n",
							      g10_errstr(rc));
	    }
	    if( i == SIGS_PER_RECORD ) {
		/* write the record */
		rnum = new_recnum();
		if( rnum2 ) { /* write the stored record */
		    rec2.r.sig.owner = pubkeyid;
		    rec2.r.sig.chain = rnum; /* the next record number */
		    rc = write_record( rnum2, &rec2 );
		    if( rc ) {
			log_error("build_sigrecs: write_record failed\n" );
			goto leave;
		    }
		}
		rec2 = rec;
		rnum2 = rnum;
		memset( &rec, 0, sizeof rec );
		rec.rectype = RECTYPE_SIG;
		i = 0;
	    }
	    rec.r.sig.sig[i].local_id = node->pkt->pkt.signature->local_id;
	    rec.r.sig.sig[i].flag = 0;
	    i++;
	}
    }
    if( i || rnum2 ) {
	/* write the record */
	rnum = new_recnum();
	if( rnum2 ) { /* write the stored record */
	    rec2.r.sig.owner = pubkeyid;
	    rec2.r.sig.chain = rnum;
	    rc = write_record( rnum2, &rec2 );
	    if( rc ) {
		log_error("build_sigrecs: write_record failed\n" );
		goto leave;
	    }
	}
	if( i ) { /* write the pending record */
	    rec.r.sig.owner = pubkeyid;
	    rec.r.sig.chain = 0;
	    rc = write_record( rnum, &rec );
	    if( rc ) {
		log_error("build_sigrecs: write_record failed\n" );
		goto leave;
	    }
	}
    }

  leave:
    m_free( finfo );
    release_kbnode( keyblock );
    if( DBG_TRUST )
	log_debug("trustdb: build_sigrecs: %s\n", g10_errstr(rc) );
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
 * FIXME: We have to do more thinks here. e.g. we should never increase
 *	  the trust value.
 *
 * Do not do it for duplicates.
 */
static int
propagate_trust( TRUST_SEG_LIST tslist )
{
    int i, rc;
    unsigned trust;
    TRUST_SEG_LIST tsl;

    for(tsl = tslist; tsl; tsl = tsl->next ) {
	if( tsl->dup )
	    continue;
	assert( tsl->nseg );
	/* the last segment is always a ultimately trusted one, so we can
	 * assign a fully trust to the next one */
	i = tsl->nseg-1;
	tsl->seg[i].trust = TRUST_ULTIMATE;
	trust = TRUST_FULLY;
	for(i-- ; i >= 0; i-- ) {
	    tsl->seg[i].trust = trust;
	    if( i > 0 ) {
		/* get the trust of this pubkey */
		rc = get_ownertrust( tsl->seg[i].lid, &trust );
		if( rc )
		    return rc;
	    }
	}
    }
    return 0;
}


/****************
 * we have the pubkey record but nothing more is known
 */
static int
do_check( ulong pubkeyid, unsigned *trustlevel )
{
    int i, rc=0;
    ulong rnum;
    TRUSTREC rec;
    TRUST_SEG_LIST tsl, tsl2, tslist;
    int marginal, fully;
    int fully_needed = opt.completes_needed;
    int marginal_needed = opt.marginals_needed;

    assert( fully_needed > 0 && marginal_needed > 1 );


    *trustlevel = TRUST_UNDEFINED;

    /* verify the cache */

    /* do we have sigrecs */
    rc = scan_record( pubkeyid, &rec, 4, &rnum );
    if( rc == -1 ) { /* no sigrecs, so build them */
	rc = build_sigrecs( pubkeyid, 1 );
	if( !rc ) /* and read again */
	    rc = scan_record( pubkeyid, &rec, 4, &rnum );
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

	log_debug("tslist segs:" );
	for(i=0; i < tsl->nseg; i++ )
	    fprintf(stderr, "  %lu/%02x", tsl->seg[i].lid, tsl->seg[i].trust );
	putc('\n',stderr);
    }

    /* and look wether there is a trusted path.
     * We only have to look at the first segment, because
     * propagate_trust has investigated all other segments */
    marginal = fully = 0;
    for(tsl = tslist; tsl; tsl = tsl->next ) {
	if( tsl->dup )
	    continue;
	if( tsl->seg[0].trust == TRUST_ULTIMATE ) {
	    *trustlevel = TRUST_ULTIMATE; /* our own key */
	    break;
	}
	if( tsl->seg[0].trust == TRUST_FULLY ) {
	    marginal++;
	    fully++;
	}
	else if( tsl->seg[0].trust == TRUST_MARGINAL )
	    marginal++;

	if( fully >= fully_needed ) {
	    *trustlevel = TRUST_FULLY;
	    break;
	}
    }
    if( !tsl && marginal >= marginal_needed )
	*trustlevel = TRUST_MARGINAL;

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


/*********************************************************
 ****************  API Interface  ************************
 *********************************************************/

/****************
 * Perform some checks over the trustdb
 *  level 0: only open the db
 *	  1: used for initial program startup
 */
int
init_trustdb( int level )
{
    int rc=0;

    if( !ultikey_table )
	ultikey_table = new_lid_table();

    if( !level || level==1 ) {
	char *fname = make_filename("~/.g10", "trustdb.g10", NULL );
	if( access( fname, R_OK ) ) {
	    if( errno != ENOENT ) {
		log_error("can't access %s: %s\n", fname, strerror(errno) );
		m_free(fname);
		return G10ERR_TRUSTDB;
	    }
	    if( level )
		create_db( fname );
	}
	m_free(db_name);
	db_name = fname;

	if( !level )
	    return 0;

	/* we can verify a signature about our local data (secring and trustdb)
	 * in ~/.g10/ here */
	rc = verify_private_data();
	if( !rc ) {
	    /* verify, that our own certificates are in the trustDB
	     * or move them to the trustdb. */
	    rc = verify_own_certs();

	    /* should we check wether there is no other ultimately trusted
	     * key in the database? */

	}
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
	PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
	int rc;

	if( (rc = get_pubkey_byname( pkc, username )) )
	    log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
	else if( (rc=search_record( pkc, &rec )) && rc != -1 )
	    log_error("problem finding '%s' in trustdb: %s\n",
						username, g10_errstr(rc));
	else if( rc == -1 )
	    log_error("user '%s' not in trustdb\n", username);
	else if( (rc = list_sigs( pkc->local_id )) )
	    log_error("user '%s' list problem: %s\n", username, g10_errstr(rc));
	free_public_cert( pkc );
    }
    else {
	ulong recnum;
	int i;

	printf("TrustDB: %s\n", db_name );
	for(i=9+strlen(db_name); i > 0; i-- )
	    putchar('-');
	putchar('\n');
	for(recnum=0; !read_record( recnum, &rec); recnum++ )
	    dump_record( recnum, &rec, stdout );
    }
}

void
list_trust_path( int max_depth, const char *username )
{
    int rc;
    int wipe=0;
    int i;
    TRUSTREC rec;
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );

    if( max_depth < 0 ) {
	wipe = 1;
	max_depth = -max_depth;
    }

    if( (rc = get_pubkey_byname( pkc, username )) )
	log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
    else if( (rc=search_record( pkc, &rec )) && rc != -1 )
	log_error("problem finding '%s' in trustdb: %s\n",
					    username, g10_errstr(rc));
    else if( rc == -1 ) {
	log_info("user '%s' not in trustdb - inserting\n", username);
	rc = insert_trust_record( pkc );
	if( rc )
	    log_error("failed to put '%s' into trustdb: %s\n", username, g10_errstr(rc));
	else {
	    assert( pkc->local_id );
	}
    }

    if( !rc ) {
	TRUST_SEG_LIST tsl, tslist = NULL;

	if( !qry_lid_table_flag( ultikey_table, pkc->local_id, NULL ) ) {
	    tslist = m_alloc( sizeof *tslist );
	    tslist->nseg = 1;
	    tslist->dup = 0;
	    tslist->seg[0].lid = pkc->local_id;
	    tslist->seg[0].trust = 0;
	    tslist->next = NULL;
	    rc = 0;
	}
	else {
	    LOCAL_ID_INFO *lids = new_lid_table();
	    TRUST_INFO stack[MAX_LIST_SIGS_DEPTH];

	    stack[0].lid = pkc->local_id;
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
	}	     cvs checkout -h
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
	    for(i=0; i < tsl->nseg; i++ )
		printf("  %lu/%02x", tsl->seg[i].lid, tsl->seg[i].trust );
	    putchar('\n');
	}
    }

    free_public_cert( pkc );
}


/****************
 * Get the trustlevel for this PKC.
 * Note: This does not ask any questions
 * Returns: 0 okay of an errorcode
 *
 * It operates this way:
 *  locate the pkc in the trustdb
 *	found:
 *	    Do we have a valid cache record for it?
 *		yes: return trustlevel from cache
 *		no:  make a cache record and all the other stuff
 *	not found:
 *	    Return with a trustlevel, saying that we do not have
 *	    a trust record for it. The caller may use insert_trust_record()
 *	    and then call this function here again.
 *
 * Problems: How do we get the complete keyblock to check that the
 *	     cache record is actually valid?  Think we need a clever
 *	     cache in getkey.c	to keep track of this stuff. Maybe it
 *	     is not necessary to check this if we use a local pubring. Hmmmm.
 */
int
check_trust( PKT_public_cert *pkc, unsigned *r_trustlevel )
{
    TRUSTREC rec;
    unsigned trustlevel = TRUST_UNKNOWN;
    int rc=0;

    if( DBG_TRUST )
	log_info("check_trust() called.\n");

    /* get the pubkey record */
    if( pkc->local_id ) {
	if( read_record( pkc->local_id, &rec ) ) {
	    log_error("check_trust: read record failed\n");
	    return G10ERR_TRUSTDB;
	}
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=scan_record_by_pkc( pkc, &rec, 2 )) && rc != -1 ) {
	    log_error("check_trust: scan_record_by_pkc(2) failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
	else if( rc == -1 ) {
	    rc = insert_trust_record( pkc );
	    if( rc ) {
		log_error("failed to insert pubkey into trustdb: %s\n",
							    g10_errstr(rc));
		goto leave;
	    }
	    log_info("pubkey not in trustdb - inserted as %lu\n",
				    pkc->local_id );
	}
    }
    /* fixme: do some additional checks on the pubkey record */

    rc = do_check( pkc->local_id, &trustlevel );
    if( rc ) {
	log_error("check_trust: do_check failed: %s\n", g10_errstr(rc));
	return rc;
    }


  leave:
    if( DBG_TRUST )
	log_info("check_trust() returns trustlevel %04x.\n", trustlevel);
    *r_trustlevel = trustlevel;
    return 0;
}




/****************
 * Enumerate all keys, which are needed to build all trust paths for
 * the given key.  This function dies not return the key itself or
 * the ultimate key.
 *
 *  1) create a void pointer and initialize it to NULL
 *  2) pass this void pointer by reference to this function.
 *     Set lid to the key you want to enumerate and pass it by reference.
 *  3) call this function as long as it does not return -1
 *     to indicate EOF. LID does contain the next key used to build the web
 *  4) Always call this function a last time with LID set to NULL,
 *     so that it can free it's context.
 */
int
enum_trust_web( void **context, ulong *lid )
{
    ENUM_TRUST_WEB_CONTEXT *c = *context;

    if( !c ) { /* make a new context */
	c = m_alloc_clear( sizeof *c );
	*context = c;
	if( *lid != last_trust_web_key )
	    log_bug("enum_trust_web: nyi\n");
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

    if( read_record( lid, &rec ) ) {
	log_error("get_ownertrust: read record failed\n");
	return G10ERR_TRUSTDB;
    }
    if( r_otrust )
	*r_otrust = rec.r.pubkey.ownertrust;
    return 0;
}

int
keyid_from_trustdb( ulong lid, u32 *keyid )
{
    TRUSTREC rec;

    if( read_record( lid, &rec ) ) {
	log_error("keyid_from_trustdb: read record failed\n");
	return G10ERR_TRUSTDB;
    }
    if( keyid ) {
	keyid[0] = rec.r.pubkey.keyid[0];
	keyid[1] = rec.r.pubkey.keyid[1];
    }
    return 0;
}


int
query_trust_record( PKT_public_cert *pkc )
{
    TRUSTREC rec;
    int rc=0;

    if( pkc->local_id ) {
	if( read_record( pkc->local_id, &rec ) ) {
	    log_error("query_trust_record: read record failed\n");
	    return G10ERR_TRUSTDB;
	}
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=scan_record_by_pkc( pkc, &rec, 2 )) && rc != -1 ) {
	    log_error("query_trust_record: scan_record_by_pkc(2) failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
	else if( rc == -1 )
	    return rc;
    }
    return 0;
}


/****************
 * Insert a trust record into the TrustDB
 * This function failes if this record already exists.
 */
int
insert_trust_record( PKT_public_cert *pkc )
{
    TRUSTREC rec;
    u32 keyid[2];
    ulong recnum;
    byte *fingerprint;
    size_t fingerlen;


    if( pkc->local_id )
	log_bug("pkc->local_id=%lu\n", (ulong)pkc->local_id );

    keyid_from_pkc( pkc, keyid );
    fingerprint = fingerprint_from_pkc( pkc, &fingerlen );

    /* FIXME: check that we do not have this record. */

    recnum = new_recnum();
    /* build record */
    memset( &rec, 0, sizeof rec );
    rec.rectype = 2; /* the pubkey record */
    rec.r.pubkey.local_id = recnum;
    rec.r.pubkey.keyid[0] = keyid[0];
    rec.r.pubkey.keyid[1] = keyid[1];
    rec.r.pubkey.pubkey_algo = pkc->pubkey_algo;
    memcpy(rec.r.pubkey.fingerprint, fingerprint, fingerlen );
    rec.r.pubkey.ownertrust = 0;
    rec.r.pubkey.no_sigs = 0;
    if( write_record( recnum, &rec ) ) {
	log_error("insert_trust_record: write failed\n");
	return G10ERR_TRUSTDB;
    }

    pkc->local_id = recnum;

    return 0;
}


int
update_ownertrust( ulong lid, unsigned new_trust )
{
    TRUSTREC rec;

    if( read_record( lid, &rec ) ) {
	log_error("update_ownertrust: read failed\n");
	return G10ERR_TRUSTDB;
    }
    /* check keyid, fingerprint etc ? */
    if( rec.rectype != 2 ) {
	log_error("update_ownertrust: invalid record type\n");
	return G10ERR_TRUSTDB;
    }

    rec.r.pubkey.ownertrust = new_trust;
    if( write_record( lid, &rec ) ) {
	log_error("update_ownertrust: write failed\n");
	return G10ERR_TRUSTDB;
    }

    return 0;
}



/****************
 * Kludge to prevent duplicate build_sigrecs() due to an invalid
 * certificate (no selfsignature or something like this)
 */
static int
update_no_sigs( ulong lid, int no_sigs )
{
    TRUSTREC rec;

    if( read_record( lid, &rec ) ) {
	log_error("update_no_sigs: read failed\n");
	return G10ERR_TRUSTDB;
    }
    /* check keyid, fingerprint etc ? */
    if( rec.rectype != 2 ) {
	log_error("update_no_sigs: invalid record type\n");
	return G10ERR_TRUSTDB;
    }

    rec.r.pubkey.no_sigs = !!no_sigs;
    if( write_record( lid, &rec ) ) {
	log_error("update_no_sigs: write failed\n");
	return G10ERR_TRUSTDB;
    }

    return 0;
}


int
verify_private_data()
{
    int rc = 0;
    char *sigfile = make_filename("~/.g10", "sig", NULL );

    if( access( sigfile, R_OK ) ) {
	if( errno != ENOENT ) {
	    log_error("can't access %s: %s\n", sigfile, strerror(errno) );
	    rc = G10ERR_TRUSTDB;
	    goto leave;
	}
	log_info("private data signature missing; creating ...\n");
	rc = sign_private_data();
	if( rc ) {
	    log_error("error creating %s: %s\n", sigfile, g10_errstr(rc) );
	    goto leave;
	}
    }

    /* FIXME: verify this signature */

  leave:
    m_free(sigfile);
    return rc;
}


int
sign_private_data()
{
    int rc;
    char *sigfile = make_filename("~/.g10", "sig", NULL );
    char *secring = make_filename("~/.g10", "secring.g10", NULL );
    STRLIST list = NULL;

    add_to_strlist( &list, db_name );
    add_to_strlist( &list, secring );

    rc = sign_file( list, 1, NULL, 0, NULL, sigfile);

    m_free(sigfile);
    m_free(secring);
    free_strlist(list);
    return rc;
}

