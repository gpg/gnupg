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

struct trust_record {
    byte rectype;
    byte reserved;
    union {
	struct {	    /* version record: */
	    byte magic[2];
	    byte version;   /* should be 1 */
	    byte reserved[3];
	    ulong locked;    /* pid of process which holds a lock */
	    ulong created;   /* timestamp of trustdb creation  */
	    ulong modified;  /* timestamp of last modification */
	    ulong validated; /* timestamp of last validation   */
	    ulong local_id_counter;
	    byte marginals_needed;
	    byte completes_needed;
	    byte max_cert_depth;
	} version;
	struct {	    /* public key record */
	    ulong local_id;
	    u32   keyid[2];
	    byte pubkey_algo;
	    byte reserved;
	    byte fingerprint[20];
	    byte ownertrust;
	    /* fixme: indicate a flag to */
	} pubkey;
	struct {	    /* cache record */
	    ulong owner;
	    u32   keyid[2];	  /* needed?? */
	    byte valid;
	    byte reserved;
	    byte blockhash[20];
	    byte n_untrusted;
	    byte n_marginal;
	    byte n_fully;
	    byte trustlevel;
	} cache;
	struct {
	    ulong owner;  /* local_id of record owner (pubkey record) */
	    ulong chain;  /* offset of next record or NULL for last one */
	    struct {
		ulong  local_id; /* of pubkey record of signator (0=unused) */
		byte flag;     /* reserved */
	    } sig[SIGS_PER_RECORD];
	} sigrec;
    } r;
};
typedef struct trust_record TRUSTREC;

typedef struct {
    ulong     pubkey_id;   /* localid of the pubkey */
    ulong     sig_id;	   /* returned signature id */
    unsigned  sig_flag;    /* returned signaure record flag */
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



static void create_db( const char *fname );
static void open_db(void);
static int  read_record( ulong recnum, TRUSTREC *rec );
static int  write_record( ulong recnum, TRUSTREC *rec );
static ulong new_recnum(void);
static void dump_record( ulong rnum, TRUSTREC *rec, FILE *fp );
static int walk_sigrecs( SIGREC_CONTEXT *c );

static LOCAL_ID_INFO *new_lid_table(void);
static void release_lid_table( LOCAL_ID_INFO *tbl );
static int get_lid_table_flag( LOCAL_ID_INFO *tbl, ulong lid, unsigned *flag );

static void print_user_id( const char *text, u32 *keyid );
static int do_list_path( ulong pubkey, int depth, int max_depth,
			 LOCAL_ID_INFO *lids, ulong *stack );

static int list_sigs( ulong pubkey_id );


static char *db_name;
static int  db_fd = -1;
static int no_io_dbg = 0;
/* a table used to keep track of ultimately trusted keys
 * which are the ones from our secrings */
static LOCAL_ID_INFO *ultikey_table;

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
    fwrite_32( fp, 0 ); /* local-id-counter (not used) */
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
    if( DBG_TRUST && !no_io_dbg )
	log_debug("trustdb: read_record(%lu)\n", (ulong)recnum);
    if( lseek( db_fd, recnum * TRUST_RECORD_LEN, SEEK_SET ) == -1 ) {
	log_error("trustdb: lseek failed: %s\n", strerror(errno) );
	return G10ERR_READ_FILE;
    }
    n = read( db_fd, buf, TRUST_RECORD_LEN);
    if( !n ) {
	if( DBG_TRUST )
	    log_debug("trustdb: no record at %lu\n", (ulong)recnum );
	return -1; /* eof */
    }
    else if( n != TRUST_RECORD_LEN ) {
	log_error("trustdb: read failed (n=%d): %s\n", n, strerror(errno) );
	return G10ERR_READ_FILE;
    }
    p = buf;
    rec->rectype = *p++;
    rec->reserved = *p++;
    switch( rec->rectype ) {
      case 0:  /* unused record */
	break;
      case 1: /* version record */
	rec->r.version.magic[0] = *p++;
	rec->r.version.magic[1] = *p++;
	rec->r.version.version	= *p++;
	memcpy( rec->r.version.reserved, p, 3); p += 3;
	rec->r.version.locked	= buftoulong(p); p += 4;
	rec->r.version.created	= buftoulong(p); p += 4;
	rec->r.version.modified = buftoulong(p); p += 4;
	rec->r.version.validated= buftoulong(p); p += 4;
	rec->r.version.local_id_counter = buftoulong(p); p += 4;
	rec->r.version.marginals_needed = *p++;
	rec->r.version.completes_needed = *p++;
	rec->r.version.max_cert_depth = *p++;
	if( recnum ) {
	    log_error("%s: version record with recnum %lu\n",
						    db_name, (ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	if( rec->reserved != 'g' || rec->r.version.magic[0] != '1'
				  || rec->r.version.magic[1] != '0' ) {
	    log_error("%s: not a trustdb file\n", db_name );
	    rc = G10ERR_TRUSTDB;
	}
	if( rec->r.version.version != 1 ) {
	    log_error("%s: invalid file version %d\n",
				       db_name, rec->r.version.version );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case 2:
	rec->r.pubkey.local_id = buftoulong(p); p += 4;
	rec->r.pubkey.keyid[0] = buftou32(p); p += 4;
	rec->r.pubkey.keyid[1] = buftou32(p); p += 4;
	rec->r.pubkey.pubkey_algo = *p++;
	rec->r.pubkey.reserved = *p++;
	memcpy( rec->r.pubkey.fingerprint, p, 20); p += 20;
	rec->r.pubkey.ownertrust = *p++;
	if( rec->r.pubkey.local_id != recnum ) {
	    log_error("%s: pubkey local_id != recnum (%lu,%lu)\n",
					db_name,
					(ulong)rec->r.pubkey.local_id,
					(ulong)recnum );
	    rc = G10ERR_TRUSTDB;
	}
	break;
      case 3:
	rec->r.cache.owner    = buftoulong(p); p += 4;
	rec->r.cache.keyid[0] = buftou32(p); p += 4;
	rec->r.cache.keyid[1] = buftou32(p); p += 4;
	rec->r.cache.valid = *p++;
	rec->r.cache.reserved = *p++;
	memcpy(rec->r.cache.blockhash, p, 20); p += 20;
	rec->r.cache.n_untrusted = *p++;
	rec->r.cache.n_marginal = *p++;
	rec->r.cache.n_fully = *p++;
	rec->r.cache.trustlevel = *p++;
	break;
      case 4:
      case 5:
	rec->r.sigrec.owner   = buftoulong(p); p += 4;
	rec->r.sigrec.chain   = buftoulong(p); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    rec->r.sigrec.sig[i].local_id = buftoulong(p); p += 4;
	    rec->r.sigrec.sig[i].flag = *p++;
	}
	break;
      default:
	log_error("%s: invalid record type %d at recnum %lu\n",
					db_name, rec->rectype, (ulong)recnum );
	rc = G10ERR_TRUSTDB;
	break;
    }
    if( DBG_TRUST && !rc && !no_io_dbg ) {
	log_debug("trustdb: ");
	dump_record( recnum, rec, stderr);
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

    if( DBG_TRUST && !no_io_dbg )
	log_debug("trustdb: write_record(%lu)\n", (ulong)recnum);
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
      case 2:
	ulongtobuf(p, rec->r.pubkey.local_id); p += 4;
	u32tobuf(p, rec->r.pubkey.keyid[0]); p += 4;
	u32tobuf(p, rec->r.pubkey.keyid[1]); p += 4;
	*p++ = rec->r.pubkey.pubkey_algo;
	*p++ = rec->r.pubkey.reserved;
	memcpy( p, rec->r.pubkey.fingerprint, 20); p += 20;
	*p++ = rec->r.pubkey.ownertrust;
	assert( rec->r.pubkey.local_id == recnum );
	break;
      case 3:
	ulongtobuf(p, rec->r.cache.owner); p += 4;
	u32tobuf(p, rec->r.cache.keyid[0]); p += 4;
	u32tobuf(p, rec->r.cache.keyid[1]); p += 4;
	*p++ = rec->r.cache.valid;
	*p++ = rec->r.cache.reserved;
	memcpy(p, rec->r.cache.blockhash, 20); p += 20;
	*p++ = rec->r.cache.n_untrusted;
	*p++ = rec->r.cache.n_marginal;
	*p++ = rec->r.cache.n_fully;
	*p++ = rec->r.cache.trustlevel;
	break;
      case 4:
      case 5:
	ulongtobuf(p, rec->r.sigrec.owner); p += 4;
	ulongtobuf(p, rec->r.sigrec.chain); p += 4;
	for(i=0; i < SIGS_PER_RECORD; i++ ) {
	    ulongtobuf(p, rec->r.sigrec.sig[i].local_id); p += 4;
	    *p++ = rec->r.sigrec.sig[i].flag;
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
 * Scan the trustdb for a record of type RECTYPE which matches PKC
 * The local_id is set to the correct value
 */
static int
scan_record_by_pkc( PKT_public_cert *pkc, TRUSTREC *rec, int rectype )
{
    ulong recnum;
    u32 keyid[2];
    byte *fingerprint;
    size_t fingerlen;
    int rc;

    assert( rectype == 2 || rectype == 3 );

    if( DBG_TRUST )
	log_debug("trustdb: scan_record_by_pkc\n");
    keyid_from_pkc( pkc, keyid );
    fingerprint = fingerprint_from_pkc( pkc, &fingerlen );
    assert( fingerlen == 20 || fingerlen == 16 );

    no_io_dbg = 1;
    for(recnum=1; !(rc=read_record( recnum, rec)); recnum++ ) {
	if( rec->rectype != rectype )
	    continue;
	if( rec->rectype == 2 ) {
	    if( rec->r.pubkey.keyid[0] == keyid[0]
		&& rec->r.pubkey.keyid[1] == keyid[1]
		&& rec->r.pubkey.pubkey_algo == pkc->pubkey_algo
		&& !memcmp(rec->r.pubkey.fingerprint, fingerprint, fingerlen)
	      ) { /* found */
		/* store the local_id */
		if( pkc->local_id && pkc->local_id != recnum )
		    log_error("%s: found record, but local_id from mem does "
			      "not match recnum (%lu,%lu)\n", db_name,
					 (ulong)pkc->local_id, (ulong)recnum );
		pkc->local_id = recnum;
		no_io_dbg = 0;
		return 0;
	    }
	}
	else
	    log_bug("not yet implemented\n");
    }
    no_io_dbg = 0;
    if( DBG_TRUST )
	log_debug("trustdb: scan_record_by_pkc: %s\n", rc==-1?"eof": g10_errstr(rc));
    if( rc != -1 )
	log_error("%s: scan_record_by_pkc failed: %s\n",db_name, g10_errstr(rc) );
    return rc;
}

/****************
 * scan the DB for a record of type RECTYPE which can be localized
 * with LOCAL_ID
 */
static int
scan_record( ulong local_id, TRUSTREC *rec, int rectype, ulong *r_recnum )
{
    ulong recnum;
    int rc;

    assert( rectype == 3 || rectype == 4 );

    if( DBG_TRUST )
	log_debug("trustdb: scan_record type %d local_id %lu\n",
						rectype, (ulong)local_id);
    no_io_dbg = 1;
    for(recnum=1; !(rc=read_record( recnum, rec)); recnum++ ) {
	if( rec->rectype != rectype )
	    continue;
	if( rec->rectype == 34 ) {
	    if( rec->r.cache.owner == local_id ) { /* found */
		*r_recnum = recnum;
		no_io_dbg = 0;
		return 0;
	    }
	}
	else if( rec->rectype == 4 ) {
	    if( rec->r.sigrec.owner == local_id ) { /* found */
		*r_recnum = recnum;
		no_io_dbg = 0;
		return 0;
	    }
	}
	else
	    log_bug("not yet implemented\n");
    }
    no_io_dbg = 0;
    if( DBG_TRUST )
	log_debug("trustdb: scan_record: %s\n", rc==-1?"eof": g10_errstr(rc));
    if( rc != -1 )
	log_error("%s: scan_record failed: %s\n",db_name, g10_errstr(rc) );
    return rc;
}


static void
dump_record( ulong rnum, TRUSTREC *rec, FILE *fp  )
{
    int i, any;

    fprintf(fp, "trust record %lu, type=", rnum );

    switch( rec->rectype ) {
      case 0: fprintf(fp, "free\n");
	break;
      case 1: fprintf(fp, "version\n");
	break;
      case 2: fprintf(fp, "pubkey, keyid=%08lX, ownertrust=%02x\n",
		   rec->r.pubkey.keyid[1], rec->r.pubkey.ownertrust );
	break;
      case 3: fprintf(fp, "cache\n");
      case 4:
      case 5:
	fprintf(fp, "sigrec, owner=%lu, chain=%lu%s\n",
			 rec->r.sigrec.owner, rec->r.sigrec.chain,
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
	rc = scan_record_by_pkc( pkc, &rec, 2 );
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


void
list_trustdb( const char *username )
{
    TRUSTREC rec;

    if( username ) {
	PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
	int rc;

	if( (rc = get_pubkey_byname( pkc, username )) )
	    log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
	else if( (rc=scan_record_by_pkc( pkc, &rec, 2 )) && rc != -1 )
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
	no_io_dbg = 1;
	for(recnum=0; !read_record( recnum, &rec); recnum++ )
	    dump_record( recnum, &rec, stdout );
	no_io_dbg = 0;
    }
}

void
list_trust_path( int max_depth, const char *username )
{
    int rc;
    TRUSTREC rec;
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );

    if( max_depth < 1 )
	max_depth = MAX_LIST_SIGS_DEPTH+1;


    if( (rc = get_pubkey_byname( pkc, username )) )
	log_error("user '%s' not found: %s\n", username, g10_errstr(rc) );
    else if( (rc=scan_record_by_pkc( pkc, &rec, 2 )) && rc != -1 )
	log_error("problem finding '%s' in trustdb: %s\n",
					    username, g10_errstr(rc));
    else if( rc == -1 )
	log_error("user '%s' not in trustdb\n", username);
    else {
	LOCAL_ID_INFO *lids;
	ulong stack[MAX_LIST_SIGS_DEPTH];

	lids = new_lid_table();
	stack[0] = pkc->local_id;
	rc = do_list_path( pkc->local_id, 1, max_depth, lids, stack );
	putchar('\n');

	release_lid_table(lids);
	if( rc )
	    log_error("user '%s' list problem: %s\n", username, g10_errstr(rc));
    }

    free_public_cert( pkc );
}

/****************
 * Walk throug the signatures of a public key.
 * The caller must provide a context structure, with all fields set
 * to zero, but the pubkeyid filed set to the requested pubkey;
 * This function does not change this field.  On return the context
 * is filled with the local-id of the signature and the signature flag.
 * No fields should be changed (clearing all fields and setting
 * pubkeyid is okay to continue with an other pubkey)
 * Returns: 0 - okay, -1 for eof (no more sigs) or any other errorcode
 */
static int
walk_sigrecs( SIGREC_CONTEXT *c )
{
    int rc=0;
    TRUSTREC *r;
    ulong rnum;

    if( c->ctl.eof )
	return -1;
    r = &c->ctl.rec;
    if( !r->rectype ) { /* this is the first call */
	rc = scan_record( c->pubkey_id, r, 4, &rnum );
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
 *************	trust logic  *******************
 ***********************************************/

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
 * Add a new item to the table or return 1 if we aread have this item
 * fixme: maybe its a good idea to tage items from an unused item list.
 */
static int
add_lid_table_item( LOCAL_ID_INFO *tbl, ulong lid, unsigned flag )
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
get_lid_table_flag( LOCAL_ID_INFO *tbl, ulong lid, unsigned *flag )
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
    if( rec.rectype != 2 ) {
	log_error("record with local_id %lu is not a pubkey record\n", lid);
	return G10ERR_TRUSTDB;
    }
    keyid[0] = rec.r.pubkey.keyid[0];
    keyid[1] = rec.r.pubkey.keyid[1];
    return 0;
}


/****************
 * Verify, that all our public keys are in the trustDB and marked as
 * ultimately trusted.
 */
static int
verify_own_certs()
{
    int rc;
    void *enum_context = NULL;
    PKT_secret_cert *skc = m_alloc_clear( sizeof *skc );
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
    u32 keyid[2];
    int trust;

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
	/* look into the trustdb */
	rc = check_pkc_trust( pkc, &trust );
	if( rc ) {
	    log_info("keyid %08lX: problem in trustdb: %s\n", (ulong)keyid[1],
							      g10_errstr(rc) );
	    goto leave;
	}
	if( trust & TRUST_NO_PUBKEY ) {
	    log_info("keyid %08lX: not yet in trustdb\n", (ulong)keyid[1] );
	    rc = insert_trust_record( pkc );
	    if( rc )
		log_error("keyid %08lX: insert failed: %s\n",
					    (ulong)keyid[1], g10_errstr(rc) );
	    else
		log_info("keyid %08lX: inserted\n", (ulong)keyid[1] );
	}
	else if( (trust & TRUST_MASK) != TRUST_ULT_TRUST )  {
	  /*log_error("keyid %08lX: not marked as ultimately trusted\n",
							   (ulong)keyid[1] );
	       FIXME: mark */
	}

	if( !(trust & TRUST_NO_PUBKEY) ) {
	    if( DBG_TRUST )
		log_debug("putting %08lX(%lu) into ultikey_table\n",
					(ulong)keyid[1], pkc->local_id );
	    if( add_lid_table_item( ultikey_table, pkc->local_id, 0 ) )
		log_error("keyid %08lX: already in ultikey_table\n",
							    (ulong)keyid[1]);
	}

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
    sx.pubkey_id = pubkey;
    for(;;) {
	rc = walk_sigrecs( &sx );
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
	    if( !get_lid_table_flag( ultikey_table, sx.sig_id, NULL ) ) {
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
	    else if( add_lid_table_item( lids, sx.sig_id, *lineno ) ) {
		unsigned refline;
		get_lid_table_flag( lids, sx.sig_id, &refline );
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





static int
do_list_path( ulong pubkey, int depth, int max_depth,
	      LOCAL_ID_INFO *lids, ulong *stack )
{
    SIGREC_CONTEXT sx;
    int rc;

    if( depth > max_depth || depth >= MAX_LIST_SIGS_DEPTH  )
	return 0;
    if( !get_lid_table_flag( ultikey_table, pubkey, NULL ) ) {
	/* found a path */
	int i;
	u32 keyid[2];

	for(i=0; i < depth; i++ ) {
	    if( keyid_from_local_id( stack[i], keyid ) )
		printf("%*s????????(%lu) ", i*4,"", stack[i] );
	    else {
		printf("%*s%08lX(%lu) ", i*4,"", keyid[1], stack[i] );
		print_user_id("", keyid );
	    }
	}
	putchar('\n');
	return 0;
    }

    if( add_lid_table_item( lids, pubkey, 0 ) )
	return 0;

    memset( &sx, 0, sizeof sx );
    sx.pubkey_id = pubkey;
    do {
	rc = walk_sigrecs( &sx );
	if( !rc ) {
	    stack[depth] = sx.sig_id;
	    rc = do_list_path( sx.sig_id, depth+1, max_depth, lids, stack );
	}
    } while( !rc );
    return rc==-1? 0 : rc;
}




/****************
 * Check all the sigs of the given keyblock and mark them
 * as checked.
 */
static int
check_sigs( KBNODE keyblock, int *selfsig_okay )
{
    KBNODE kbctx;
    KBNODE node;
    int rc;

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
	    }
	    if( DBG_TRUST )
		log_debug("trustdb: sig from %08lX: %s\n",
				(ulong)node->pkt->pkt.signature->keyid[1],
						    g10_errstr(rc) );
	}
    }
    return 0;
}


/****************
 * If we do not have sigrecs for the given key, build them and write them
 * to the trustdb
 */
static int
build_sigrecs( ulong pubkeyid )
{
    TRUSTREC rec, rec2;
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
	log_error("build_sigrecs: can't read pubkey record\n");
	goto leave;
    }
    finfo = m_alloc_clear( sizeof *finfo );
    finfo->keyid[0] = rec.r.pubkey.keyid[0];
    finfo->keyid[1] = rec.r.pubkey.keyid[1];
    finfo->pubkey_algo = rec.r.pubkey.pubkey_algo;
    memcpy( finfo->fingerprint, rec.r.pubkey.fingerprint, 20);
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
	rc = G10ERR_BAD_CERT;
	goto leave;
    }

    /* valid key signatures are now marked; we can now build the
     * sigrecs */
    memset( &rec, 0, sizeof rec );
    rec.rectype = 4;
    i = 0;
    rnum = rnum2 = 0;
    for( kbctx=NULL; (node=walk_kbtree( keyblock, &kbctx)) ; ) {
	if( node->flag & 1 ) {
	    assert( node->pkt->pkttype == PKT_SIGNATURE );
	    if( !node->pkt->pkt.signature->local_id )  {
		/* the next function should always succeed, because
		 * we have already checked the signature, and for this
		 * it was necessary to have the pubkey. The only reason
		 * this can fail are I/o erros of the trustdb. */
		rc = set_signature_packets_local_id( node->pkt->pkt.signature );
		if( rc )
		    log_fatal("set_signature_packets_local_id failed: %s\n",
							      g10_errstr(rc));
	    }
	    if( i == SIGS_PER_RECORD ) {
		/* write the record */
		rnum = new_recnum();
		if( rnum2 ) { /* write the stored record */
		    rec2.r.sigrec.owner = pubkeyid;
		    rec2.r.sigrec.chain = rnum; /* the next record number */
		    rc = write_record( rnum2, &rec2 );
		    if( rc ) {
			log_error("build_sigrecs: write_record failed\n" );
			goto leave;
		    }
		}
		rec2 = rec;
		rnum2 = rnum;
		memset( &rec, 0, sizeof rec );
		rec.rectype = 5;
		i = 0;
	    }
	    rec.r.sigrec.sig[i].local_id = node->pkt->pkt.signature->local_id;
	    rec.r.sigrec.sig[i].flag = 0;
	    i++;
	}
    }
    if( i || rnum2 ) {
	/* write the record */
	rnum = new_recnum();
	if( rnum2 ) { /* write the stored record */
	    rec2.r.sigrec.owner = pubkeyid;
	    rec2.r.sigrec.chain = rnum;
	    rc = write_record( rnum2, &rec2 );
	    if( rc ) {
		log_error("build_sigrecs: write_record failed\n" );
		goto leave;
	    }
	}
	if( i ) { /* write the pending record */
	    rec.r.sigrec.owner = pubkeyid;
	    rec.r.sigrec.chain = 0;
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
 * Recursive check the signatures.
 */
 #if 0
static int
walk( KBNODE keyblock, int levels )
{
    KBNODE kbctx, node;

    check_sigs( keyblock );
    if( levels ) { /* check the next level */
	for( kbctx=NULL; (node=walk_kbtree( keyblock, &kbctx)) ; ) {
	    if( node->pkt->pkttype == PKT_SIGNATURE && (node->flag & 1) ) {
		/* read the keyblock for this signator */

		/* and check his signatures */
		/*walk( his_keyblock, levels-1)*/
	    }
	}
    }
    return -1;
}
#endif




/****************
 *
 */
static int
check_trust( ulong pubkeyid )
{
    int rc=0;
    ulong rnum;
    TRUSTREC rec;

    /* verify the cache */

    /* do we have sigrecs */
    rc = scan_record( pubkeyid, &rec, 4, &rnum );
    if( rc == -1 ) { /* no sigrecs, so build them */
	rc = build_sigrecs( pubkeyid );
	if( !rc ) /* and read again */
	    rc = scan_record( pubkeyid, &rec, 4, &rnum );
    }
    if( rc )
	return rc;  /* error while looking for sigrec or building sigrecs */

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
check_pkc_trust( PKT_public_cert *pkc, int *r_trustlevel )
{
    TRUSTREC rec;
    int trustlevel = 0;
    int rc=0;

    if( opt.verbose )
	log_info("check_pkc_trust() called.\n");

    /* get the pubkey record */
    if( pkc->local_id ) {
	if( read_record( pkc->local_id, &rec ) ) {
	    log_error("check_pkc_trust: read record failed\n");
	    return G10ERR_TRUSTDB;
	}
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=scan_record_by_pkc( pkc, &rec, 2 )) && rc != -1 ) {
	    log_error("check_pkc_trust: scan_record_by_pkc(2) failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
	else if( rc == -1 ) {
	    log_error("check_pkc_trust: pubkey not in TrustDB\n");
	    trustlevel = TRUST_NO_PUBKEY;
	    goto leave;
	}
    }
    /* fixme: do some additional checks on the pubkey record */

    rc = check_trust( pkc->local_id );
    if( rc ) {
	log_error("check_pkc_trust: check_trust failed: %s\n", g10_errstr(rc));
	return rc;
    }


  leave:
    if( opt.verbose )
	log_info("check_pkc_trust() returns trustlevel %04x.\n", trustlevel);
    *r_trustlevel = trustlevel;
    return 0;
}


int
get_ownertrust( PKT_public_cert *pkc, int *r_otrust )
{
    TRUSTREC rec;
    int rc;

    /* get the pubkey record */
    if( pkc->local_id ) {
	if( read_record( pkc->local_id, &rec ) ) {
	    log_error("get_ownertrust: read record failed\n");
	    return G10ERR_TRUSTDB;
	}
    }
    else { /* no local_id: scan the trustdb */
	if( (rc=scan_record_by_pkc( pkc, &rec, 2 )) && rc != -1 ) {
	    log_error("get_ownertrust: scan_record_by_pkc(2) failed: %s\n",
							    g10_errstr(rc));
	    return rc;
	}
	else if( rc == -1 )
	    return rc;
    }
    *r_otrust = rec.r.pubkey.ownertrust;
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


    if( DBG_TRUST )
	log_debug("trustdb: insert_record\n");

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
    if( write_record( recnum, &rec ) ) {
	log_error("insert_trust_record: write failed\n");
	return G10ERR_TRUSTDB;
    }

    pkc->local_id = recnum;

    return 0;
}


int
update_trust_record( PKT_public_cert *pkc, int new_trust )
{
    TRUSTREC rec;
    ulong recnum;

    if( DBG_TRUST )
	log_debug("trustdb: update_record\n");

    assert( pkc->local_id );

    if( read_record( pkc->local_id, &rec ) ) {
	log_error("update_trust_record: read failed\n");
	return G10ERR_TRUSTDB;
    }
    /* check keyid, fingerprint etc ? */

    rec.r.pubkey.ownertrust = 0;
    if( write_record( recnum, &rec ) ) {
	log_error("insert_trust_record: write failed\n");
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

