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


#define TRUST_RECORD_LEN 40

struct trust_record {
    byte rectype;
    byte reserved;
    union {
	struct {	    /* version record: */
	    byte magic[2];
	    byte version;   /* should be 1 */
	    byte reserved[3];
	    u32  locked;    /* pid of process which holds a lock */
	    u32  created;   /* timestamp of trustdb creation  */
	    u32  modified;  /* timestamp of last modification */
	    u32  validated; /* timestamp of last validation   */
	    u32  local_id_counter;
	    byte marginals_needed;
	    byte completes_needed;
	    byte max_cert_depth;
	} version;
	struct {	    /* public key record */
	    u32 local_id;
	    u32 keyid[2];
	    byte algo;
	    byte reserved;
	    byte fingerprint[20];
	    byte ownertrust;
	} pubkey;
	struct {	    /* cache record */
	    u32 local_id;
	    u32 keyid[2];
	    byte valid;
	    byte reserved;
	    byte blockhash[20];
	    byte n_untrusted;
	    byte n_marginal;
	    byte n_fully;
	    byte trustlevel;
	} cache;
    } r;
};
typedef struct trust_record TRUSTREC;


static void create_db( const char *fname );
static void open_db(void);
static int  read_record( u32 recnum, TRUSTREC *rec );
static u32 new_local_id(void);

static char *db_name;
static int  db_fd = -1;
static int no_io_dbg = 0;

#define buftou32( p )  ((*(byte*)(p) << 24) | (*((byte*)(p)+1)<< 16) | \
		       (*((byte*)(p)+2) << 8) | (*((byte*)(p)+3)))
#define buftou16( p )  ((*((byte*)(p)) << 8) | (*((byte*)(p)+1)))
#define u32tobuf( p, a ) do {				\
			    ((byte*)p)[0] = a >> 24;	\
			    ((byte*)p)[1] = a >> 16;	\
			    ((byte*)p)[2] = a >>  8;	\
			    ((byte*)p)[3] = a	   ;	\
			} while(0)
#define u16tobuf( p, a ) do {				\
			    ((byte*)p)[0] = a >>  8;	\
			    ((byte*)p)[1] = a	   ;	\
			} while(0)


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
fwrite_16(FILE *fp, u16 a)
{
    putc( (a>>8) & 0x0ff , fp );
    if( putc( a & 0xff, fp ) == EOF )
	log_fatal("error writing u16 to trustdb: %s\n", strerror(errno) );
}

static int
fwrite_32( FILE*fp, u32 a)
{
    putc( (a>>24) & 0xff, fp );
    putc( (a>>16) & 0xff, fp );
    putc( (a>> 8) & 0xff, fp );
    if( putc( a & 0xff, fp ) == EOF )
	log_fatal("error writing u32 to trustdb: %s\n", strerror(errno) );
}

static int
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
    u32 along;
    u16 ashort;

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
read_record( u32 recnum, TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int n;

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
	rec->r.version.locked	= buftou32(p); p += 4;
	rec->r.version.created	= buftou32(p); p += 4;
	rec->r.version.modified = buftou32(p); p += 4;
	rec->r.version.validated= buftou32(p); p += 4;
	rec->r.version.local_id_counter = buftou32(p); p += 4;
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
	rec->r.pubkey.local_id = buftou32(p); p += 4;
	rec->r.pubkey.keyid[0] = buftou32(p); p += 4;
	rec->r.pubkey.keyid[1] = buftou32(p); p += 4;
	rec->r.pubkey.algo = *p++;
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
	rec->r.cache.local_id = buftou32(p); p += 4;
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
write_record( u32 recnum, TRUSTREC *rec )
{
    byte buf[TRUST_RECORD_LEN], *p;
    int rc = 0;
    int n;

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
	log_bug(NULL);
	break;
      case 2:
	u32tobuf(p, rec->r.pubkey.local_id); p += 4;
	u32tobuf(p, rec->r.pubkey.keyid[0]); p += 4;
	u32tobuf(p, rec->r.pubkey.keyid[1]); p += 4;
	*p++ = rec->r.pubkey.algo;
	*p++ = rec->r.pubkey.reserved;
	memcpy( p, rec->r.pubkey.fingerprint, 20); p += 20;
	*p++ = rec->r.pubkey.ownertrust;
	assert( rec->r.pubkey.local_id == recnum );
	break;
      case 3:
	u32tobuf(p, rec->r.cache.local_id); p += 4;
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
      default:
	log_bug(NULL);
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

static u32
new_local_id()
{
    off_t offset;
    u32 recnum;

    /* fixme: look for unused records */
    offset = lseek( db_fd, 0, SEEK_END );
    if( offset == -1 )
	log_fatal("trustdb: lseek to end failed: %s\n", strerror(errno) );
    recnum = offset / TRUST_RECORD_LEN;
    assert(recnum); /* this is will never be the first record */
    return recnum ;
}

/****************
 * Scan the trustdb for a record of type RECTYPE which maches PKC
 * The local_id is set to the correct value
 */
static int
scan_record( PKT_public_cert *pkc, TRUSTREC *rec, int rectype )
{
    u32 recnum;
    u32 keyid[2];
    byte *fingerprint;
    size_t fingerlen;
    int dbg = DBG_TRUST;
    int rc;

    assert( rectype == 2 || rectype == 3 );

    if( DBG_TRUST )
	log_debug("trustdb: scan_record\n");
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
		&& rec->r.pubkey.algo	  == pkc->pubkey_algo
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
	log_debug("trustdb: scan_record: eof or error\n");
    if( rc != -1 )
	log_error("%s: scan_record failed: %s\n",db_name, g10_errstr(rc) );
    return rc;
}




/***********************************************
 *************	trust logic  *******************
 ***********************************************/

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
	/* fixme: to be sure that it is a secret key of our own,
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
	    /* FIXME: insert */
	}
	else if( (trust & TRUST_MASK) != TRUST_ULT_TRUST )  {
	    log_error("keyid %08lX: not marked as ultimately trusted\n",
							   (ulong)keyid[1] );
	    /* FIXME: mark */
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



/****************
 * Check all the sigs of the given keyblock and mark them
 * as checked.
 */
static int
check_sigs( KBNODE keyblock )
{
    KBNODE kbctx;
    KBNODE node;
    int rc;

    for( kbctx=NULL; (node=walk_kbtree( keyblock, &kbctx)) ; ) {
	if( node->pkt->pkttype == PKT_SIGNATURE
	    && (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    rc = check_key_signature( keyblock, node );
	    if( !rc )
		node->flag |= 1; /* mark signature valid */
	    if( DBG_TRUST )
		log_debug("trustdb: sig from %08lX: %s\n",
						rc? g10_errstr(rc): "okay" );
	}
    }
    return 0;
}


/****************
 * Recursive check the signatures.
 */
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

}





/****************
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
static int
check_trust()
{
}



/*********************************************************
 ****************  API Interface  ************************
 *********************************************************/

/****************
 * Perform some checks over the trustdb
 *  level 0: used for initial program startup
 */
int
check_trustdb( int level )
{
    int rc=0;

    if( !level ) {
	char *fname = make_filename("~/.g10", "trustDB", NULL );
	if( access( fname, R_OK ) ) {
	    if( errno != ENOENT ) {
		log_error("can't access %s: %s\n", fname, strerror(errno) );
		m_free(fname);
		return G10ERR_TRUSTDB;
	    }
	    create_db( fname );
	}
	m_free(db_name);
	db_name = fname;

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
	log_bug(NULL);

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
 *		no:  make a cache record
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
	if( (rc=scan_record( pkc, &rec, 2 )) && rc != -1 ) {
	    log_error("check_pkc_trust: scan_record(2) failed: %s\n",
							    g10_errstr(rc));
	    return G10ERR_TRUSTDB;
	}
	else if( rc == -1 ) {
	    log_error("check_pkc_trust: pubkey not in TrustDB\n");
	    trustlevel = TRUST_NO_PUBKEY;
	    goto leave;
	}
    }
    /* fixme: do some additional checks on the pubkey record */


  leave:
    if( opt.verbose )
	log_info("check_pkc_trust() returns trustlevel %04x.\n", trustlevel);
    *r_trustlevel = trustlevel;
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
    u32 recnum;
    byte *fingerprint;
    size_t fingerlen;


    if( DBG_TRUST )
	log_debug("trustdb: insert_record\n");

    assert( !pkc->local_id );

    keyid_from_pkc( pkc, keyid );
    fingerprint = fingerprint_from_pkc( pkc, &fingerlen );

    /* FIXME: check that we do not have this record. */

    recnum = new_local_id();
    /* build record */
    memset( &rec, 0, sizeof rec );
    rec.rectype = 2; /* the pubkey record */
    rec.r.pubkey.local_id = recnum;
    rec.r.pubkey.keyid[0] = keyid[0];
    rec.r.pubkey.keyid[1] = keyid[1];
    rec.r.pubkey.algo = pkc->pubkey_algo;
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
    u32 keyid[2];
    u32 recnum;

    if( DBG_TRUST )
	log_debug("trustdb: update_record\n");

    assert( pkc->local_id );

    if( read_record( pkc->local_id, &rec ) ) {
	log_error("update_trust_record: read failed\n");
	return G10ERR_TRUSTDB;
    }
    /* check keyid, fingerprint etc ? */

    recnum = new_local_id();
    /* build record */
    memset( &rec, 0, sizeof rec );
    rec.rectype = 2; /* the pubkey record */
    rec.r.pubkey.local_id = recnum;
    rec.r.pubkey.keyid[0] = keyid[0];
    rec.r.pubkey.keyid[1] = keyid[1];
    rec.r.pubkey.algo = pkc->pubkey_algo;
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

