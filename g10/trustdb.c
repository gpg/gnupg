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
	byte raw[TRUST_RECORD_LEN-2];
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



static char *db_name;

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
    fwrite_32( fp, 0 ); /* local-id-counter */
    fwrite_8( fp, 3 );	/* marginals needed */
    fwrite_8( fp, 1 );	/* completes needed */
    fwrite_8( fp, 4 );	/* max_cet_depth */
    fwrite_zeros( fp, 9 ); /* filler */
    fclose(fp);
}













/***********************************************
 *************	trust logic  *******************
 ***********************************************/





/*********************************************************
 ****************  API Interface  ************************
 *********************************************************/

/****************
 * Perform some checks over the trustdb
 *  level 0: used on initial program startup
 */
int
check_trustdb( int level )
{
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
	 * in ~/.g10/ here
	 */
    }
    else
	log_bug(NULL);

    return 0;
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
    int trustlevel = 0;

    if( opt.verbose )
	log_info("check_pkc_trust() called.\n");

    *r_trustlevel = trustlevel;
    return 0;
}

