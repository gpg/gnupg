/* md.c  -  message digest dispatcher
 *	Copyright (C) 1998,1999 Free Software Foundation, Inc.
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

#include "g10lib.h"
#include "util.h"
#include "cipher.h"
#include "dynload.h"
#include "rmd.h"


struct md_digest_list_s;

/* this structure is put right after the GCRY_MD_HD buffer, so that
 * only one memory block is needed. */
struct gcry_md_context {
    int  magic;
    int  secure;
    FILE  *debug;
    int finalized;
    struct md_digest_list_s *list;
};
#define CTX_MAGIC_NORMAL 0x11071961
#define CTX_MAGIC_SECURE 0x16917011

static const char * digest_algo_to_string( int algo );
static int check_digest_algo( int algo );
static GCRY_MD_HD md_open( int algo, int secure );
static int  md_enable( GCRY_MD_HD hd, int algo );
static GCRY_MD_HD md_copy( GCRY_MD_HD a );
static void md_close(GCRY_MD_HD a);
static void md_write( GCRY_MD_HD a, byte *inbuf, size_t inlen);
static void md_final(GCRY_MD_HD a);
static byte *md_read( GCRY_MD_HD a, int algo );
static int md_get_algo( GCRY_MD_HD a );
static int md_digest_length( int algo );
static const byte *md_asn_oid( int algo, size_t *asnlen, size_t *mdlen );
static void md_start_debug( GCRY_MD_HD a, const char *suffix );
static void md_stop_debug( GCRY_MD_HD a );

/****************
 * This structure is used for the list of available algorithms
 * and for the list of algorithms in GCRY_MD_HD.
 */
struct md_digest_list_s {
    struct md_digest_list_s *next;
    const char *name;
    int algo;
    byte *asnoid;
    int asnlen;
    int mdlen;
    void (*init)( void *c );
    void (*write)( void *c, byte *buf, size_t nbytes );
    void (*final)( void *c );
    byte *(*read)( void *c );
    size_t contextsize; /* allocate this amount of context */
    PROPERLY_ALIGNED_TYPE context;
};

static struct md_digest_list_s *digest_list;


static struct md_digest_list_s *
new_list_item( int algo,
	       const char *(*get_info)( int, size_t*,byte**, int*, int*,
				       void (**)(void*),
				       void (**)(void*,byte*,size_t),
				       void (**)(void*),byte *(**)(void*)) )
{
    struct md_digest_list_s *r;

    r = g10_xcalloc( 1, sizeof *r );
    r->algo = algo,
    r->name = (*get_info)( algo, &r->contextsize,
			   &r->asnoid, &r->asnlen, &r->mdlen,
			   &r->init, &r->write, &r->final, &r->read );
    if( !r->name ) {
	g10_free(r);
	r = NULL;
    }
    return r;
}



/****************
 * Try to load the modules with the requeste algorithm
 * and return true if new modules are available
 * If req_alog is -1 try to load all digest algorithms.
 */
static int
load_digest_module( int req_algo )
{
    static int initialized = 0;
    static u32 checked_algos[256/32];
    static int checked_all = 0;
    struct md_digest_list_s *r;
    void *context = NULL;
    int algo;
    int any = 0;
    const char *(*get_info)( int, size_t*,byte**, int*, int*,
			    void (**)(void*),
			    void (**)(void*,byte*,size_t),
			    void (**)(void*),byte *(**)(void*));

    if( !initialized ) {
	cipher_modules_constructor();
	initialized = 1;
    }
    algo = req_algo;
    if( algo > 255 || !algo )
	return 0; /* algorithm number too high (does not fit into out bitmap)*/
    if( checked_all )
	return 0; /* already called with -1 */
    if( algo < 0 )
	checked_all = 1;
    else if( (checked_algos[algo/32] & (1 << (algo%32))) )
	return 0; /* already checked and not found */
    else
	checked_algos[algo/32] |= (1 << (algo%32));

    while( enum_gnupgext_digests( &context, &algo, &get_info ) ) {
	if( req_algo != -1 && algo != req_algo )
	    continue;
	for(r=digest_list; r; r = r->next )
	    if( r->algo == algo )
		break;
	if( r ) {
	    log_info("skipping digest %d: already loaded\n", algo );
	    continue;
	}
	r = new_list_item( algo, get_info );
	if( ! r ) {
	    log_info("skipping digest %d: no name\n", algo );
	    continue;
	}
	/* put it into the list */
	if( g10_opt_verbose > 1 )
	    log_info("loaded digest %d\n", algo);
	r->next = digest_list;
	digest_list = r;
	any = 1;
	if( req_algo != -1 )
	    break;
    }
    enum_gnupgext_digests( &context, NULL, NULL );
    return any;
}



/****************
 * Map a string to the digest algo
 */
int
gcry_md_map_name( const char *string )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next )
	    if( !stricmp( r->name, string ) )
		return r->algo;
    } while( !r && load_digest_module(-1) );
    return 0;
}


/****************
 * Map a digest algo to a string
 */
static const char *
digest_algo_to_string( int algo )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next )
	    if( r->algo == algo )
		return r->name;
    } while( !r && load_digest_module( algo ) );
    return NULL;
}

/****************
 * This function simply returns the name of the algorithm or some constant
 * string when there is no algo.  It will never return NULL.
 * Use	the macro gcry_md_test_algo() to check whether the algorithm
 * is valid.
 */
const char *
gcry_md_algo_name( int algo )
{
    const char *s = digest_algo_to_string( algo );
    return s? s: "?";
}


static int
check_digest_algo( int algo )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next )
	    if( r->algo == algo )
		return 0;
    } while( !r && load_digest_module(algo) );
    return GCRYERR_INV_MD_ALGO;
}



/****************
 * Open a message digest handle for use with algorithm ALGO.
 * More algorithms may be added by md_enable(). The initial algorithm
 * may be 0.
 */
static GCRY_MD_HD
md_open( int algo, int secure )
{
    GCRY_MD_HD hd;
    struct gcry_md_context *ctx;
    int bufsize = secure? 512 : 1024;
    size_t n;

    /* Allocate a memory area to hold the caller visible buffer with it's
     * control information and the data required by this module. Set the
     * context pointer at the beginning to this area.
     * We have to use this strange scheme because we want to hide the
     * internal data but have a variable sized buffer.
     *
     *	+---+------+---........------+-------------+
     *	!ctx! bctl !  buffer	     ! private	   !
     *	+---+------+---........------+-------------+
     *	  !			      ^
     *	  !---------------------------!
     *
     * We have to make sture that private is well aligned.
     */
    n = sizeof( struct gcry_md_handle ) + bufsize;
    n = ((n + sizeof(PROPERLY_ALIGNED_TYPE)-1)
	 / sizeof(PROPERLY_ALIGNED_TYPE) ) * sizeof(PROPERLY_ALIGNED_TYPE);

    /* allocate and set the Context pointer to the private data */
    hd = secure ? g10_malloc_secure( n + sizeof( struct gcry_md_context ) )
		: g10_malloc(	     n + sizeof( struct gcry_md_context ) );
    if( !hd ) {
	set_lasterr( GCRYERR_NO_MEM );
	return NULL;
    }

    hd->ctx = ctx = (struct gcry_md_context*)( (char*)hd + n );
    /* setup the globally visible data (bctl in the diagram)*/
    hd->bufsize = n - sizeof( struct gcry_md_handle ) + 1;
    hd->bufpos = 0;
    /* initialize the private data */
    memset( hd->ctx, 0, sizeof *hd->ctx );
    ctx->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
    ctx->secure = secure;
    fast_random_poll(); /* FIXME: should we really do that? */
    if( algo && md_enable( hd, algo ) ) {
	md_close( hd );
	return NULL;
    }
    return hd;
}


GCRY_MD_HD
gcry_md_open( int algo, unsigned int flags )
{
    GCRY_MD_HD hd;
    /* fixme: check that algo is available and that only valid
     * flag values are used */
    hd = md_open( algo, (flags & GCRY_MD_FLAG_SECURE) );
    return hd;
}



static int
md_enable( GCRY_MD_HD hd, int algo )
{
    struct gcry_md_context *h = hd->ctx;
    struct md_digest_list_s *r, *ac;

    for( ac=h->list; ac; ac = ac->next )
	if( ac->algo == algo )
	    return 0; /* already enabled */
    /* find the algorithm */
    do {
	for(r = digest_list; r; r = r->next )
	    if( r->algo == algo )
		break;
    } while( !r && load_digest_module( algo ) );
    if( !r ) {
	log_debug("md_enable: algorithm %d not available\n", algo );
	return set_lasterr( GCRYERR_INV_MD_ALGO );
    }
    /* and allocate a new list entry */
    ac = h->secure? g10_malloc_secure( sizeof *ac + r->contextsize
					       - sizeof(r->context) )
		  : g10_malloc( sizeof *ac + r->contextsize
					       - sizeof(r->context) );
    if( !ac )
	return set_lasterr( GCRYERR_NO_MEM );

    *ac = *r;
    ac->next = h->list;
    h->list = ac;
    /* and init this instance */
    (*ac->init)( &ac->context.c );
    return 0;
}


int
gcry_md_enable( GCRY_MD_HD hd, int algo )
{
    return md_enable( hd, algo );
}

static GCRY_MD_HD
md_copy( GCRY_MD_HD ahd )
{
    struct gcry_md_context *a = ahd->ctx;
    struct gcry_md_context *b;
    GCRY_MD_HD bhd;
    struct md_digest_list_s *ar, *br;
    size_t n;

    if( ahd->bufpos )
	md_write( ahd, NULL, 0 );

    n = (char*)ahd->ctx - (char*)ahd;
    bhd = a->secure ? g10_malloc_secure( n + sizeof( struct gcry_md_context ) )
		    : g10_malloc(	 n + sizeof( struct gcry_md_context ) );
    if( !bhd ) {
	set_lasterr( GCRYERR_NO_MEM );
	return NULL;
    }

    bhd->ctx = b = (struct gcry_md_context*)( (char*)bhd + n );
    /* no need to copy the buffer due to the write above */
    assert( ahd->bufsize == (n - sizeof( struct gcry_md_handle ) + 1) );
    bhd->bufsize = ahd->bufsize;
    bhd->bufpos = 0;  assert( !ahd->bufpos );
    memcpy( b, a, sizeof *a );
    b->list = NULL;
    b->debug = NULL;
    /* and now copy the complete list of algorithms */
    /* I know that the copied list is reversed, but that doesn't matter */
    for( ar=a->list; ar; ar = ar->next ) {
	br = a->secure ? g10_xmalloc_secure( sizeof *br + ar->contextsize
					       - sizeof(ar->context) )
		       : g10_xmalloc( sizeof *br + ar->contextsize
					       - sizeof(ar->context) );
	memcpy( br, ar, sizeof(*br) + ar->contextsize
				    - sizeof(ar->context) );
	br->next = b->list;
	b->list = br;
    }

    if( a->debug )
	md_start_debug( bhd, "unknown" );
    return bhd;
}

GCRY_MD_HD
gcry_md_copy( GCRY_MD_HD hd )
{
    return md_copy( hd );
}

/****************
 * Reset all contexts and discard any buffered stuff.  This may be used
 * instead of a md_close(); md_open().
 */
void
gcry_md_reset( GCRY_MD_HD a )
{
    struct md_digest_list_s *r;

    a->bufpos = a->ctx->finalized = 0;
    for( r=a->ctx->list; r; r = r->next ) {
	memset( r->context.c, 0, r->contextsize );
	(*r->init)( &r->context.c );
    }
}


static void
md_close(GCRY_MD_HD a)
{
    struct md_digest_list_s *r, *r2;

    if( !a )
	return;
    if( a->ctx->debug )
	md_stop_debug(a);
    for(r=a->ctx->list; r; r = r2 ) {
	r2 = r->next;
	g10_free(r);
    }
    g10_free(a);
}


void
gcry_md_close( GCRY_MD_HD hd )
{
    md_close( hd );
}


static void
md_write( GCRY_MD_HD a, byte *inbuf, size_t inlen)
{
    struct md_digest_list_s *r;

    if( a->ctx->debug ) {
	if( a->bufpos && fwrite(a->buf, a->bufpos, 1, a->ctx->debug ) != 1 )
	    BUG();
	if( inlen && fwrite(inbuf, inlen, 1, a->ctx->debug ) != 1 )
	    BUG();
    }
    for(r=a->ctx->list; r; r = r->next ) {
	if( a->bufpos )
	    (*r->write)( &r->context.c, a->buf, a->bufpos );
	(*r->write)( &r->context.c, inbuf, inlen );
    }
    a->bufpos = 0;
}


void
gcry_md_write( GCRY_MD_HD hd, const byte *inbuf, size_t inlen)
{
    md_write( hd, (byte*)inbuf, inlen );
}



static void
md_final(GCRY_MD_HD a)
{
    struct md_digest_list_s *r;

    if( a->ctx->finalized )
	return;

    if( a->bufpos )
	md_write( a, NULL, 0 );

    for(r=a->ctx->list; r; r = r->next ) {
	(*r->final)( &r->context.c );
    }
    a->ctx->finalized = 1;
}


int
gcry_md_ctl( GCRY_MD_HD hd, int cmd, byte *buffer, size_t buflen)
{
    if( cmd == GCRYCTL_FINALIZE )
	md_final( hd );
    else
	return GCRYERR_INV_OP;
    return 0;
}


/****************
 * if ALGO is null get the digest for the used algo (which should be only one)
 */
static byte *
md_read( GCRY_MD_HD a, int algo )
{
    struct md_digest_list_s *r;

    if( !algo ) {  /* return the first algorithm */
	if( (r=a->ctx->list) ) {
	    if( r->next )
		log_debug("more than algorithm in md_read(0)\n");
	    return (*r->read)( &r->context.c );
	}
    }
    else {
	for(r=a->ctx->list; r; r = r->next )
	    if( r->algo == algo )
		return (*r->read)( &r->context.c );
    }
    BUG();
    return NULL;
}

/****************
 * Read out the complete digest, this function implictly finalizes
 * the hash.
 */
byte *
gcry_md_read( GCRY_MD_HD hd, int algo )
{
    gcry_md_ctl( hd, GCRYCTL_FINALIZE, NULL, 0 );
    return md_read( hd, algo);
}


/****************
 * This function combines md_final and md_read but keeps the context
 * intact.  This function can be used to calculate intermediate
 * digests.  The digest is copied into buffer and the digestlength is
 * returned.  If buffer is NULL only the needed size for buffer is returned.
 * buflen gives the max size of buffer. If the buffer is too shourt to
 * hold the complete digest, the buffer is filled with as many bytes are
 * possible and this value is returned.
 */
#if 0
static int
md_digest( GCRY_MD_HD a, int algo, byte *buffer, int buflen )
{
    struct md_digest_list_s *r = NULL;
    char *context;
    char *digest;

    if( a->bufpos )
	md_write( a, NULL, 0 );

    if( !algo ) {  /* return digest for the first algorithm */
	if( (r=a->ctx->list) && r->next )
	    log_debug("more than algorithm in md_digest(0)\n");
    }
    else {
	for(r=a->ctx->list; r; r = r->next )
	    if( r->algo == algo )
		break;
    }
    if( !r )
	BUG();

    if( !buffer )
	return r->mdlen;

    /* I don't want to change the interface, so I simply work on a copy
     * of the context (extra overhead - should be fixed)*/
    context = a->ctx->secure ? g10_xmalloc_secure( r->contextsize )
			     : g10_xmalloc( r->contextsize );
    memcpy( context, r->context.c, r->contextsize );
    (*r->final)( context );
    digest = (*r->read)( context );

    if( buflen > r->mdlen )
	buflen = r->mdlen;
    memcpy( buffer, digest, buflen );

    g10_free(context);
    return buflen;
}
#endif

/****************
 * Read out an intermediate digest.
 */
int
gcry_md_get( GCRY_MD_HD hd, int algo, byte *buffer, int buflen )
{
    /*md_digest ... */
    return GCRYERR_INTERNAL;
}


/****************
 * Shortcut function to hash a buffer with a given algo. The only supported
 * algorithm is RIPE-MD. The supplied digest buffer must be large enough
 * to store the resulting hash.  No error is returned, the function will
 * abort on an invalite algo.  DISABLED_ALGOS are ignored here.
 */
void
gcry_md_hash_buffer( int algo, char *digest, const char *buffer, size_t length)
{
    if( algo == GCRY_MD_RMD160 )
	rmd160_hash_buffer( digest, buffer, length );
    else
	BUG();
}

static int
md_get_algo( GCRY_MD_HD a )
{
    struct md_digest_list_s *r;

    if( (r=a->ctx->list) ) {
	if( r->next )
	    log_error("WARNING: more than algorithm in md_get_algo()\n");
	return r->algo;
    }
    return 0;
}


int
gcry_md_get_algo( GCRY_MD_HD hd )
{
    return md_get_algo( hd ); /* fixme: we need error handling */
}


/****************
 * Return the length of the digest
 */
static int
md_digest_length( int algo )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next ) {
	    if( r->algo == algo )
		return r->mdlen;
	}
    } while( !r && load_digest_module( algo ) );
    return 0;
}

/****************
 * Return the length of the digest in bytes.
 * This function will return 0 in case of errors.
 */
unsigned int
gcry_md_get_algo_dlen( int algo )
{
    /* we do some very quick checks here */
    switch( algo )
    {
      case GCRY_MD_MD5: return 16;
      case GCRY_MD_SHA1:
      case GCRY_MD_RMD160: return 20;
      default: {
	    int len = md_digest_length( algo );
	    if( !len )
		set_lasterr( GCRYERR_INV_MD_ALGO );
	    return 0;
	}
    }
}


/* Hmmm: add a mode to enumerate the OIDs
 *	to make g10/sig-check.c more portable */
static const byte *
md_asn_oid( int algo, size_t *asnlen, size_t *mdlen )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next ) {
	    if( r->algo == algo ) {
		if( asnlen )
		    *asnlen = r->asnlen;
		if( mdlen )
		    *mdlen = r->mdlen;
		return r->asnoid;
	    }
	}
    } while( !r && load_digest_module( algo ) );
    log_bug("no asn for md algo %d\n", algo);
    return NULL;
}



/****************
 * Return information about the given cipher algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_GET_ASNOID:
 *	Return the ASNOID of the algorithm in buffer. if buffer is NULL, only
 *	the required length is returned.
 *
 * On error the value -1 is returned and the error reason may be
 * retrieved by gcry_errno().
 * Note:  Because this function is in most caes used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
int
gcry_md_algo_info( int algo, int what, void *buffer, size_t *nbytes)
{
    switch( what ) {
      case GCRYCTL_TEST_ALGO:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_ARG );
	    return -1;
	}
	if( check_digest_algo( algo ) ) {
	    set_lasterr( GCRYERR_INV_MD_ALGO );
	    return -1;
	}
	break;

      case GCRYCTL_GET_ASNOID: {
	    size_t asnlen;
	    const char *asn = md_asn_oid( algo, &asnlen, NULL );
	    if( buffer && *nbytes >= asnlen ) {
		memcpy( buffer, asn, asnlen );
		*nbytes = asnlen;
		return 0;
	    }
	    if( !buffer && nbytes ) {
		*nbytes = asnlen;
		return 0;
	    }
	    set_lasterr( buffer ? GCRYERR_TOO_SHORT : GCRYERR_INV_ARG );
	    return -1;
	}
	break;

      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
}




void
md_start_debug( GCRY_MD_HD md, const char *suffix )
{
    static int idx=0;
    char buf[25];

    if( md->ctx->debug ) {
	log_debug("Oops: md debug already started\n");
	return;
    }
    idx++;
    sprintf(buf, "dbgmd-%05d.%.10s", idx, suffix );
    md->ctx->debug = fopen(buf, "w");
    if( !md->ctx->debug )
	log_debug("md debug: can't open %s\n", buf );
}

void
md_stop_debug( GCRY_MD_HD md )
{
    if( md->ctx->debug ) {
	if( md->bufpos )
	    md_write( md, NULL, 0 );
	fclose(md->ctx->debug);
	md->ctx->debug = NULL;
    }
  #ifdef HAVE_U64_TYPEDEF
    {  /* a kludge to pull in the __muldi3 for Solaris */
       volatile u32 a = (u32)(ulong)md;
       volatile u64 b = 42;
       volatile u64 c;
       c = a * b;
    }
  #endif
}



/****************
 * Return information about the digest handle.
 *  GCRYCTL_IS_SECURE:
 *	Returns 1 when the handle works on secured memory
 *	otherwise 0 is returned.  There is no error return.
 */
int
gcry_md_info( GCRY_MD_HD h, int cmd, void *buffer, size_t *nbytes)
{
    switch( cmd ) {
      case GCRYCTL_IS_SECURE:
	return h->ctx->secure;

      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
}

