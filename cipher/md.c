/* md.c  -  message digest dispatcher
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
#include <assert.h>
#include "util.h"
#include "cipher.h"
#include "errors.h"
#include "dynload.h"
#include "rmd.h"


/****************
 * This structure is used for the list of available algorithms
 * and for the list of algorithms in MD_HANDLE.
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

    r = m_alloc_clear( sizeof *r );
    r->algo = algo,
    r->name = (*get_info)( algo, &r->contextsize,
			   &r->asnoid, &r->asnlen, &r->mdlen,
			   &r->init, &r->write, &r->final, &r->read );
    if( !r->name ) {
	m_free(r);
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
string_to_digest_algo( const char *string )
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
const char *
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


int
check_digest_algo( int algo )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next )
	    if( r->algo == algo )
		return 0;
    } while( !r && load_digest_module(algo) );
    return G10ERR_DIGEST_ALGO;
}



/****************
 * Open a message digest handle for use with algorithm ALGO.
 * More algorithms may be added by md_enable(). The initial algorithm
 * may be 0.
 */
MD_HANDLE
md_open( int algo, int secure )
{
    MD_HANDLE hd;
    int bufsize;

    if( secure ) {
	bufsize = 512 - sizeof( *hd );
	hd = m_alloc_secure_clear( sizeof *hd + bufsize );
    }
    else {
	bufsize = 1024 - sizeof( *hd );
	hd = m_alloc_clear( sizeof *hd + bufsize );
    }

    hd->bufsize = bufsize+1; /* hd has already one byte allocated */
    hd->secure = secure;
    if( algo )
	md_enable( hd, algo );
    fast_random_poll();
    return hd;
}

void
md_enable( MD_HANDLE h, int algo )
{
    struct md_digest_list_s *r, *ac;

    for( ac=h->list; ac; ac = ac->next )
	if( ac->algo == algo )
	    return ; /* already enabled */
    /* find the algorithm */
    do {
	for(r = digest_list; r; r = r->next )
	    if( r->algo == algo )
		break;
    } while( !r && load_digest_module( algo ) );
    if( !r ) {
	log_error("md_enable: algorithm %d not available\n", algo );
	return;
    }
    /* and allocate a new list entry */
    ac = h->secure? m_alloc_secure( sizeof *ac + r->contextsize
					       - sizeof(r->context) )
		  : m_alloc( sizeof *ac + r->contextsize
					       - sizeof(r->context) );
    *ac = *r;
    ac->next = h->list;
    h->list = ac;
    /* and init this instance */
    (*ac->init)( &ac->context.c );
}


MD_HANDLE
md_copy( MD_HANDLE a )
{
    MD_HANDLE b;
    struct md_digest_list_s *ar, *br;

    if( a->bufcount )
	md_write( a, NULL, 0 );
    b = a->secure ? m_alloc_secure( sizeof *b + a->bufsize - 1 )
		  : m_alloc( sizeof *b + a->bufsize - 1 );
    memcpy( b, a, sizeof *a + a->bufsize - 1 );
    b->list = NULL;
    b->debug = NULL;
    /* and now copy the complete list of algorithms */
    /* I know that the copied list is reversed, but that doesn't matter */
    for( ar=a->list; ar; ar = ar->next ) {
	br = a->secure ? m_alloc_secure( sizeof *br + ar->contextsize
					       - sizeof(ar->context) )
		       : m_alloc( sizeof *br + ar->contextsize
					       - sizeof(ar->context) );
	memcpy( br, ar, sizeof(*br) + ar->contextsize
				    - sizeof(ar->context) );
	br->next = b->list;
	b->list = br;
    }

    if( a->debug )
	md_start_debug( b, "unknown" );
    return b;
}


/****************
 * Reset all contexts and discard any buffered stuff.  This may be used
 * instead of a md_close(); md_open().
 */
void
md_reset( MD_HANDLE a )
{
    struct md_digest_list_s *r;

    a->bufcount = a->finalized = 0;
    for( r=a->list; r; r = r->next ) {
	memset( r->context.c, 0, r->contextsize );
	(*r->init)( &r->context.c );
    }
}


void
md_close(MD_HANDLE a)
{
    struct md_digest_list_s *r, *r2;

    if( !a )
	return;
    if( a->debug )
	md_stop_debug(a);
    for(r=a->list; r; r = r2 ) {
	r2 = r->next;
	m_free(r);
    }
    m_free(a);
}


void
md_write( MD_HANDLE a, byte *inbuf, size_t inlen)
{
    struct md_digest_list_s *r;

    if( a->debug ) {
	if( a->bufcount && fwrite(a->buffer, a->bufcount, 1, a->debug ) != 1 )
	    BUG();
	if( inlen && fwrite(inbuf, inlen, 1, a->debug ) != 1 )
	    BUG();
    }
    for(r=a->list; r; r = r->next ) {
	(*r->write)( &r->context.c, a->buffer, a->bufcount );
	(*r->write)( &r->context.c, inbuf, inlen );
    }
    a->bufcount = 0;
}



void
md_final(MD_HANDLE a)
{
    struct md_digest_list_s *r;

    if( a->finalized )
	return;

    if( a->bufcount )
	md_write( a, NULL, 0 );

    for(r=a->list; r; r = r->next ) {
	(*r->final)( &r->context.c );
    }
    a->finalized = 1;
}


/****************
 * if ALGO is null get the digest for the used algo (which should be only one)
 */
byte *
md_read( MD_HANDLE a, int algo )
{
    struct md_digest_list_s *r;

    if( !algo ) {  /* return the first algorithm */
	if( (r=a->list) ) {
	    if( r->next )
		log_debug("more than algorithm in md_read(0)\n");
	    return (*r->read)( &r->context.c );
	}
    }
    else {
	for(r=a->list; r; r = r->next )
	    if( r->algo == algo )
		return (*r->read)( &r->context.c );
    }
    BUG();
    return NULL;
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
int
md_digest( MD_HANDLE a, int algo, byte *buffer, int buflen )
{
    struct md_digest_list_s *r = NULL;
    char *context;
    char *digest;

    if( a->bufcount )
	md_write( a, NULL, 0 );

    if( !algo ) {  /* return digest for the first algorithm */
	if( (r=a->list) && r->next )
	    log_debug("more than algorithm in md_digest(0)\n");
    }
    else {
	for(r=a->list; r; r = r->next )
	    if( r->algo == algo )
		break;
    }
    if( !r )
	BUG();

    if( !buffer )
	return r->mdlen;

    /* I don't want to change the interface, so I simply work on a copy
     * the context (extra overhead - should be fixed)*/
    context = a->secure ? m_alloc_secure( r->contextsize )
			: m_alloc( r->contextsize );
    memcpy( context, r->context.c, r->contextsize );
    (*r->final)( context );
    digest = (*r->read)( context );

    if( buflen > r->mdlen )
	buflen = r->mdlen;
    memcpy( buffer, digest, buflen );

    m_free(context);
    return buflen;
}


int
md_get_algo( MD_HANDLE a )
{
    struct md_digest_list_s *r;

    if( (r=a->list) ) {
	if( r->next )
	    log_error("WARNING: more than algorithm in md_get_algo()\n");
	return r->algo;
    }
    return 0;
}

/****************
 * Return the length of the digest
 */
int
md_digest_length( int algo )
{
    struct md_digest_list_s *r;

    do {
	for(r = digest_list; r; r = r->next ) {
	    if( r->algo == algo )
		return r->mdlen;
	}
    } while( !r && load_digest_module( algo ) );
    log_error("WARNING: no length for md algo %d\n", algo);
    return 0;
}


/* Hmmm: add a mode to enumerate the OIDs
 *	to make g10/sig-check.c more portable */
const byte *
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


void
md_start_debug( MD_HANDLE md, const char *suffix )
{
    static int idx=0;
    char buf[25];

    if( md->debug ) {
	log_debug("Oops: md debug already started\n");
	return;
    }
    idx++;
    sprintf(buf, "dbgmd-%05d.%.10s", idx, suffix );
    md->debug = fopen(buf, "w");
    if( !md->debug )
	log_debug("md debug: can't open %s\n", buf );
}

void
md_stop_debug( MD_HANDLE md )
{
    if( md->debug ) {
	if( md->bufcount )
	    md_write( md, NULL, 0 );
	fclose(md->debug);
	md->debug = NULL;
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

