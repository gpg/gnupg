/* md.c  -  message digest dispatcher
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

#define DEFINES_MD_HANDLE 1

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "util.h"
#include "cipher.h"
#include "errors.h"
#include "dynload.h"
#include "md5.h"
#include "sha1.h"
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
    char context[1];
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
 * Put the static entries into the table.
 */
static void
setup_digest_list()
{
    struct md_digest_list_s *r;

    r = new_list_item( DIGEST_ALGO_MD5, md5_get_info );
    if( r ) { r->next = digest_list; digest_list = r; }

    r = new_list_item( DIGEST_ALGO_RMD160, rmd160_get_info );
    if( r ) { r->next = digest_list; digest_list = r; }

    r = new_list_item( DIGEST_ALGO_SHA1, sha1_get_info );
    if( r ) { r->next = digest_list; digest_list = r; }
}


/****************
 * Try to load all modules and return true if new modules are available
 */
static int
load_digest_modules()
{
    static int done = 0;
    static int initialized = 0;
    struct md_digest_list_s *r;
    void *context = NULL;
    int algo;
    int any = 0;
    const char *(*get_info)( int, size_t*,byte**, int*, int*,
			    void (**)(void*),
			    void (**)(void*,byte*,size_t),
			    void (**)(void*),byte *(**)(void*));

    if( !initialized ) {
	setup_digest_list(); /* load static modules on the first call */
	initialized = 1;
	return 1;
    }

    if( done )
	return 0;
    done = 1;

    while( enum_gnupgext_digests( &context, &algo, &get_info ) ) {
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
    } while( !r && load_digest_modules() );
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
    } while( !r && load_digest_modules() );
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
    } while( !r && load_digest_modules() );
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
    hd = secure ? m_alloc_secure_clear( sizeof *hd )
		: m_alloc_clear( sizeof *hd );
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
    } while( !r && load_digest_modules() );
    if( !r ) {
	log_error("md_enable: algorithm %d not available\n", algo );
	return;
    }
    /* and allocate a new list entry */
    ac = h->secure? m_alloc_secure( sizeof *ac + r->contextsize )
		  : m_alloc( sizeof *ac + r->contextsize );
    *ac = *r;
    ac->next = h->list;
    h->list = ac;
    /* and init this instance */
    (*ac->init)( &ac->context );
}


MD_HANDLE
md_copy( MD_HANDLE a )
{
    MD_HANDLE b;
    struct md_digest_list_s *ar, *br;

    b = a->secure ? m_alloc_secure( sizeof *b )
		  : m_alloc( sizeof *b );
    memcpy( b, a, sizeof *a );
    b->list = NULL;
    /* and now copy the compelte list of algorithms */
    /* I know that the copied list is reversed, but that doesn't matter */
    for( ar=a->list; ar; ar = ar->next ) {
	br = a->secure ? m_alloc_secure( sizeof *br + ar->contextsize )
		       : m_alloc( sizeof *br + ar->contextsize );
	memcpy( br, ar, sizeof(*br) + ar->contextsize );
	br->next = b->list;
	b->list = br;
    }
    return b;
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
	(*r->write)( &r->context, a->buffer, a->bufcount );
	(*r->write)( &r->context, inbuf, inlen );
    }
    a->bufcount = 0;
}



void
md_final(MD_HANDLE a)
{
    struct md_digest_list_s *r;

    if( a->bufcount )
	md_write( a, NULL, 0 );

    for(r=a->list; r; r = r->next ) {
	(*r->final)( &r->context );
    }
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
		log_error("warning: more than algorithm in md_read(0)\n");
	    return (*r->read)( &r->context );
	}
    }
    else {
	for(r=a->list; r; r = r->next )
	    if( r->algo == algo )
		return (*r->read)( &r->context );
    }
    BUG();
    return NULL;
}

int
md_get_algo( MD_HANDLE a )
{
    struct md_digest_list_s *r;

    if( (r=a->list) ) {
	if( r->next )
	    log_error("warning: more than algorithm in md_get_algo()\n");
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
    } while( !r && load_digest_modules() );
    log_error("warning: no length for md algo %d\n", algo);
    return 0;
}


/* fixme: add a mode to enumerate the OIDs
 *	  to make g10/sig-check.c more portable */
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
    } while( !r && load_digest_modules() );
    log_bug("warning: no asn for md algo %d\n", algo);
    return NULL;
}


void
md_start_debug( MD_HANDLE md, const char *suffix )
{
    static int index=0;
    char buf[25];

    if( md->debug ) {
	log_debug("Oops: md debug already started\n");
	return;
    }
    index++;
    sprintf(buf, "dbgmd-%05d.%.10s", index, suffix );
    md->debug = fopen(buf, "w");
    if( !md->debug )
	log_debug("md debug: can't open %s\n", buf );
}

void
md_stop_debug( MD_HANDLE md )
{
    if( md->debug ) {
	fclose(md->debug);
	md->debug = NULL;
    }
}

