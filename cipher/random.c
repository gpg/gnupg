/* random.c  -	random number generator
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


/****************
 * This random number generator is modelled after the one described
 * in Peter Gutmann's Paper: "Software Generation of Practically
 * Strong Random Numbers".
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "util.h"
#include "rmd.h"
#include "ttyio.h"
#include "i18n.h"
#include "rand-internal.h"


#if SIZEOF_UNSIGNED_LONG == 8
  #define ADD_VALUE 0xa5a5a5a5a5a5a5a5
#elif SIZEOF_UNSIGNED_LONG == 4
  #define ADD_VALUE 0xa5a5a5a5
#else
  #error weird size for an unsigned long
#endif

struct cache {
    int len;
    int size;
    byte *buffer;
};


static int is_initialized;
static struct cache cache[3];
#define MASK_LEVEL(a) do {if( a > 2 ) a = 2; else if( a < 0 ) a = 0; } while(0)
static char *rndpool;	/* allocated size is POOLSIZE+BLOCKLEN */
static char *keypool;	/* allocated size is POOLSIZE+BLOCKLEN */
static size_t pool_readpos;
static size_t pool_writepos;
static int pool_filled;
static int pool_balance;
static int just_mixed;

static int secure_alloc;
static int quick_test;


static void read_pool( byte *buffer, size_t length, int level );


static void
initialize()
{
    /* The data buffer is allocated somewhat larger, so that
     * we can use this extra space (which is allocated in secure memory)
     * as a temporary hash buffer */
    rndpool = secure_alloc ? m_alloc_secure_clear(POOLSIZE+BLOCKLEN)
			   : m_alloc_clear(POOLSIZE+BLOCKLEN);
    keypool = secure_alloc ? m_alloc_secure_clear(POOLSIZE+BLOCKLEN)
			   : m_alloc_clear(POOLSIZE+BLOCKLEN);
    is_initialized = 1;
}

void
secure_random_alloc()
{
    secure_alloc = 1;
}


int
quick_random_gen( int onoff )
{
    int last = quick_test;
    if( onoff != -1 )
	quick_test = onoff;
  #ifdef USE_RAND_DUMMY
    last = 1; /* insecure RNG */
  #endif
    return last;
}


/****************
 * Fill the buffer with LENGTH bytes of cryptographically strong
 * random bytes. level 0 is not very strong, 1 is strong enough
 * for most usage, 2 is good for key generation stuff but may be very slow.
 */
void
randomize_buffer( byte *buffer, size_t length, int level )
{
    for( ; length; length-- )
	*buffer++ = get_random_byte(level);
}


byte
get_random_byte( int level )
{
    MASK_LEVEL(level);
    if( !cache[level].len ) {
	if( !is_initialized )
	    initialize();
	if( !cache[level].buffer ) {
	    cache[level].size = 100;
	    cache[level].buffer = level && secure_alloc?
					 m_alloc_secure( cache[level].size )
				       : m_alloc( cache[level].size );
	}
	read_pool(cache[level].buffer, cache[level].size, level );
	cache[level].len = cache[level].size;
    }

    return cache[level].buffer[--cache[level].len];
}



/****************
 * Return a pointer to a randomized buffer of level 0 and LENGTH bits
 * caller must free the buffer. This function does not use the
 * cache (will be removed in future). Note: The returned value is
 * rounded up to bytes.
 */
byte *
get_random_bits( size_t nbits, int level, int secure )
{
    byte *buf;
    size_t nbytes = (nbits+7)/8;

    MASK_LEVEL(level);
    buf = secure? m_alloc_secure( nbytes ) : m_alloc( nbytes );
    read_pool( buf, nbytes, level );
    return buf;
}


/****************
 * Mix the pool
 */
static void
mix_pool(byte *pool)
{
    char *hashbuf = pool + POOLSIZE;
    char *p, *pend;
    int i, n;
    RMD160_CONTEXT md;

    rmd160_init( &md );
 #if DIGESTLEN != 20
    #error must have a digest length of 20 for ripe-md-160
 #endif
    /* loop over the pool */
    pend = pool + POOLSIZE;
    memcpy(hashbuf, pend - DIGESTLEN, DIGESTLEN );
    memcpy(hashbuf+DIGESTLEN, pool, BLOCKLEN-DIGESTLEN);
    rmd160_mixblock( &md, hashbuf);
    memcpy(pool, hashbuf, 20 );

    p = pool;
    for( n=1; n < POOLBLOCKS; n++ ) {
	memcpy(hashbuf, p, DIGESTLEN );

	p += DIGESTLEN;
	if( p+DIGESTLEN+BLOCKLEN < pend )
	    memcpy(hashbuf+DIGESTLEN, p+DIGESTLEN, BLOCKLEN-DIGESTLEN);
	else {
	    char *pp = p+DIGESTLEN;
	    for(i=DIGESTLEN; i < BLOCKLEN; i++ ) {
		if( pp >= pend )
		    pp = pool;
		hashbuf[i] = *pp++;
	    }
	}

	rmd160_mixblock( &md, hashbuf);
	memcpy(p, hashbuf, 20 );
    }
}


static void
read_pool( byte *buffer, size_t length, int level )
{
    int i;
    ulong *sp, *dp;

    if( length >= POOLSIZE )
	BUG(); /* not allowed */
    if( !level ) { /* read simple random bytes */
	read_random_source( buffer, length, level );
	return;
    }

    /* for level 2 make sure that there is enough random in the pool */
    if( level == 2 && pool_balance < length ) {
	size_t needed;
	byte *p;

	if( pool_balance < 0 )
	    pool_balance = 0;
	needed = length - pool_balance;
	if( needed > POOLSIZE )
	    BUG();
	p = m_alloc_secure( needed );
	read_random_source( p, needed, 2 ); /* read /dev/random */
	add_randomness( p, needed, 3);
	m_free(p);
	pool_balance += needed;
    }

    /* make sure the pool is filled */
    while( !pool_filled )
	random_poll();
    /* do always a fast random poll */
    fast_random_poll();

    /* mix the pool (if add_randomness() didn't it) */
    if( !just_mixed )
	mix_pool(rndpool);

    /* create a new pool */
    for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				i < POOLWORDS; i++, dp++, sp++ )
	*dp = *sp + ADD_VALUE;
    /* and mix both pools */
    mix_pool(rndpool);
    mix_pool(keypool);
    /* read the required data
     * we use a readpoiter to read from a different postion each
     * time */
    while( length-- ) {
	*buffer++ = keypool[pool_readpos++];
	if( pool_readpos >= POOLSIZE )
	    pool_readpos = 0;
	pool_balance--;
    }
    if( pool_balance < 0 )
	pool_balance = 0;
    /* and clear the keypool */
    memset( keypool, 0, POOLSIZE );
}


/****************
 * Add LENGTH bytes of randomness from buffer to the pool.
 * source may be used to specify the randomeness source.
 */
void
add_randomness( const void *buffer, size_t length, int source )
{
    if( !is_initialized )
	initialize();
    while( length-- ) {
	rndpool[pool_writepos++] = *((byte*)buffer)++;
	if( pool_writepos >= POOLSIZE ) {
	    if( source > 1 )
		pool_filled = 1;
	    pool_writepos = 0;
	    mix_pool(rndpool);
	    just_mixed = !length;
	}
    }
}



