/* random.c  -	random number generator
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef	HAVE_GETHRTIME
  #include <sys/times.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
  #include <sys/times.h>
#endif
#ifdef HAVE_GETRUSAGE
  #include <sys/resource.h>
#endif
#include "g10lib.h"
#include "rmd.h"
#include "ttyio.h"
#include "random.h"
#include "rand-internal.h"
#include "dynload.h"


#ifndef RAND_MAX   /* for SunOS */
  #define RAND_MAX 32767
#endif


#if SIZEOF_UNSIGNED_LONG == 8
  #define ADD_VALUE 0xa5a5a5a5a5a5a5a5
#elif SIZEOF_UNSIGNED_LONG == 4
  #define ADD_VALUE 0xa5a5a5a5
#else
  #error weird size for an unsigned long
#endif

#define BLOCKLEN  64   /* hash this amount of bytes */
#define DIGESTLEN 20   /* into a digest of this length (rmd160) */
/* poolblocks is the number of digests which make up the pool
 * and poolsize must be a multiple of the digest length
 * to make the AND operations faster, the size should also be
 * a multiple of ulong
 */
#define POOLBLOCKS 30
#define POOLSIZE (POOLBLOCKS*DIGESTLEN)
#if (POOLSIZE % SIZEOF_UNSIGNED_LONG)
  #error Please make sure that poolsize is a multiple of ulong
#endif
#define POOLWORDS (POOLSIZE / SIZEOF_UNSIGNED_LONG)


static int is_initialized;
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
static int faked_rng;


static byte *get_random_bytes( size_t nbytes, int level, int secure );
static void read_pool( byte *buffer, size_t length, int level );
static void add_randomness( const void *buffer, size_t length, int source );
static void random_poll(void);
static void read_random_source( int requester, size_t length, int level);
static int gather_faked( void (*add)(const void*, size_t, int), int requester,
						    size_t length, int level );

static struct {
    ulong mixrnd;
    ulong mixkey;
    ulong slowpolls;
    ulong fastpolls;
    ulong getbytes1;
    ulong ngetbytes1;
    ulong getbytes2;
    ulong ngetbytes2;
    ulong addbytes;
    ulong naddbytes;
} rndstats;

static void
initialize(void)
{
    /* The data buffer is allocated somewhat larger, so that
     * we can use this extra space (which is allocated in secure memory)
     * as a temporary hash buffer */
    rndpool = secure_alloc ? g10_xcalloc_secure(1,POOLSIZE+BLOCKLEN)
			   : g10_xcalloc(1,POOLSIZE+BLOCKLEN);
    keypool = secure_alloc ? g10_xcalloc_secure(1,POOLSIZE+BLOCKLEN)
			   : g10_xcalloc(1,POOLSIZE+BLOCKLEN);
    is_initialized = 1;
    cipher_modules_constructor();
}


void
random_dump_stats()
{
    fprintf(stderr,
	    "random usage: poolsize=%d mixed=%lu polls=%lu/%lu added=%lu/%lu\n"
	    "              outmix=%lu getlvl1=%lu/%lu getlvl2=%lu/%lu\n",
	POOLSIZE, rndstats.mixrnd, rndstats.slowpolls, rndstats.fastpolls,
		  rndstats.naddbytes, rndstats.addbytes,
	rndstats.mixkey, rndstats.ngetbytes1, rndstats.getbytes1,
		    rndstats.ngetbytes2, rndstats.getbytes2 );
}

void
secure_random_alloc()
{
    secure_alloc = 1;
}


int
quick_random_gen( int onoff )
{
    int last;

    read_random_source(0,0,0); /* init */
    last = quick_test;
    if( onoff != -1 )
	quick_test = onoff;
    return faked_rng? 1 : last;
}


/****************
 * Fill the buffer with LENGTH bytes of cryptographically strong
 * random bytes. level 0 is not very strong, 1 is strong enough
 * for most usage, 2 is good for key generation stuff but may be very slow.
 */
void
gcry_randomize( byte *buffer, size_t length, enum gcry_random_level level )
{
    char *p = get_random_bytes( length, level, 1 );
    memcpy( buffer, p, length );
    g10_free(p);
}


int
random_is_faked()
{
    if( !is_initialized )
	initialize();
    return faked_rng || quick_test;
}

/****************
 * Return a pointer to a randomized buffer of level 0 and LENGTH bits
 * caller must free the buffer.
 * Note: The returned value is rounded up to bytes.
 */
static byte *
get_random_bytes( size_t nbytes, int level, int secure )
{
    byte *buf, *p;

    if( quick_test && level > 1 )
	level = 1;
    MASK_LEVEL(level);
    if( level == 1 ) {
	rndstats.getbytes1 += nbytes;
	rndstats.ngetbytes1++;
    }
    else if( level >= 2 ) {
	rndstats.getbytes2 += nbytes;
	rndstats.ngetbytes2++;
    }

    buf = secure && secure_alloc ? g10_xmalloc_secure( nbytes )
				 : g10_xmalloc( nbytes );
    for( p = buf; nbytes > 0; ) {
	size_t n = nbytes > POOLSIZE? POOLSIZE : nbytes;
	read_pool( p, n, level );
	nbytes -= n;
	p += n;
    }
    return buf;
}

void *
gcry_random_bytes( size_t nbytes, enum gcry_random_level level )
{
    return get_random_bytes( nbytes, level, 0 );
}

void *
gcry_random_bytes_secure( size_t nbytes, enum gcry_random_level level )
{
    return get_random_bytes( nbytes, level, 1 );
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

    /* for level 2 make sure that there is enough random in the pool */
    if( level == 2 && pool_balance < length ) {
	size_t needed;

	if( pool_balance < 0 )
	    pool_balance = 0;
	needed = length - pool_balance;
	if( needed > POOLSIZE )
	    BUG();
	read_random_source( 3, needed, 2 );
	pool_balance += needed;
    }

    /* make sure the pool is filled */
    while( !pool_filled )
	random_poll();

    /* do always a fast random poll */
    fast_random_poll();

    if( !level ) { /* no need for cryptographic strong random */
	/* create a new pool */
	for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				    i < POOLWORDS; i++, dp++, sp++ )
	    *dp = *sp + ADD_VALUE;
	/* must mix both pools */
	mix_pool(rndpool); rndstats.mixrnd++;
	mix_pool(keypool); rndstats.mixkey++;
	memcpy( buffer, keypool, length );
    }
    else {
	/* mix the pool (if add_randomness() didn't it) */
	if( !just_mixed ) {
	    mix_pool(rndpool);
	    rndstats.mixrnd++;
	}
	/* create a new pool */
	for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				    i < POOLWORDS; i++, dp++, sp++ )
	    *dp = *sp + ADD_VALUE;
	/* and mix both pools */
	mix_pool(rndpool); rndstats.mixrnd++;
	mix_pool(keypool); rndstats.mixkey++;
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
}


/****************
 * Add LENGTH bytes of randomness from buffer to the pool.
 * source may be used to specify the randomness source.
 */
static void
add_randomness( const void *buffer, size_t length, int source )
{
    const byte *p = buffer;

    if( !is_initialized )
	initialize();
    rndstats.addbytes += length;
    rndstats.naddbytes++;
    while( length-- ) {
	rndpool[pool_writepos++] = *p++;
	if( pool_writepos >= POOLSIZE ) {
	    if( source > 1 )
		pool_filled = 1;
	    pool_writepos = 0;
	    mix_pool(rndpool); rndstats.mixrnd++;
	    just_mixed = !length;
	}
    }
}



static void
random_poll()
{
    rndstats.slowpolls++;
    read_random_source( 2, POOLSIZE/5, 1 );
}


void
fast_random_poll()
{
    static void (*fnc)( void (*)(const void*, size_t, int), int) = NULL;
    static int initialized = 0;

    rndstats.fastpolls++;
    if( !initialized ) {
	if( !is_initialized )
	    initialize();
	initialized = 1;
	fnc = dynload_getfnc_fast_random_poll();
    }
    if( fnc ) {
	(*fnc)( add_randomness, 1 );
	return;
    }

    /* fall back to the generic function */
  #if HAVE_GETHRTIME
    {	hrtime_t tv;
	tv = gethrtime();
	add_randomness( &tv, sizeof(tv), 1 );
    }
  #elif HAVE_GETTIMEOFDAY
    {	struct timeval tv;
	if( gettimeofday( &tv, NULL ) )
	    BUG();
	add_randomness( &tv.tv_sec, sizeof(tv.tv_sec), 1 );
	add_randomness( &tv.tv_usec, sizeof(tv.tv_usec), 1 );
    }
  #else /* use times */
    #ifndef HAVE_DOSISH_SYSTEM
    {	struct tms buf;
	times( &buf );
	add_randomness( &buf, sizeof buf, 1 );
    }
    #endif
  #endif
  #ifdef HAVE_GETRUSAGE
    {	struct rusage buf;
	if( getrusage( RUSAGE_SELF, &buf ) )
	    BUG();
	add_randomness( &buf, sizeof buf, 1 );
	memset( &buf, 0, sizeof buf );
    }
  #endif
}



static void
read_random_source( int requester, size_t length, int level )
{
    static int (*fnc)(void (*)(const void*, size_t, int), int,
						    size_t, int) = NULL;
    if( !fnc ) {
	if( !is_initialized )
	    initialize();
	fnc = dynload_getfnc_gather_random();
	if( !fnc ) {
	    faked_rng = 1;
	    fnc = gather_faked;
	}
	if( !requester && !length && !level )
	    return; /* init only */
    }
    if( (*fnc)( add_randomness, requester, length, level ) < 0 )
	log_fatal("No way to gather entropy for the RNG\n");
}


static int
gather_faked( void (*add)(const void*, size_t, int), int requester,
	      size_t length, int level )
{
    static int initialized=0;
    size_t n;
    char *buffer, *p;

    if( !initialized ) {
	log_info(_("WARNING: using insecure random number generator!!\n"));
	/* we can't use tty_printf here - do we need this function at
	  all - does it really make sense or canit be viewed as a potential
	  security problem ? wk 17.11.99 */
	#warning Extended warning disabled
      #if 0
	tty_printf(_("The random number generator is only a kludge to let\n"
		   "it run - it is in no way a strong RNG!\n\n"
		   "DON'T USE ANY DATA GENERATED BY THIS PROGRAM!!\n\n"));
      #endif
	initialized=1;
      #ifdef HAVE_RAND
	srand( time(NULL) * getpid());
      #else
	srandom( time(NULL) * getpid());
      #endif
    }

    p = buffer = g10_xmalloc( length );
    n = length;
  #ifdef HAVE_RAND
    while( n-- )
	*p++ = ((unsigned)(1 + (int) (256.0*rand()/(RAND_MAX+1.0)))-1);
  #else
    while( n-- )
	*p++ = ((unsigned)(1 + (int) (256.0*random()/(RAND_MAX+1.0)))-1);
  #endif
    add_randomness( buffer, length, requester );
    g10_free(buffer);
    return 0; /* okay */
}

