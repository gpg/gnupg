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
 * How it works:
 *
 * See Peter Gutmann's Paper: "Software Generation of Practically
 * Strong Random Numbers"
 *
 * fixme!
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef HAVE_GETTIMEOFTIME
  #include <sys/times.h>
#endif
#ifdef HAVE_GETRUSAGE
  #include <sys/resource.h>
#endif
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "util.h"
#include "random.h"
#include "rmd.h"
#include "ttyio.h"
#include "i18n.h"


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
static int just_mixed;

static int secure_alloc;
static int quick_test;



static void read_pool( byte *buffer, size_t length, int level );
static void read_dev_random( byte *buffer, size_t length, int level );


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
  #ifndef HAVE_DEV_RANDOM
    last = 1; /* insecure RNG */
  #endif
    return last;
}


/****************
 * Fill the buffer with LENGTH bytes of cryptologic strong
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
	read_dev_random( buffer, length, level );
	return;
    }

    /* always do a random poll if we need strong numbers */
    if( pool_filled && level == 2 )
	random_poll();
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
    }
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
	    pool_filled = 1;
	    pool_writepos = 0;
	    mix_pool(rndpool);
	    just_mixed = !length;
	}
    }
}



/********************
 *  FIXME: move these functions to rand_unix.c
 */

void
random_poll()
{
    char buf[POOLSIZE/5];
    read_dev_random( buf, POOLSIZE/5, 1 ); /* read /dev/urandom */
    add_randomness( buf, POOLSIZE/5, 2);
    memset( buf, 0, POOLSIZE/5);
}


void
fast_random_poll()
{
  #ifdef HAVE_GETTIMEOFTIME
    {	struct timeval tv;
	if( gettimeofday( &tv, NULL ) )
	    BUG();
	add_randomness( &tv.tv_sec, sizeof(tv.tv_sec), 1 );
	add_randomness( &tv.tv_usec, sizeof(tv.tv_usec), 1 );
    }
  #else /* use times */
    {	struct tms buf;
	times( &buf );
	add_randomness( &buf, sizeof buf, 1 );
    }
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


#ifdef HAVE_DEV_RANDOM

static int
open_device( const char *name, int minor )
{
    int fd;
    struct stat sb;

    fd = open( name, O_RDONLY );
    if( fd == -1 )
	log_fatal("can't open %s: %s\n", name, strerror(errno) );
    if( fstat( fd, &sb ) )
	log_fatal("stat() off %s failed: %s\n", name, strerror(errno) );
  #if defined(__sparc__) && defined(__linux__)
    #warning something is wrong with UltraPenguin /dev/random
  #else
    if( !S_ISCHR(sb.st_mode) )
	log_fatal("invalid random device!\n" );
  #endif
    return fd;
}


static void
read_dev_random( byte *buffer, size_t length, int level )
{
    static int fd_urandom = -1;
    static int fd_random = -1;
    int fd;
    int n;
    int warn=0;

    if( level == 2 && !quick_test ) {
	if( fd_random == -1 )
	    fd_random = open_device( "/dev/random", 8 );
	fd = fd_random;
    }
    else {
	/* fixme: we should use a simpler one for level 0,
	 * because reading from /dev/urandom removes entropy
	 * and the next read on /dev/random may have to wait */
	if( fd_urandom == -1 )
	    fd_urandom = open_device( "/dev/urandom", 9 );
	fd = fd_urandom;
    }


    do {
	fd_set rfds;
	struct timeval tv;
	int rc;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if( !(rc=select(fd+1, &rfds, NULL, NULL, &tv)) ) {
	    if( !warn )
		tty_printf( _(
"\n"
"Not enough random bytes available.  Please do some other work to give\n"
"the OS a chance to collect more entropy! (Need %d more bytes)\n"), length );
	    warn = 1;
	    continue;
	}
	else if( rc == -1 ) {
	    tty_printf("select() error: %s\n", strerror(errno));
	    continue;
	}

	assert( length < 500 );
	do {
	    n = read(fd, buffer, length );
	    if( n >= 0 && n > length ) {
		log_error("bogus read from random device (n=%d)\n", n );
		n = length;
	    }
	} while( n == -1 && errno == EINTR );
	if( n == -1 )
	    log_fatal("read error on random device: %s\n", strerror(errno) );
	assert( n <= length );
	buffer += n;
	length -= n;
    } while( length );
}

#else /* not HAVE_DEV_RANDOM */


#ifndef RAND_MAX   /* for SunOS */
  #define RAND_MAX 32767
#endif

static void
read_dev_random( byte *buffer, size_t length, int level )
{
    static int initialized=0;

    if( !initialized ) {
	log_info(_("warning: using insecure random number generator!!\n"));
	tty_printf(_("The random number generator is only a kludge to let\n"
		   "it compile - it is in no way a strong RNG!\n\n"
		   "DON'T USE ANY DATA GENERATED BY THIS PROGRAM!!\n\n"));
	initialized=1;
      #ifdef HAVE_RAND
	srand(make_timestamp()*getpid());
      #else
	srandom(make_timestamp()*getpid());
      #endif
    }

  #ifdef HAVE_RAND
    while( length-- )
	*buffer++ = ((unsigned)(1 + (int) (256.0*rand()/(RAND_MAX+1.0)))-1);
  #else
    while( length-- )
	*buffer++ = ((unsigned)(1 + (int) (256.0*random()/(RAND_MAX+1.0)))-1);
  #endif
}

#endif

