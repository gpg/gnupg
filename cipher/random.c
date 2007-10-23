/* random.c  -	random number generator
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2003, 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include <time.h>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_GETHRTIME
#include <sys/times.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif
#ifdef HAVE_TIMES
#include <sys/times.h>
#endif
#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
#endif
#ifdef _WIN32
#include <process.h>
#endif
#include "util.h"
#include "rmd.h"
#include "ttyio.h"
#include "i18n.h"
#include "random.h"
#include "rand-internal.h"
#include "algorithms.h"

#ifndef RAND_MAX   /* for SunOS */
#define RAND_MAX 32767
#endif


/* Check whether we can lock the seed file read write. */
#if defined(HAVE_FCNTL) && defined(HAVE_FTRUNCATE) && !defined(HAVE_W32_SYSTEM)
#define LOCK_SEED_FILE 1
#else
#define LOCK_SEED_FILE 0
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
static int did_initial_extra_seeding;
static char *seed_file_name;
static int allow_seed_file_update;
static int no_seed_file_locking;

static int secure_alloc;
static int quick_test;
static int faked_rng;


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


static int (*
getfnc_gather_random (void))(void (*)(const void*, size_t, int), int,
                        size_t, int)
{
#ifdef USE_ALL_RANDOM_MODULES
  static int (*fnc)(void (*)(const void*, size_t, int), int, size_t, int);
  
  if (fnc)
    return fnc;
# ifdef USE_RNDLINUX
  if ( !access (NAME_OF_DEV_RANDOM, R_OK)
       && !access (NAME_OF_DEV_URANDOM, R_OK))
    {
      fnc = rndlinux_gather_random;
      return fnc;
    }
# endif
# ifdef USE_RNDEGD
  if ( rndegd_connect_socket (1) != -1 )
    {
      fnc = rndegd_gather_random;
      return fnc;
    }
# endif
# ifdef USE_RNDUNIX
  fnc = rndunix_gather_random;
  return fnc;
# endif

  log_fatal (_("no entropy gathering module detected\n"));

#else
# ifdef USE_RNDLINUX
  return rndlinux_gather_random;
# endif
# ifdef USE_RNDUNIX
  return rndunix_gather_random;
# endif
# ifdef USE_RNDEGD
  return rndegd_gather_random;
# endif
# ifdef USE_RNDW32
  return rndw32_gather_random;
# endif
# ifdef USE_RNDRISCOS
  return rndriscos_gather_random;
# endif
#endif
  return NULL;
}

static int (*
getfnc_fast_random_poll (void))( void (*)(const void*, size_t, int), int)
{
#ifdef USE_RNDW32
  return rndw32_gather_random_fast;
#endif
  return NULL;
}



static void
initialize(void)
{
    /* The data buffer is allocated somewhat larger, so that
     * we can use this extra space (which is allocated in secure memory)
     * as a temporary hash buffer */
    rndpool = secure_alloc ? xmalloc_secure_clear(POOLSIZE+BLOCKLEN)
			   : xmalloc_clear(POOLSIZE+BLOCKLEN);
    keypool = secure_alloc ? xmalloc_secure_clear(POOLSIZE+BLOCKLEN)
			   : xmalloc_clear(POOLSIZE+BLOCKLEN);
    is_initialized = 1;
}

static void
burn_stack (int bytes)
{
    char buf[128];
    
    wipememory(buf,sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        burn_stack (bytes);
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
secure_randoxmalloc()
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
randomize_buffer( byte *buffer, size_t length, int level )
{
    char *p = get_random_bits( length*8, level, 1 );
    memcpy( buffer, p, length );
    xfree(p);
}


int
random_is_faked()
{
    if( !is_initialized )
	initialize();
    return faked_rng || quick_test;
}

/* Disable locking of seed files. */
void 
random_disable_locking ()
{
  no_seed_file_locking = 1;
}

/****************
 * Return a pointer to a randomized buffer of level 0 and LENGTH bits
 * caller must free the buffer.
 * Note: The returned value is rounded up to bytes.
 */
byte *
get_random_bits( size_t nbits, int level, int secure )
{
    byte *buf, *p;
    size_t nbytes = (nbits+7)/8;

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

    buf = secure && secure_alloc ? xmalloc_secure( nbytes ) : xmalloc( nbytes );
    for( p = buf; nbytes > 0; ) {
	size_t n = nbytes > POOLSIZE? POOLSIZE : nbytes;
	read_pool( p, n, level );
	nbytes -= n;
	p += n;
    }
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
    burn_stack (384); /* for the rmd160_mixblock() */
}


void
set_random_seed_file( const char *name )
{
    if( seed_file_name )
	BUG();
    seed_file_name = xstrdup( name );
}


/* Lock an open file identified by file descriptor FD and wait a
   reasonable time to succeed.  With FOR_WRITE set to true a Rite lock
   will be taken.  FNAME is used only for diagnostics. Returns 0 on
   success or -1 on error. */
static int
lock_seed_file (int fd, const char *fname, int for_write)
{
#if LOCK_SEED_FILE
  struct flock lck;
  struct timeval tv;
  int backoff=0;

  if (no_seed_file_locking)
    return 0;
  
  /* We take a lock on the entire file. */
  memset (&lck, 0, sizeof lck);
  lck.l_type = for_write? F_WRLCK : F_RDLCK;
  lck.l_whence = SEEK_SET;

  while (fcntl (fd, F_SETLK, &lck) == -1)
    {
      if (errno != EAGAIN && errno != EACCES)
        {
          log_info (_("can't lock `%s': %s\n"), fname, strerror (errno));
          return -1;
        }

      if (backoff > 2) /* Show the first message after ~2.25 seconds. */
        log_info( _("waiting for lock on `%s'...\n"), fname);
      
      tv.tv_sec = backoff;
      tv.tv_usec = 250000;
      select (0, NULL, NULL, NULL, &tv);
      if (backoff < 10)
        backoff++ ;
    }
#endif /*LOCK_SEED_FILE*/
  return 0;
}



/****************
 * Read in a seed form the random_seed file
 * and return true if this was successful
 */
static int
read_seed_file(void)
{
    int fd;
    struct stat sb;
    unsigned char buffer[POOLSIZE];
    int n;

    if( !seed_file_name )
	return 0;

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
    fd = open( seed_file_name, O_RDONLY | O_BINARY );
#else
    fd = open( seed_file_name, O_RDONLY );
#endif
    if( fd == -1 && errno == ENOENT) {
	allow_seed_file_update = 1;
	return 0;
    }

    if( fd == -1 ) {
	log_info(_("can't open `%s': %s\n"), seed_file_name, strerror(errno) );
	return 0;
    }
    if (lock_seed_file (fd, seed_file_name, 0))
      {
        close (fd);
        return 0;
      }

    if( fstat( fd, &sb ) ) {
	log_info(_("can't stat `%s': %s\n"), seed_file_name, strerror(errno) );
	close(fd);
	return 0;
    }
    if( !S_ISREG(sb.st_mode) ) {
	log_info(_("`%s' is not a regular file - ignored\n"), seed_file_name );
	close(fd);
	return 0;
    }
    if( !sb.st_size ) {
	log_info(_("note: random_seed file is empty\n") );
	close(fd);
	allow_seed_file_update = 1;
	return 0;
    }
    if( sb.st_size != POOLSIZE ) {
	log_info(_("WARNING: invalid size of random_seed file - not used\n") );
	close(fd);
	return 0;
    }
    do {
	n = read( fd, buffer, POOLSIZE );
    } while( n == -1 && errno == EINTR );
    if( n != POOLSIZE ) {
	log_fatal(_("can't read `%s': %s\n"), seed_file_name,strerror(errno) );
	close(fd);
	return 0;
    }

    close(fd);

    add_randomness( buffer, POOLSIZE, 0 );
    /* add some minor entropy to the pool now (this will also force a mixing) */
    {	pid_t x = getpid();
	add_randomness( &x, sizeof(x), 0 );
    }
    {	time_t x = time(NULL);
	add_randomness( &x, sizeof(x), 0 );
    }
    {	clock_t x = clock();
	add_randomness( &x, sizeof(x), 0 );
    }
    /* And read a few bytes from our entropy source.  By using
     * a level of 0 this will not block and might not return anything
     * with some entropy drivers, however the rndlinux driver will use
     * /dev/urandom and return some stuff - Do not read to much as we
     * want to be friendly to the scare system entropy resource. */
    read_random_source( 0, 16, 0 );

    allow_seed_file_update = 1;
    return 1;
}

void
update_random_seed_file()
{
    ulong *sp, *dp;
    int fd, i;

    if( !seed_file_name || !is_initialized || !pool_filled )
	return;
    if( !allow_seed_file_update ) {
	log_info(_("note: random_seed file not updated\n"));
	return;
    }


    /* copy the entropy pool to a scratch pool and mix both of them */
    for(i=0,dp=(ulong*)keypool, sp=(ulong*)rndpool;
				    i < POOLWORDS; i++, dp++, sp++ ) {
	*dp = *sp + ADD_VALUE;
    }
    mix_pool(rndpool); rndstats.mixrnd++;
    mix_pool(keypool); rndstats.mixkey++;

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
    fd = open( seed_file_name, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,
							S_IRUSR|S_IWUSR );
#else
# if LOCK_SEED_FILE
    fd = open( seed_file_name, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR );
# else
    fd = open( seed_file_name, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
# endif
#endif
    if( fd == -1 ) {
	log_info(_("can't create `%s': %s\n"), seed_file_name, strerror(errno) );
	return;
    }

    if (lock_seed_file (fd, seed_file_name, 1))
      {
        close (fd);
        return;
      }
#if LOCK_SEED_FILE
    if (ftruncate (fd, 0))
      {
	log_info(_("can't write `%s': %s\n"), seed_file_name, strerror(errno));
        close (fd);
        return;
      }
#endif /*LOCK_SEED_FILE*/

    do {
	i = write( fd, keypool, POOLSIZE );
    } while( i == -1 && errno == EINTR );
    if( i != POOLSIZE ) {
	log_info(_("can't write `%s': %s\n"), seed_file_name, strerror(errno) );
    }
    if( close(fd) )
	log_info(_("can't close `%s': %s\n"), seed_file_name, strerror(errno) );
}


static void
read_pool( byte *buffer, size_t length, int level )
{
    int i;
    ulong *sp, *dp;

    if( length > POOLSIZE ) {
	log_bug("too many random bits requested\n");
    }

    if( !pool_filled ) {
	if( read_seed_file() )
	    pool_filled = 1;
    }

    /* For level 2 quality (key generation) we alwas make
     * sure that the pool has been seeded enough initially */
    if( level == 2 && !did_initial_extra_seeding ) {
	size_t needed;

	pool_balance = 0;
	needed = length - pool_balance;
	if( needed < POOLSIZE/2 )
	    needed = POOLSIZE/2;
	else if( needed > POOLSIZE )
	    BUG();
	read_random_source( 3, needed, 2 );
	pool_balance += needed;
	did_initial_extra_seeding=1;
    }

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
	wipememory(keypool, POOLSIZE);
    }
}


/****************
 * Add LENGTH bytes of randomness from buffer to the pool.
 * source may be used to specify the randomness source.
 * Source is:
 *	0 - used ony for initialization
 *	1 - fast random poll function
 *	2 - normal poll function
 *	3 - used when level 2 random quality has been requested
 *	    to do an extra pool seed.
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
	rndpool[pool_writepos++] ^= *p++;
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
    static int (*fnc)( void (*)(const void*, size_t, int), int) = NULL;
    static int initialized = 0;

    rndstats.fastpolls++;
    if( !initialized ) {
	if( !is_initialized )
	    initialize();
	initialized = 1;
	fnc = getfnc_fast_random_poll();
    }
    if( fnc ) {
	(*fnc)( add_randomness, 1 );
	return;
    }

    /* fall back to the generic function */
#if defined(HAVE_GETHRTIME) && !defined(HAVE_BROKEN_GETHRTIME)
    {	hrtime_t tv;
        /* On some Solaris and HPUX system gethrtime raises an SIGILL, but we 
         * checked this with configure */
	tv = gethrtime();
	add_randomness( &tv, sizeof(tv), 1 );
    }
#elif defined (HAVE_GETTIMEOFDAY)
    {	struct timeval tv;
	if( gettimeofday( &tv, NULL ) )
	    BUG();
	add_randomness( &tv.tv_sec, sizeof(tv.tv_sec), 1 );
	add_randomness( &tv.tv_usec, sizeof(tv.tv_usec), 1 );
    }
#elif defined (HAVE_CLOCK_GETTIME)
    {	struct timespec tv;
	if( clock_gettime( CLOCK_REALTIME, &tv ) == -1 )
	    BUG();
	add_randomness( &tv.tv_sec, sizeof(tv.tv_sec), 1 );
	add_randomness( &tv.tv_nsec, sizeof(tv.tv_nsec), 1 );
    }
#elif defined (HAVE_TIMES)
    {	struct tms buf;
        if( times( &buf ) == -1 )
	    BUG();
	add_randomness( &buf, sizeof buf, 1 );
    }
#endif
#ifdef HAVE_GETRUSAGE
#ifndef RUSAGE_SELF
#ifdef __GCC__
#warning There is no RUSAGE_SELF on this system
#endif
#else
    {	struct rusage buf;
        /* QNX/Neutrino does return ENOSYS - so we just ignore it and
         * add whatever is in buf.  In a chroot environment it might not
         * work at all (i.e. because /proc/ is not accessible), so we better 
         * ignore all error codes and hope for the best
         */
        getrusage( RUSAGE_SELF, &buf );
        
	add_randomness( &buf, sizeof buf, 1 );
	wipememory( &buf, sizeof buf );
    }
#endif
#endif
    /* time and clock are available on all systems - so
     * we better do it just in case one of the above functions
     * didn't work */
    {	time_t x = time(NULL);
	add_randomness( &x, sizeof(x), 1 );
    }
    {	clock_t x = clock();
	add_randomness( &x, sizeof(x), 1 );
    }
}



static void
read_random_source( int requester, size_t length, int level )
{
    static int (*fnc)(void (*)(const void*, size_t, int), int,
						    size_t, int) = NULL;
    if( !fnc ) {
	if( !is_initialized )
	    initialize();
	fnc = getfnc_gather_random();
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
	tty_printf(_("The random number generator is only a kludge to let\n"
		   "it run - it is in no way a strong RNG!\n\n"
		   "DON'T USE ANY DATA GENERATED BY THIS PROGRAM!!\n\n"));
	initialized=1;
#ifdef HAVE_RAND
	srand(make_timestamp()*getpid());
#else
	srandom(make_timestamp()*getpid());
#endif
    }

    p = buffer = xmalloc( length );
    n = length;
#ifdef HAVE_RAND
    while( n-- )
	*p++ = ((unsigned)(1 + (int) (256.0*rand()/(RAND_MAX+1.0)))-1);
#else
    while( n-- )
	*p++ = ((unsigned)(1 + (int) (256.0*random()/(RAND_MAX+1.0)))-1);
#endif
    add_randomness( buffer, length, requester );
    xfree(buffer);
    return 0; /* okay */
}
