/* rand-unix.c	-  raw random number generator for unix like OSes
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


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef	HAVE_GETHRTIME
  #include <sys/times.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
  #include <sys/times.h>
#endif
#ifdef HAVE_GETRUSAGE
  #include <sys/resource.h>
#endif
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "util.h"
#include "rmd.h"
#include "ttyio.h"
#include "i18n.h"
#include "rand-internal.h"
#ifdef USE_RAND_UNIX  /* This file is only for real systems */


void
random_poll()
{
    char buf[POOLSIZE/5];
    read_random_source( buf, POOLSIZE/5, 1 ); /* read /dev/urandom */
    add_randomness( buf, POOLSIZE/5, 2);
    memset( buf, 0, POOLSIZE/5);
}


void
fast_random_poll()
{
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


#ifdef HAVE_DEV_RANDOM	/* we have the /dev/random devices */

/****************
 * Used to open the Linux and xBSD /dev/random devices
 */
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


void
read_random_source( byte *buffer, size_t length, int level )
{
    static int fd_urandom = -1;
    static int fd_random = -1;
    int fd;
    int n;
    int warn=0;

    if( level >= 2 ) {
	if( fd_random == -1 )
	    fd_random = open_device( NAME_OF_DEV_RANDOM, 8 );
	fd = fd_random;
    }
    else {
	if( fd_urandom == -1 )
	    fd_urandom = open_device( NAME_OF_DEV_URANDOM, 9 );
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


/****************
 * The real random data collector for Unix.
 * this function runs in a loop, waiting for commands from ctrl_fd
 * and normally starts a collection process, which outputs random
 * bytes to out_fd.
 *
 * Commands understand from ctrl_fd are single character:
 *  'Q' = Quit the loop
 *  'S' = Start a new collection process
 */
static void
collector( FILE *ctrlfp, FILE *outfp )
{



}

#endif /* no HAVE_DEV_RANDOM */
#endif /* USE_RAND_UNIX */
