/* rndlinux.c  -  raw random number for OSes with /dev/random
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_GETTIMEOFDAY
#include <sys/times.h>
#endif
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#if 0
#include <sys/ioctl.h>
#include <asm/types.h>
#include <linux/random.h>
#endif
#include "types.h"
#include "util.h"
#include "ttyio.h"
#include "algorithms.h"

#include "i18n.h"

static int open_device( const char *name, int minor );


#if 0
#ifdef HAVE_DEV_RANDOM_IOCTL
static ulong
get_entropy_count( int fd )
{
    ulong count;

    if( ioctl( fd, RNDGETENTCNT, &count ) == -1 )
	g10_log_fatal("ioctl(RNDGETENTCNT) failed: %s\n", strerror(errno) );
    return count;
}
#endif
#endif

/****************
 * Used to open the /dev/random devices (Linux, xBSD, Solaris (if it exists), ...)
 */
static int
open_device( const char *name, int minor )
{
    int fd;
    struct stat sb;

    fd = open( name, O_RDONLY );
    if( fd == -1 )
	g10_log_fatal("can't open %s: %s\n", name, strerror(errno) );
    if( fstat( fd, &sb ) )
	g10_log_fatal("stat() off %s failed: %s\n", name, strerror(errno) );
    /* Don't check device type for better portability */
    /*  if( (!S_ISCHR(sb.st_mode)) && (!S_ISFIFO(sb.st_mode)) )
	  g10_log_fatal("invalid random device!\n" ); */
    return fd;
}


/****************
 * Note:  Using a level of 0 should never block and better add nothing
 * to the pool.  This is easy to accomplish with /dev/urandom.
 */
int
rndlinux_gather_random( void (*add)(const void*, size_t, int), int requester,
					  size_t length, int level )
{
    static int fd_urandom = -1;
    static int fd_random = -1;
    int fd;
    int n;
    int warn=0;
    byte buffer[768];

    if( level >= 2 ) {
	if( fd_random == -1 )
	    fd_random = open_device( NAME_OF_DEV_RANDOM, 8 );
	fd = fd_random;
    }
    else {
	/* this will also be used for elve 0 but by using /dev/urandom
	 * we can be sure that oit will never block. */
	if( fd_urandom == -1 )
	    fd_urandom = open_device( NAME_OF_DEV_URANDOM, 9 );
	fd = fd_urandom;
    }

#if 0
#ifdef HAVE_DEV_RANDOM_IOCTL
    g10_log_info("entropy count of %d is %lu\n", fd, get_entropy_count(fd) );
#endif
#endif
    while( length ) {
	fd_set rfds;
	struct timeval tv;
	int rc;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if( !(rc=select(fd+1, &rfds, NULL, NULL, &tv)) ) {
	    if( !warn )
		tty_printf(
_("\n"
"Not enough random bytes available.  Please do some other work to give\n"
"the OS a chance to collect more entropy! (Need %d more bytes)\n"), (int)length );
	    warn = 1;
	    continue;
	}
	else if( rc == -1 ) {
	    tty_printf(
		       "select() error: %s\n", strerror(errno));
	    continue;
	}

	do {
	    int nbytes = length < sizeof(buffer)? length : sizeof(buffer);
	    n = read(fd, buffer, nbytes );
	    if( n >= 0 && n > nbytes ) {
		g10_log_error("bogus read from random device (n=%d)\n", n );
		n = nbytes;
	    }
	} while( n == -1 && errno == EINTR );
	if( n == -1 )
	    g10_log_fatal("read error on random device: %s\n", strerror(errno));
	(*add)( buffer, n, requester );
	length -= n;
    }
    wipememory(buffer, sizeof(buffer) );

    return 0; /* success */
}
