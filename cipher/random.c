/* random.c  -	random number generator
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"
#include "cipher.h"

struct cache {
    int len;
    byte buffer[100]; /* fixme: should be allocated with m_alloc_secure()*/
};

static struct cache cache[3];
#define MASK_LEVEL(a) do {if( a > 2 ) a = 2; else if( a < 0 ) a = 0; } while(0)


static int open_device( const char *name, int minor );
static void fill_buffer( byte *buffer, size_t length, int level );

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
	fill_buffer(cache[level].buffer, DIM(cache[level].buffer), level );
	cache[level].len = DIM(cache[level].buffer);
    }

    return cache[level].buffer[--cache[level].len];
}




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
    if( !S_ISCHR(sb.st_mode)
      #ifdef __linux__
	|| (sb.st_rdev >> 8) != 1
	|| (sb.st_rdev & 0xff) != minor
      #endif
      )
	log_fatal("invalid random device!\n" );
    return fd;
}


static void
fill_buffer( byte *buffer, size_t length, int level )
{
    FILE *fp;
    static int fd_urandom = -1;
    static int fd_random = -1;
    int fd;
    int n;

    if( level == 2 ) {
	if( fd_random == -1 )
	    fd_random = open_device( "/dev/random", 8 );
	fd = fd_random;
    }
    else {
	if( fd_urandom == -1 )
	    fd_urandom = open_device( "/dev/urandom", 9 );
	fd = fd_urandom;
    }


    do {
	do {
	    n = read(fd, buffer, length );
	} while( n == -1 && errno == EINTR );
	if( n == -1 )
	    log_fatal("read error on random device: %s\n", strerror(errno) );
	buffer += n;
	length -= n;
    } while( length );
}

