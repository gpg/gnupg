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
#include "util.h"
#include "cipher.h"

static struct {
    int level;
    int len;
    byte buffer[100]; /* fixme: should this be allocated in secure space? */
} cache;

/****************
 * Fill the buffer with LENGTH bytes of cryptologic strong
 * random bytes. level 0 is not very strong, 1 is strong enough
 * for most usage, 2 is good for key generation stuff but may be very slow.
 */
void
randomize_buffer( byte *buffer, size_t length, int level )
{
    FILE *fp;

    if( level == 2 )
	level = 1; /* 2 is much too slow */
    fp = fopen(level < 2? "/dev/urandom":"/dev/random", "r");
    if( !fp )
	log_fatal("can't open random device: %s\n", strerror(errno) );
    for( ; length; length-- )
	*buffer++ = getc(fp);
    fclose(fp);
}


byte
get_random_byte( int level )
{
    if( !cache.len || cache.level < level ) {
	randomize_buffer(cache.buffer, DIM(cache.buffer), level );
	cache.level = level;
	cache.len = DIM(cache.buffer);
    }

    return cache.buffer[--cache.len];
}


