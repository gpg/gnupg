/* random.h - random functions
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
#ifndef G10_RANDOM_H
#define G10_RANDOM_H

#include "types.h"

/*-- random.c --*/
void secure_random_alloc(void);
int  quick_random_gen( int onoff );
void randomize_buffer( byte *buffer, size_t length, int level );
byte get_random_byte( int level );
byte *get_random_bits( size_t nbits, int level, int secure );
void add_randomness( const void *buffer, size_t length, int source );


/*-- the next two functions are implemented by all the system
     specific source files rand_xxxx.s --*/
void random_poll(void);
void fast_random_poll(void);


#endif /*G10_RANDOM_H*/
