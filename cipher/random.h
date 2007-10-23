/* random.h - random functions
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
#ifndef G10_RANDOM_H
#define G10_RANDOM_H

#include "types.h"

/*-- random.c --*/
void random_dump_stats(void);
void secure_randoxmalloc(void);
void set_random_seed_file(const char *);
void update_random_seed_file(void);
int  quick_random_gen( int onoff );
int  random_is_faked(void);
void random_disable_locking (void);
void randomize_buffer( byte *buffer, size_t length, int level );
byte *get_random_bits( size_t nbits, int level, int secure );
void fast_random_poll( void );

/*-- rndw32.c --*/
#ifdef USE_STATIC_RNDW32
void rndw32_set_dll_name( const char *name );
#endif

#endif /*G10_RANDOM_H*/
