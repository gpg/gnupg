/* rand-internal.h - header to glue the random functions
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
#ifndef G10_RAND_INTERNAL_H
#define G10_RAND_INTERNAL_H

/* For now we use the DUMMY random generator if we do not have
 * the real random device */
#ifndef HAVE_DEV_RANDOM
  #define USE_RAND_DUMMY 1
  #undef  USE_RAND_UNIX
  #undef  USE_RAND_W32
#endif



#include "random.h"

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


void read_random_source( byte *buffer, size_t length, int level );


#endif /*G10_RAND_INTERNAL_H*/
