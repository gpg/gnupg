/* g10c.c  -  Wrapper for cipher functions
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "mpi.h"
#include "random.h"
#include "cipher.h"
#define _g10lib_INTERNAL 1
#include "g10lib.h"

const char *g10c_revision_string(int dummy) { return "$Revision$"; }

MPI
g10c_generate_secret_prime( unsigned nbits )
{
    return generate_secret_prime( nbits );
}


char *
g10c_get_random_bits( unsigned nbits, int level, int secure )
{
    return (char*)get_random_bits( nbits, level, secure );
}

