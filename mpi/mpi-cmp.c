/* mpi-cmp.c  -  MPI functions
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
#include "mpi-internal.h"

int
mpi_cmp_ui( MPI u, unsigned long v )
{
    mpi_limb_t limb = v;

    if( !u->nlimbs && !limb )
	return 0;
    if( u->sign )
	return -1;
    if( u->nlimbs > 1 )
	return 1;

    if( u->d[0] == limb )
	return 0;
    else if( u->d[0] > limb )
	return 1;
    else
	return -1;
}

int
mpi_cmp( MPI u, MPI v )
{
    mpi_size_t usize = u->nlimbs;
    mpi_size_t vsize = v->nlimbs;
    int cmp;

    /* FIXME: are the numbers always normalized? */
    if( !u->sign && v->sign )
	return 1;
    else if( u->sign && !v->sign )
	return -1;
    else if( usize != vsize && !u->sign && !v->sign )
	return usize - vsize;
    else if( usize != vsize && u->sign && v->sign )
	return vsize + usize;
    else if( !usize )
	return 0;
    else if( !(cmp=mpihelp_cmp( u->d, v->d, usize )) )
	return 0;
    else if( (cmp < 0?1:0) == (u->sign?1:0))
	return 1;
    else
	return -1;
}


