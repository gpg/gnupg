/* mpi-scan.c  -  MPI functions
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

/****************
 * Scan through an mpi and return byte for byte. a -1 is returned to indicate
 * the end of the mpi. Scanning is done from the lsb to the msb, returned
 * values are in the range of 0 .. 255.
 *
 * FIXME: This code is VERY ugly!
 */
int
mpi_getbyte( MPI a, unsigned index )
{
    int i, j;
    unsigned n;
    mpi_ptr_t ap;
    mpi_limb_t limb;

    ap = a->d;
    for(n=0,i=0; i < a->nlimbs; i++ ) {
	limb = ap[i];
	for( j=0; j < BYTES_PER_MPI_LIMB; j++, n++ )
	    if( n == index )
		return (limb >> j*8) & 0xff;
    }
    return -1;
}


/****************
 * Put a value at position INDEX into A. index counts from lsb to msb
 */
void
mpi_putbyte( MPI a, unsigned index, int c )
{
    int i, j;
    unsigned n;
    mpi_ptr_t ap;
    mpi_limb_t limb;

#if BYTES_PER_MPI_LIMB != 4
  #error please enhance this function, its ugly - i know.
#endif
    c &= 0xff;
    ap = a->d;
    for(n=0,i=0; i < a->alloced; i++ ) {
	limb = ap[i];
	for( j=0; j < BYTES_PER_MPI_LIMB; j++, n++ )
	    if( n == index ) {
		if( j == 0 )
		    limb = (limb & 0xffffff00) | c;
		else if( j == 1 )
		    limb = (limb & 0xffff00ff) | (c<<8);
		else if( j == 2 )
		    limb = (limb & 0xff00ffff) | (c<<16);
		else
		    limb = (limb & 0x00ffffff) | (c<<24);
		if( a->nlimbs <= i )
		    a->nlimbs = i+1;
		ap[i] = limb;
		return;
	    }
    }
    abort(); /* index out of range */
}

