/* mpi-bit.c  -  MPI bit level fucntions
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
#include <assert.h>
#include "mpi-internal.h"


/****************
 * Return the number of bits in A.
 * fixme: we should not count leading zero bits
 */
unsigned
mpi_get_nbits( MPI a )
{
    return a->nlimbs * BITS_PER_MPI_LIMB;
}


/****************
 * Test wether bit N is set.
 */
int
mpi_test_bit( MPI a, unsigned n )
{
    unsigned limbno, bitno;
    mpi_limb_t limb;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs )
	return 0; /* too far left: this is a 0 */
    limb = a->d[limbno];
    return (limb & (1 << bitno))? 1: 0;
}


/****************
 * Set bit N of A.
 */
void
mpi_set_bit( MPI a, unsigned n )
{
    unsigned limbno, bitno;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs ) { /* resize */
	if( a->alloced >= limbno )
	    mpi_resize(a, limbno+1 );
	a->nlimbs = limbno+1;
    }
    a->d[limbno] |= (1<<bitno);
}

/****************
 * Clear bit N of A.
 */
void
mpi_clear_bit( MPI a, unsigned n )
{
    unsigned limbno, bitno;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs )
	return; /* don't need to clear this bit, it's to far to left */
    a->d[limbno] &= ~(1 << bitno);
}


void
mpi_set_bytes( MPI a, unsigned nbits, byte (*fnc)(int), int opaque )
{
    byte *p;
    unsigned nlimbs, nlimbs2, xbits, xbytes;
    unsigned n;
    int i;

    nlimbs = nbits / BITS_PER_MPI_LIMB;
    xbits = nbits % BITS_PER_MPI_LIMB;
    nlimbs2 = xbits? (nlimbs+1):nlimbs;
    xbytes = xbits / 8;
    xbits = xbits % 8;
    if( a->alloced < nlimbs2 )
	mpi_resize(a, nlimbs2 );
    a->nlimbs = nlimbs2;
    for(n=0; n < nlimbs; n++ ) {
	p = (byte*)(a->d+n);
      #ifdef HAVE_LITTLE_ENDIAN
	for(i=0; i < BYTES_PER_MPI_LIMB; i++ )
	    p[i] = fnc(opaque);
      #else
	for(i=BYTES_PER_MPI_LIMB-1; i>=0; i-- )
	    p[i] = fnc(opaque);
      #endif
    }
    if( xbytes ) {
	p = (byte*)(a->d+n);
      #ifdef HAVE_LITTLE_ENDIAN
	for(i=0; i < xbytes; i++ )
	    p[i] = fnc(opaque);
      #else
	for(i=xbytes-1; i>=0; i-- )
	    p[i] = fnc(opaque);
      #endif
    }
    assert(!xbits);
}


