/* primegen.c - prime number generator
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
#include <string.h>
#include <assert.h>
#include "util.h"
#include "mpi.h"
#include "cipher.h"

static int no_of_small_prime_numbers;
static int rabin_miller( MPI n );


/****************
 * Generate a prime number (stored in secure memory)
 */
MPI
generate_random_prime( unsigned  nbits )
{

    unsigned  nlimbs;
    MPI prime, val_2, val_3, result;
    int i;
    unsigned x, step;
    unsigned count1, count2;
    int *mods;

    if( DBG_CIPHER )
	log_debug("generate a prime of %u bits ", nbits );

    if( !no_of_small_prime_numbers ) {
	for(i=0; small_prime_numbers[i]; i++ )
	    no_of_small_prime_numbers++;
    }
    mods = m_alloc( no_of_small_prime_numbers * sizeof *mods );
    /* make nbits fit into MPI implementation */
    nlimbs = (nbits + BITS_PER_MPI_LIMB - 1) /	BITS_PER_MPI_LIMB;
    assert( nlimbs );
    val_2  = mpi_alloc( nlimbs );
    mpi_set_ui(val_2, 2);
    val_3  = mpi_alloc( nlimbs );
    mpi_set_ui(val_3, 3);
    result = mpi_alloc( nlimbs );
    prime  = mpi_alloc_secure( nlimbs );
    count1 = count2 = 0;
    /* enter (endless) loop */
    for(;;) {
	/* generate a random number */
	mpi_set_bytes( prime, nbits, get_random_byte, 2 );
	/* set high order bit to 1, set low order bit to 1 */
	mpi_set_bit( prime, nbits-1 );
	mpi_set_bit( prime, 0 );

	/* calculate all remainders */
	for(i=0; (x = small_prime_numbers[i]); i++ )
	    mods[i] = mpi_fdiv_r_ui(NULL, prime, x);

	for(step=0; step < 20000; step += 2 ) {
	    /* check against all the small primes we have in mods */
	    count1++;
	    for(i=0; (x = small_prime_numbers[i]); i++ ) {
		while( mods[i] + step >= x )
		    mods[i] -= x;
		if( !(mods[i] + step) )
		    break;
	    }
	    if( x )
		continue;   /* found a multiple of a already known prime */
	    if( DBG_CIPHER )
		fputc('.', stderr);

	    mpi_add_ui( prime, prime, step );

	    /* do a Fermat test */
	    count2++;
	    mpi_powm( result, val_2, prime, prime );
	    if( mpi_cmp_ui(result, 2) )
		continue;  /* stepping (fermat test failed) */
	    if( DBG_CIPHER )
		fputc('+', stderr);
	    /* and a second one */
	    count2++;
	    mpi_powm( result, val_3, prime, prime );
	    if( mpi_cmp_ui(result, 3) )
		continue;  /* stepping (fermat test failed) */
	    if( DBG_CIPHER )
		fputc('+', stderr);

	    /* perform Rabin-Miller tests */
	    for(i=5; i > 0; i-- ) {
		if( DBG_CIPHER )
		    fputc('+', stderr);
		if( rabin_miller(prime) )
		    break;
	    }
	    if( !i ) {
		if( !mpi_test_bit( prime, nbits-1 ) ) {
		    if( DBG_CIPHER ) {
			fputc('\n', stderr);
			log_debug("overflow in prime generation\n");
			break; /* step loop, cont with a new prime */
		    }
		}
		if( DBG_CIPHER ) {
		    fputc('\n', stderr);
		    log_debug("performed %u simple and %u Fermat/Rabin-Miller tests\n",
					count1, count2 );
		    log_mpidump("found prime: ", prime );
		}

		mpi_free(val_2);
		mpi_free(val_3);
		mpi_free(result);
		m_free(mods);
		return prime;
	    }
	}
	if( DBG_CIPHER )
	    fputc(':', stderr); /* restart with a new random value */
    }
}


/****************
 * Return 1 if n is not a prime
 */
static int
rabin_miller( MPI n )
{
    return 0;
}

