/* primegen.c - prime number generator
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "mpi.h"
#include "cipher.h"

static int no_of_small_prime_numbers;
static MPI gen_prime( unsigned	nbits, int mode, int randomlevel );
static int check_prime( MPI prime );
static int is_prime( MPI n, int steps, int *count );
static void m_out_of_n( char *array, int m, int n );


/****************
 * Generate a prime number (stored in secure memory)
 */
MPI
generate_secret_prime( unsigned  nbits )
{
    MPI prime;

    prime = gen_prime( nbits, 1, 2 );
    fputc('\n', stderr);
    return prime;
}

MPI
generate_public_prime( unsigned  nbits )
{
    MPI prime;

    prime = gen_prime( nbits, 0, 2 );
    fputc('\n', stderr);
    return prime;
}


/****************
 * We do not need to use the strongest RNG because we gain no extra
 * security from it - The prime number is public and we could also
 * offer the factors for those who are willing to check that it is
 * indeed a strong prime.
 *
 * mode 0: Standard
 *	1: Make sure that at least one factor is of size qbits.
 */
MPI
generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
		    MPI g, MPI **ret_factors )
{
    int n;  /* number of factors */
    int m;  /* number of primes in pool */
    unsigned fbits; /* length of prime factors */
    MPI *factors; /* current factors */
    MPI *pool;	/* pool of primes */
    MPI q;	/* first prime factor (variable)*/
    MPI prime;	/* prime test value */
    MPI q_factor; /* used for mode 1 */
    byte *perms = NULL;
    int i, j;
    int count1, count2;
    unsigned nprime;
    unsigned req_qbits = qbits; /* the requested q bits size */

    /* find number of needed prime factors */
    for(n=1; (pbits - qbits - 1) / n  >= qbits; n++ )
	;
    n--;
    if( !n || (mode==1 && n < 2) )
	log_fatal("can't gen prime with pbits=%u qbits=%u\n", pbits, qbits );
    if( mode == 1 ) {
	n--;
	fbits = (pbits - 2*req_qbits -1) / n;
	qbits =  pbits - req_qbits - n*fbits;
    }
    else {
	fbits = (pbits - req_qbits -1) / n;
	qbits = pbits - n*fbits;
    }
    if( DBG_CIPHER )
	log_debug("gen prime: pbits=%u qbits=%u fbits=%u/%u n=%d\n",
		    pbits, req_qbits, qbits, fbits, n  );
    prime = mpi_alloc( (pbits + BITS_PER_MPI_LIMB - 1) /  BITS_PER_MPI_LIMB );
    q = gen_prime( qbits, 0, 1 );
    q_factor = mode==1? gen_prime( req_qbits, 0, 1 ) : NULL;

    /* allocate an array to hold the factors + 2 for later usage */
    factors = m_alloc_clear( (n+2) * sizeof *factors );

    /* make a pool of 3n+5 primes (this is an arbitrary value) */
    m = n*3+5;
    if( m < 25 )
	m = 25;
    pool = m_alloc_clear( m * sizeof *pool );

    /* permutate over the pool of primes */
    count1=count2=0;
    do {
      next_try:
	if( !perms ) {
	    /* allocate new primes */
	    for(i=0; i < m; i++ ) {
		mpi_free(pool[i]);
		pool[i] = NULL;
	    }
	    /* init m_out_of_n() */
	    perms = m_alloc_clear( m );
	    for(i=0; i < n; i++ ) {
		perms[i] = 1;
		pool[i] = gen_prime( fbits, 0, 1 );
		factors[i] = pool[i];
	    }
	}
	else {
	    m_out_of_n( perms, n, m );
	    for(i=j=0; i < m && j < n ; i++ )
		if( perms[i] ) {
		    if( !pool[i] )
			pool[i] = gen_prime( fbits, 0, 1 );
		    factors[j++] = pool[i];
		}
	    if( i == n ) {
		m_free(perms); perms = NULL;
		fputc('!', stderr);
		goto next_try;	/* allocate new primes */
	    }
	}

	mpi_set( prime, q );
	mpi_mul_ui( prime, prime, 2 );
	if( mode == 1 )
	    mpi_mul( prime, prime, q_factor );
	for(i=0; i < n; i++ )
	    mpi_mul( prime, prime, factors[i] );
	mpi_add_ui( prime, prime, 1 );
	nprime = mpi_get_nbits(prime);
	if( nprime < pbits ) {
	    if( ++count1 > 20 ) {
		count1 = 0;
		qbits++;
		fputc('>', stderr);
		q = gen_prime( qbits, 0, 1 );
		goto next_try;
	    }
	}
	else
	    count1 = 0;
	if( nprime > pbits ) {
	    if( ++count2 > 20 ) {
		count2 = 0;
		qbits--;
		fputc('<', stderr);
		q = gen_prime( qbits, 0, 1 );
		goto next_try;
	    }
	}
	else
	    count2 = 0;
    } while( !(nprime == pbits && check_prime( prime )) );

    if( DBG_CIPHER ) {
	putc('\n', stderr);
	log_mpidump( "prime    : ", prime );
	log_mpidump( "factor  q: ", q );
	if( mode == 1 )
	    log_mpidump( "factor q0: ", q_factor );
	for(i=0; i < n; i++ )
	    log_mpidump( "factor pi: ", factors[i] );
	log_debug("bit sizes: prime=%u, q=%u", mpi_get_nbits(prime), mpi_get_nbits(q) );
	if( mode == 1 )
	    fprintf(stderr, ", q0=%u", mpi_get_nbits(q_factor) );
	for(i=0; i < n; i++ )
	    fprintf(stderr, ", p%d=%u", i, mpi_get_nbits(factors[i]) );
	putc('\n', stderr);
    }

    if( ret_factors ) { /* caller wants the factors */
	*ret_factors = m_alloc_clear( (n+2) * sizeof **ret_factors);
	if( mode == 1 ) {
	    i = 0;
	    (*ret_factors)[i++] = mpi_copy( q_factor );
	    for(; i <= n; i++ )
		(*ret_factors)[i] = mpi_copy( factors[i] );
	}
	else {
	    for(; i < n; i++ )
		(*ret_factors)[i] = mpi_copy( factors[i] );
	}
    }

    if( g ) { /* create a generator (start with 3)*/
	MPI tmp   = mpi_alloc( mpi_get_nlimbs(prime) );
	MPI b	  = mpi_alloc( mpi_get_nlimbs(prime) );
	MPI pmin1 = mpi_alloc( mpi_get_nlimbs(prime) );

	if( mode == 1 )
	    BUG(); /* not yet implemented */
	factors[n] = q;
	factors[n+1] = mpi_alloc_set_ui(2);
	mpi_sub_ui( pmin1, prime, 1 );
	mpi_set_ui(g,2);
	do {
	    mpi_add_ui(g, g, 1);
	    if( DBG_CIPHER ) {
		log_debug("checking g: ");
		mpi_print( stderr, g, 1 );
	    }
	    else
		fputc('^', stderr);
	    for(i=0; i < n+2; i++ ) {
		/*fputc('~', stderr);*/
		mpi_fdiv_q(tmp, pmin1, factors[i] );
		/* (no mpi_pow(), but it is okay to use this with mod prime) */
		mpi_powm(b, g, tmp, prime );
		if( !mpi_cmp_ui(b, 1) )
		    break;
	    }
	    if( DBG_CIPHER )
		fputc('\n', stderr);
	} while( i < n+2 );
	mpi_free(factors[n+1]);
	mpi_free(tmp);
	mpi_free(b);
	mpi_free(pmin1);
    }
    if( !DBG_CIPHER )
	putc('\n', stderr);

    m_free( factors );	/* (factors are shallow copies) */
    for(i=0; i < m; i++ )
	mpi_free( pool[i] );
    m_free( pool );
    m_free(perms);
    return prime;
}



static MPI
gen_prime( unsigned  nbits, int secret, int randomlevel )
{
    unsigned  nlimbs;
    MPI prime, val_2, val_3, result;
    int i;
    unsigned x, step;
    unsigned count1, count2;
    int *mods;

    if( 0 && DBG_CIPHER )
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
    prime  = secret? mpi_alloc_secure( nlimbs ): mpi_alloc( nlimbs );
    count1 = count2 = 0;
    /* enter (endless) loop */
    for(;;) {
	int dotcount=0;

	/* generate a random number */
	mpi_set_bytes( prime, nbits, get_random_byte, randomlevel );
	/* set high order bit to 1, set low order bit to 1 */
	mpi_set_highbit( prime, nbits-1 );
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

	    mpi_add_ui( prime, prime, step );

	   #if 0
	    /* do a Fermat test */
	    count2++;
	    mpi_powm( result, val_2, prime, prime );
	    if( mpi_cmp_ui(result, 2) )
		continue;  /* stepping (fermat test failed) */
	    fputc('+', stderr);
	   #endif

	    /* perform stronger tests */
	    if( is_prime(prime, 5, &count2 ) ) {
		if( !mpi_test_bit( prime, nbits-1 ) ) {
		    if( 0 && DBG_CIPHER ) {
			fputc('\n', stderr);
			log_debug("overflow in prime generation\n");
			break; /* step loop, cont with a new prime */
		    }
		}

		if( 0 && DBG_CIPHER ) {
		    log_debug("performed %u simple and %u stronger tests\n",
					count1, count2 );
		    log_mpidump("found prime: ", prime );
		}

		mpi_free(val_2);
		mpi_free(val_3);
		mpi_free(result);
		m_free(mods);
		return prime;
	    }
	    if( ++dotcount == 10 ) {
		fputc('.', stderr);
		dotcount = 0;
	    }
	}
	fputc(':', stderr); /* restart with a new random value */
    }
}

/****************
 * Returns: true if this may be a prime
 */
static int
check_prime( MPI prime )
{
    int i;
    unsigned x;
    int count=0;

    /* check against small primes */
    for(i=0; (x = small_prime_numbers[i]); i++ ) {
	if( mpi_divisible_ui( prime, x ) )
	    return 0;
    }

  #if 0
    result = mpi_alloc( mpi_get_nlimbs(prime) );
    val_2  = mpi_alloc_set_ui( 2 );
    mpi_powm( result, val_2, prime, prime );
    if( mpi_cmp_ui(result, 2) ) {
	mpi_free(result);
	mpi_free(val_2);
	return 0;
    }
    mpi_free(result);
    mpi_free(val_2);
    fputc('+', stderr);
  #endif

    /* perform stronger tests */
    if( is_prime(prime, 5, &count ) )
	return 1; /* is probably a prime */
    fputc('.', stderr);
    return 0;
}


/****************
 * Return true if n is probably a prime
 */
static int
is_prime( MPI n, int steps, int *count )
{
    MPI x = mpi_alloc( mpi_get_nlimbs( n ) );
    MPI y = mpi_alloc( mpi_get_nlimbs( n ) );
    MPI z = mpi_alloc( mpi_get_nlimbs( n ) );
    MPI nminus1 = mpi_alloc( mpi_get_nlimbs( n ) );
    MPI a2 = mpi_alloc_set_ui( 2 );
    MPI q;
    unsigned i, j, k;
    int rc = 0;
    unsigned nbits = mpi_get_nbits( n );

    mpi_sub_ui( nminus1, n, 1 );

    /* find q and k, so that n = 1 + 2^k * q */
    q = mpi_copy( nminus1 );
    k = mpi_trailing_zeros( q );
    mpi_tdiv_q_2exp(q, q, k);

    for(i=0 ; i < steps; i++ ) {
	++*count;
	if( !i ) {
	    mpi_set_ui( x, 2 );
	}
	else {
	    mpi_set_bytes( x, nbits-1, get_random_byte, 0 );
	    /* work around a bug in mpi_set_bytes */
	    if( mpi_test_bit( x, nbits-2 ) ) {
		mpi_set_highbit( x, nbits-2 ); /* clear all higher bits */
	    }
	    else {
		mpi_set_highbit( x, nbits-2 );
		mpi_clear_bit( x, nbits-2 );
	    }
	    assert( mpi_cmp( x, nminus1 ) < 0 && mpi_cmp_ui( x, 1 ) > 0 );
	}
	mpi_powm( y, x, q, n);
	if( mpi_cmp_ui(y, 1) && mpi_cmp( y, nminus1 ) ) {
	    for( j=1; j < k && mpi_cmp( y, nminus1 ); j++ ) {
		mpi_powm(y, y, a2, n);
		if( !mpi_cmp_ui( y, 1 ) )
		    goto leave; /* not a prime */
	    }
	    if( mpi_cmp( y, nminus1 ) )
		goto leave; /* not a prime */
	}
	fputc('+', stderr);
    }
    rc = 1; /* may be a prime */

  leave:
    mpi_free( x );
    mpi_free( y );
    mpi_free( z );
    mpi_free( nminus1 );
    mpi_free( q );

    return rc;
}


static void
m_out_of_n( char *array, int m, int n )
{
    int i=0, i1=0, j=0, jp=0,  j1=0, k1=0, k2=0;

    if( !m || m >= n )
	return;

    if( m == 1 ) { /* special case */
	for(i=0; i < n; i++ )
	    if( array[i] ) {
		array[i++] = 0;
		if( i >= n )
		    i = 0;
		array[i] = 1;
		return;
	    }
	BUG();
    }

    for(j=1; j < n; j++ ) {
	if( array[n-1] == array[n-j-1] )
	    continue;
	j1 = j;
	break;
    }

    if( m & 1 ) { /* m is odd */
	if( array[n-1] ) {
	    if( j1 & 1 ) {
		k1 = n - j1;
		k2 = k1+2;
		if( k2 > n )
		    k2 = n;
		goto leave;
	    }
	    goto scan;
	}
	k2 = n - j1 - 1;
	if( k2 == 0 ) {
	    k1 = i;
	    k2 = n - j1;
	}
	else if( array[k2] && array[k2-1] )
	    k1 = n;
	else
	    k1 = k2 + 1;
    }
    else { /* m is even */
	if( !array[n-1] ) {
	    k1 = n - j1;
	    k2 = k1 + 1;
	    goto leave;
	}

	if( !(j1 & 1) ) {
	    k1 = n - j1;
	    k2 = k1+2;
	    if( k2 > n )
		k2 = n;
	    goto leave;
	}
      scan:
	jp = n - j1 - 1;
	for(i=1; i <= jp; i++ ) {
	    i1 = jp + 2 - i;
	    if( array[i1-1]  ) {
		if( array[i1-2] ) {
		    k1 = i1 - 1;
		    k2 = n - j1;
		}
		else {
		    k1 = i1 - 1;
		    k2 = n + 1 - j1;
		}
		goto leave;
	    }
	}
	k1 = 1;
	k2 = n + 1 - m;
    }
  leave:
    array[k1-1] = !array[k1-1];
    array[k2-1] = !array[k2-1];
}

