/* primegen.c - prime number generator
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
 *
 * ***********************************************************************
 * The algorithm used to generate practically save primes is due to
 * Lim and Lee as described in the CRYPTO '97 proceedings (ISBN3540633847)
 * page 260.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "mpi.h"
#include "cipher.h"
#include "i18n.h"

static int no_of_small_prime_numbers;
static MPI gen_prime( unsigned	nbits, int mode, int randomlevel );
static int check_prime( MPI prime, MPI val_2 );
static int is_prime( MPI n, int steps, int *count );
static void m_out_of_n( char *array, int m, int n );

static void (*progress_cb) ( void *, int );
static void *progress_cb_data;

void
register_primegen_progress ( void (*cb)( void *, int), void *cb_data )
{
    progress_cb = cb;
    progress_cb_data = cb_data;
}


static void
progress( int c )
{
    if ( progress_cb )
	progress_cb ( progress_cb_data, c );
    else
	fputc( c, stderr );
}


/****************
 * Generate a prime number (stored in secure memory)
 */
MPI
generate_secret_prime( unsigned  nbits )
{
    MPI prime;

    prime = gen_prime( nbits, 1, 2 );
    progress('\n');
    return prime;
}

MPI
generate_public_prime( unsigned  nbits )
{
    MPI prime;

    prime = gen_prime( nbits, 0, 2 );
    progress('\n');
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
    MPI val_2  = mpi_alloc_set_ui( 2 );

    /* find number of needed prime factors */
    for(n=1; (pbits - qbits - 1) / n  >= qbits; n++ )
	;
    n--;
    if( !n || (mode==1 && n < 2) )
	log_fatal(_("can't gen prime with pbits=%u qbits=%u\n"),
                  pbits, qbits );
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
    prime = mpi_alloc ( mpi_nlimb_hint_from_nbits (pbits) );
    q = gen_prime( qbits, 0, 0 );
    q_factor = mode==1? gen_prime( req_qbits, 0, 0 ) : NULL;

    /* allocate an array to hold the factors + 2 for later usage */
    factors = xmalloc_clear( (n+2) * sizeof *factors );

    /* make a pool of 3n+5 primes (this is an arbitrary value) */
    m = n*3+5;
    if( mode == 1 )
	m += 5; /* need some more for DSA */
    if( m < 25 )
	m = 25;
    pool = xmalloc_clear( m * sizeof *pool );

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
	    perms = xmalloc_clear( m );
	    for(i=0; i < n; i++ ) {
		perms[i] = 1;
		pool[i] = gen_prime( fbits, 0, 0 );
		factors[i] = pool[i];
	    }
	}
	else {
	    m_out_of_n( perms, n, m );
	    for(i=j=0; i < m && j < n ; i++ )
		if( perms[i] ) {
		    if( !pool[i] )
			pool[i] = gen_prime( fbits, 0, 0 );
		    factors[j++] = pool[i];
		}
	    if( i == n ) {
		xfree(perms); perms = NULL;
		progress('!');
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
		progress('>');
                mpi_free (q);
		q = gen_prime( qbits, 0, 0 );
		goto next_try;
	    }
	}
	else
	    count1 = 0;
	if( nprime > pbits ) {
	    if( ++count2 > 20 ) {
		count2 = 0;
		qbits--;
		progress('<');
                mpi_free (q);
		q = gen_prime( qbits, 0, 0 );
		goto next_try;
	    }
	}
	else
	    count2 = 0;
    } while( !(nprime == pbits && check_prime( prime, val_2 )) );

    if( DBG_CIPHER ) {
	progress('\n');
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
	progress('\n');
    }

    if( ret_factors ) { /* caller wants the factors */
	*ret_factors = xmalloc_clear( (n+2) * sizeof **ret_factors);
        i = 0;
	if( mode == 1 ) {
	    (*ret_factors)[i++] = mpi_copy( q_factor );
	    for(; i <= n; i++ )
		(*ret_factors)[i] = mpi_copy( factors[i-1] );
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
		progress('^');
	    for(i=0; i < n+2; i++ ) {
		/*fputc('~', stderr);*/
		mpi_fdiv_q(tmp, pmin1, factors[i] );
		/* (no mpi_pow(), but it is okay to use this with mod prime) */
		mpi_powm(b, g, tmp, prime );
		if( !mpi_cmp_ui(b, 1) )
		    break;
	    }
	    if( DBG_CIPHER )
		progress('\n');
	} while( i < n+2 );
	mpi_free(factors[n+1]);
	mpi_free(tmp);
	mpi_free(b);
	mpi_free(pmin1);
    }
    if( !DBG_CIPHER )
	progress('\n');

    xfree( factors );	/* (factors are shallow copies) */
    for(i=0; i < m; i++ )
	mpi_free( pool[i] );
    xfree( pool );
    xfree(perms);
    mpi_free(val_2);
    mpi_free(q);
    return prime;
}



static MPI
gen_prime( unsigned int nbits, int secret, int randomlevel )
{
    unsigned  nlimbs;
    MPI prime, ptest, pminus1, val_2, val_3, result;
    int i;
    unsigned x, step;
    int count1, count2;
    int *mods;

    if( 0 && DBG_CIPHER )
	log_debug("generate a prime of %u bits ", nbits );

    if (nbits < 16)
      {
        log_error (_("can't generate a prime with less than %d bits\n"), 16);
        exit (2);
      }

    if( !no_of_small_prime_numbers ) {
	for(i=0; small_prime_numbers[i]; i++ )
	    no_of_small_prime_numbers++;
    }
    mods = xmalloc( no_of_small_prime_numbers * sizeof *mods );
    /* Make nbits fit into MPI implementation.  */
    nlimbs = mpi_nlimb_hint_from_nbits (nbits);
    val_2  = mpi_alloc_set_ui( 2 );
    val_3 = mpi_alloc_set_ui( 3);
    prime  = secret? mpi_alloc_secure( nlimbs ): mpi_alloc( nlimbs );
    result = mpi_alloc_like( prime );
    pminus1= mpi_alloc_like( prime );
    ptest  = mpi_alloc_like( prime );
    count1 = count2 = 0;
    for(;;) {  /* try forvever */
	int dotcount=0;

	/* generate a random number */
	{   char *p = get_random_bits( nbits, randomlevel, secret );
	    mpi_set_buffer( prime, p, (nbits+7)/8, 0 );
	    xfree(p);
	}

	/* Set high order bit to 1, set low order bit to 0.
           If we are generating a secret prime we are most probably
           doing that for RSA, to make sure that the modulus does have
           the requested keysize we set the 2 high order bits */
	mpi_set_highbit( prime, nbits-1 );
        if (secret)
          mpi_set_bit (prime, nbits-2);
	mpi_set_bit( prime, 0 );

	/* calculate all remainders */
	for(i=0; (x = small_prime_numbers[i]); i++ )
	    mods[i] = mpi_fdiv_r_ui(NULL, prime, x);

	/* now try some primes starting with prime */
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
		continue;   /* found a multiple of an already known prime */

	    mpi_add_ui( ptest, prime, step );

	    /* do a faster Fermat test */
	    count2++;
	    mpi_sub_ui( pminus1, ptest, 1);
	    mpi_powm( result, val_2, pminus1, ptest );
	    if( !mpi_cmp_ui( result, 1 ) ) { /* not composite */
		/* perform stronger tests */
		if( is_prime(ptest, 5, &count2 ) ) {
		    if( !mpi_test_bit( ptest, nbits-1 ) ) {
			progress('\n');
			log_debug("overflow in prime generation\n");
			break; /* step loop, continue with a new prime */
		    }

		    mpi_free(val_2);
		    mpi_free(val_3);
		    mpi_free(result);
		    mpi_free(pminus1);
		    mpi_free(prime);
		    xfree(mods);
		    return ptest;
		}
	    }
	    if( ++dotcount == 10 ) {
		progress('.');
		dotcount = 0;
	    }
	}
	progress(':'); /* restart with a new random value */
    }
}

/****************
 * Returns: true if this may be a prime
 */
static int
check_prime( MPI prime, MPI val_2 )
{
    int i;
    unsigned x;
    int count=0;

    /* check against small primes */
    for(i=0; (x = small_prime_numbers[i]); i++ ) {
	if( mpi_divisible_ui( prime, x ) )
	    return 0;
    }

    /* a quick fermat test */
    {
	MPI result = mpi_alloc_like( prime );
	MPI pminus1 = mpi_alloc_like( prime );
	mpi_sub_ui( pminus1, prime, 1);
	mpi_powm( result, val_2, pminus1, prime );
	mpi_free( pminus1 );
	if( mpi_cmp_ui( result, 1 ) ) { /* if composite */
	    mpi_free( result );
	    progress('.');
	    return 0;
	}
	mpi_free( result );
    }

    /* perform stronger tests */
    if( is_prime(prime, 5, &count ) )
	return 1; /* is probably a prime */
    progress('.');
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
            char *p;
            
            p = get_random_bits( nbits, 0, 0 );
            mpi_set_buffer( x, p, (nbits+7)/8, 0 );
            xfree(p);

	    /* Make sure that the number is smaller than the prime
	     * and keep the randomness of the high bit.  */
	    if( mpi_test_bit( x, nbits-2 ) ) {
		mpi_set_highbit( x, nbits-2 ); /* Clear all higher bits */
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
	progress('+');
    }
    rc = 1; /* may be a prime */

  leave:
    mpi_free( x );
    mpi_free( y );
    mpi_free( z );
    mpi_free( nminus1 );
    mpi_free( q );
    mpi_free (a2);

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

