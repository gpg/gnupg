/* dsa.c  -  DSA signature scheme
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
#include "util.h"
#include "mpi.h"
#include "cipher.h"
#include "dsa.h"


void
dsa_free_public_key( DSA_public_key *pk )
{
    mpi_free( pk->p ); pk->p = NULL;
    mpi_free( pk->g ); pk->g = NULL;
    mpi_free( pk->y ); pk->y = NULL;
}

void
dsa_free_secret_key( DSA_secret_key *sk )
{
    mpi_free( sk->p ); sk->p = NULL;
    mpi_free( sk->g ); sk->g = NULL;
    mpi_free( sk->y ); sk->y = NULL;
    mpi_free( sk->x ); sk->x = NULL;
}


static void
test_keys( DSA_public_key *pk, DSA_secret_key *sk, unsigned nbits )
{
    MPI test = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out1_a = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out1_b = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out2 = mpi_alloc( nbits / BITS_PER_MPI_LIMB );

    mpi_set_bytes( test, nbits, get_random_byte, 0 );

    dsa_sign( out1_a, out1_b, test, sk );
    if( !dsa_verify( out1_a, out1_b, test, pk ) )
	log_fatal("DSA operation: sign, verify failed\n");

    mpi_free( test );
    mpi_free( out1_a );
    mpi_free( out1_b );
    mpi_free( out2 );
}


/****************
 * generate a random secret exponent k from prime p, so
 * that k is relatively prime to p-1
 */
static MPI
gen_k( MPI p )
{
    MPI k = mpi_alloc_secure( mpi_get_nlimbs(p) );
    MPI temp = mpi_alloc( mpi_get_nlimbs(p) );
    MPI p_1 = mpi_copy(p);
    unsigned nbits = mpi_get_nbits(p);

    if( DBG_CIPHER )
	log_debug("choosing a random k ");
    mpi_sub_ui( p_1, p, 1);
    for(;;) {
	if( DBG_CIPHER )
	    fputc('.', stderr);
	mpi_set_bytes( k, nbits, get_random_byte, 1 );
	mpi_set_bit( k, nbits-1 ); /* make sure it's high (really needed?) */
	if( mpi_cmp( k, p_1 ) >= 0 )
	    continue; /* is not smaller than (p-1) */
	if( mpi_gcd( temp, k, p_1 ) )
	    break;  /* okay, k is relatively prime to (p-1) */
    }
    if( DBG_CIPHER )
	fputc('\n', stderr);
    mpi_free(p_1);
    mpi_free(temp);

    return k;
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 */
void
dsa_generate( DSA_public_key *pk, DSA_secret_key *sk, unsigned nbits )
{
    MPI p;    /* the prime */
    MPI g;
    MPI x;    /* the secret exponent */
    MPI y;

    p = generate_public_prime( nbits );
    /* FIXME: check wether we shall assert that (p-1)/2 is also prime
     *	      Schneier votes against it
     */
    g = mpi_alloc_set_ui(3);

    /* select a random number */
    x = mpi_alloc_secure( nbits/BITS_PER_MPI_LIMB );
    if( DBG_CIPHER )
	log_debug("choosing a random x ");
    do {
	if( DBG_CIPHER )
	    fputc('.', stderr);
	mpi_set_bytes( x, nbits, get_random_byte, 1 ); /* fixme: should be 2 */
	mpi_set_bit( x, nbits-1 ); /* make sure it's high (needed?) */
    } while( mpi_cmp( x, p ) >= 0 );  /* x must be smaller than p */

    y = mpi_alloc(nbits/BITS_PER_MPI_LIMB);
    mpi_powm( y, g, x, p );

    if( DBG_CIPHER ) {
	fputc('\n', stderr);
	log_mpidump("dsa  p= ", p );
	log_mpidump("dsa  g= ", g );
	log_mpidump("dsa  y= ", y );
	log_mpidump("dsa  x= ", x );
    }


    /* copy the stuff to the key structures */
    pk->p = mpi_copy(p);
    pk->g = mpi_copy(g);
    pk->y = mpi_copy(y);
    sk->p = p;
    sk->g = g;
    sk->y = y;
    sk->x = x;

    /* now we can test our keys (this should never fail!) */
    test_keys( pk, sk, nbits - 64 );
}


/****************
 * Test wether the secret key is valid.
 * Returns: if this is a valid key.
 */
int
dsa_check_secret_key( DSA_secret_key *sk )
{
    int rc;
    MPI y = mpi_alloc( mpi_get_nlimbs(sk->y) );

    mpi_powm( y, sk->g, sk->x, sk->p );
    rc = !mpi_cmp( y, sk->y );
    mpi_free( y );
    return rc;
}



/****************
 * Make an Elgamal signature out of INPUT
 */

void
dsa_sign(MPI a, MPI b, MPI input, DSA_secret_key *skey )
{
    MPI k;
    MPI t   = mpi_alloc( mpi_get_nlimbs(a) );
    MPI inv = mpi_alloc( mpi_get_nlimbs(a) );
    MPI p_1 = mpi_copy(skey->p);

   /*
    * b = (t * inv) mod (p-1)
    * b = (t * inv(k,(p-1),(p-1)) mod (p-1)
    * b = (((M-x*a) mod (p-1)) * inv(k,(p-1),(p-1))) mod (p-1)
    *
    */
    mpi_sub_ui(p_1, p_1, 1);
    k = gen_k( skey->p );
    mpi_powm( a, skey->g, k, skey->p );
    mpi_mul(t, skey->x, a );
    mpi_subm(t, input, t, p_1 );
    while( mpi_is_neg(t) )
	mpi_add(t, t, p_1);
    mpi_invm(inv, k, p_1 );
    mpi_mulm(b, t, inv, p_1 );

  #if 0
    if( DBG_CIPHER ) {
	log_mpidump("dsa sign p= ", skey->p);
	log_mpidump("dsa sign g= ", skey->g);
	log_mpidump("dsa sign y= ", skey->y);
	log_mpidump("dsa sign x= ", skey->x);
	log_mpidump("dsa sign k= ", k);
	log_mpidump("dsa sign M= ", input);
	log_mpidump("dsa sign a= ", a);
	log_mpidump("dsa sign b= ", b);
    }
  #endif
    mpi_free(k);
    mpi_free(t);
    mpi_free(inv);
    mpi_free(p_1);
}


/****************
 * Returns true if the signature composed from A and B is valid.
 */
int
dsa_verify(MPI a, MPI b, MPI input, DSA_public_key *pkey )
{
    int rc;
    MPI t1 = mpi_alloc( mpi_get_nlimbs(a) );
    MPI t2 = mpi_alloc( mpi_get_nlimbs(a) );

    mpi_powm( t1, pkey->y, a, pkey->p );
    mpi_powm( t2, a, b, pkey->p );
    mpi_mulm( t1, t1, t2, pkey->p );

    mpi_powm( t2, pkey->g, input, pkey->p );

    rc = !mpi_cmp( t1, t2 );

    mpi_free(t1);
    mpi_free(t2);
    return rc;
}

