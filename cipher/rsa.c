/* rsa.c  -  RSA function
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * ATTENTION: This code should not be exported from the United States
 * nor should it be used their without a license agreement with PKP.
 * The RSA alorithm is protected by U.S. Patent #4,405,829 which
 * expires on September 20, 2000!
 *
 * For a description of the algorithm, see:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. Pages 466 ff.
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


void
rsa_free_public_key( RSA_public_key *pk )
{
    mpi_free( pk->n ); pk->n = NULL;
    mpi_free( pk->e ); pk->e = NULL;
}

void
rsa_free_secret_key( RSA_secret_key *sk )
{
    mpi_free( sk->e ); sk->e = NULL;
    mpi_free( sk->n ); sk->n = NULL;
    mpi_free( sk->p ); sk->p = NULL;
    mpi_free( sk->q ); sk->q = NULL;
    mpi_free( sk->d ); sk->d = NULL;
    mpi_free( sk->u ); sk->u = NULL;
}


static void
test_keys( RSA_public_key *pk, RSA_secret_key *sk, unsigned nbits )
{
    MPI test = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out1 = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out2 = mpi_alloc( nbits / BITS_PER_MPI_LIMB );

    mpi_set_bytes( test, nbits, get_random_byte, 0 );

    rsa_public( out1, test, pk );
    rsa_secret( out2, out1, sk );
    if( mpi_cmp( test, out2 ) )
	log_fatal("RSA operation: public, secret failed\n");
    rsa_secret( out1, test, sk );
    rsa_public( out2, out1, pk );
    if( mpi_cmp( test, out2 ) )
	log_fatal("RSA operation: secret, public failed\n");
    mpi_free( test );
    mpi_free( out1 );
    mpi_free( out2 );
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 */
void
rsa_generate( RSA_public_key *pk, RSA_secret_key *sk, unsigned nbits )
{
    MPI p, q; /* the two primes */
    MPI d;    /* the private key */
    MPI u;
    MPI t1, t2;
    MPI n;    /* the public key */
    MPI e;    /* the exponent */
    MPI phi;  /* helper: (p-a)(q-1) */

    /* select two (very secret) primes */
    p = generate_random_prime( nbits / 2 );
    q = generate_random_prime( nbits / 2 );
    if( mpi_cmp( p, q ) > 0 ) /* p shall be smaller than q */
	mpi_swap(p,q);
    /* calculate phi = (p-1)(q-1) */
    t1 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    t2 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    phi = mpi_alloc_secure( nbits / BITS_PER_MPI_LIMB  );
    mpi_sub_ui( t1, p, 1 );
    mpi_sub_ui( t2, q, 1 );
    mpi_mul( phi, t1, t2 );
    /* multiply them to make the private key */
    n = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    mpi_mul( n, p, q );
    /* find a public exponent  */
    e = mpi_alloc(1);
    mpi_set_ui( e, 17); /* start with 17 */
    while( !mpi_gcd(t1, e, phi) ) { /* (while gcd is not 1) */
	if( DBG_CIPHER )
	    log_mpidump("trying e=", e);
	mpi_add_ui( e, e, 2);
    }
    /* calculate the secret key d = e^1 mod phi */
    d = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    mpi_inv_mod(d, e, phi );
    /* calculate the inverse of p and q (used for chinese remainder theorem)*/
    u = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    mpi_inv_mod(u, p, q );

    if( DBG_CIPHER ) {
	log_mpidump("p=", p );
	log_mpidump("q=", q );
	log_mpidump("phi=", phi );
	log_mpidump("n=", n );
	log_mpidump("e=", e );
	log_mpidump("d=", d );
	log_mpidump("u=", u );
    }

    mpi_free(t1);
    mpi_free(t2);
    mpi_free(phi);

    pk->n = mpi_copy(n);
    pk->e = mpi_copy(e);
    sk->n = n;
    sk->e = e;
    sk->p = p;
    sk->q = q;
    sk->d = d;
    sk->u = u;

    /* now we can test our keys (this should never fail!) */
    test_keys( pk, sk, nbits - 16 );
}




/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
void
rsa_public(MPI output, MPI input, RSA_public_key *pkey )
{
    if( output == input ) { /* powm doesn't like output and input the same */
	MPI x = mpi_alloc( mpi_get_nlimbs(input)*2 );
	mpi_powm( x, input, pkey->e, pkey->n );
	mpi_set(output, x);
	mpi_free(x);
    }
    else
	mpi_powm( output, input, pkey->e, pkey->n );
}

/****************
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *	m = c^d mod n
 *
 * Where m is OUTPUT, c is INPUT and d,n are elements of PKEY.
 *
 * FIXME: We should better use the Chinese Remainder Theorem
 */
void
rsa_secret(MPI output, MPI input, RSA_secret_key *skey )
{
    mpi_powm( output, input, skey->d, skey->n );
}



