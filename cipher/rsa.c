/* rsa.c  -  RSA function
 *	Copyright (C) 1997, 1998, 1999 by Werner Koch (dd9jn)
 *	Copyright (C) 2000 Free Software Foundation, Inc.
 ***********************************************************************
 * ATTENTION: This code should not be used in the United States
 * before the U.S. Patent #4,405,829 expires on September 20, 2000!
 ***********************************************************************
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
#include <string.h>
#include "util.h"
#include "mpi.h"
#include "cipher.h"
#include "rsa.h"


typedef struct {
    MPI n;	    /* modulus */
    MPI e;	    /* exponent */
} RSA_public_key;


typedef struct {
    MPI n;	    /* public modulus */
    MPI e;	    /* public exponent */
    MPI d;	    /* exponent */
    MPI p;	    /* prime  p. */
    MPI q;	    /* prime  q. */
    MPI u;	    /* inverse of p mod q. */
} RSA_secret_key;


static void test_keys( RSA_secret_key *sk, unsigned nbits );
static void generate( RSA_secret_key *sk, unsigned nbits );
static int  check_secret_key( RSA_secret_key *sk );
static void public(MPI output, MPI input, RSA_public_key *skey );
static void secret(MPI output, MPI input, RSA_secret_key *skey );


static void
test_keys( RSA_secret_key *sk, unsigned nbits )
{
    RSA_public_key pk;
    MPI test = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    MPI out1 = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    MPI out2 = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );

    pk.n = sk->n;
    pk.e = sk->e;
    {	char *p = get_random_bits( nbits, 0, 0 );
	mpi_set_buffer( test, p, (nbits+7)/8, 0 );
	m_free(p);
    }

    public( out1, test, &pk );
    secret( out2, out1, sk );
    if( mpi_cmp( test, out2 ) )
	log_fatal("RSA operation: public, secret failed\n");
    secret( out1, test, sk );
    public( out2, out1, &pk );
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
static void
generate( RSA_secret_key *sk, unsigned nbits )
{
    MPI p, q; /* the two primes */
    MPI d;    /* the private key */
    MPI u;
    MPI t1, t2;
    MPI n;    /* the public key */
    MPI e;    /* the exponent */
    MPI phi;  /* helper: (p-a)(q-1) */
    MPI g;
    MPI f;

    /* select two (very secret) primes */
    p = generate_secret_prime( nbits / 2 );
    q = generate_secret_prime( nbits / 2 );
    if( mpi_cmp( p, q ) > 0 ) /* p shall be smaller than q (for calc of u)*/
	mpi_swap(p,q);
    /* calculate Euler totient: phi = (p-1)(q-1) */
    t1 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    t2 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    phi = mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    g	= mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB  );
    f	= mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB  );
    mpi_sub_ui( t1, p, 1 );
    mpi_sub_ui( t2, q, 1 );
    mpi_mul( phi, t1, t2 );
    mpi_gcd(g, t1, t2);
    mpi_fdiv_q(f, phi, g);
    /* multiply them to make the private key */
    n = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    mpi_mul( n, p, q );
    /* find a public exponent  */
    e = mpi_alloc( (6+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    mpi_set_ui( e, 17); /* start with 17 */
    while( !mpi_gcd(t1, e, phi) ) /* (while gcd is not 1) */
	mpi_add_ui( e, e, 2);
    /* calculate the secret key d = e^1 mod phi */
    d = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    mpi_invm(d, e, f );
    /* calculate the inverse of p and q (used for chinese remainder theorem)*/
    u = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    mpi_invm(u, p, q );

    if( DBG_CIPHER ) {
	log_mpidump("  p= ", p );
	log_mpidump("  q= ", q );
	log_mpidump("phi= ", phi );
	log_mpidump("  g= ", g );
	log_mpidump("  f= ", f );
	log_mpidump("  n= ", n );
	log_mpidump("  e= ", e );
	log_mpidump("  d= ", d );
	log_mpidump("  u= ", u );
    }

    mpi_free(t1);
    mpi_free(t2);
    mpi_free(phi);
    mpi_free(f);
    mpi_free(g);

    sk->n = n;
    sk->e = e;
    sk->p = p;
    sk->q = q;
    sk->d = d;
    sk->u = u;

    /* now we can test our keys (this should never fail!) */
    test_keys( sk, nbits - 64 );
}


/****************
 * Test wether the secret key is valid.
 * Returns: true if this is a valid key.
 */
static int
check_secret_key( RSA_secret_key *sk )
{
    int rc;
    MPI temp = mpi_alloc( mpi_get_nlimbs(sk->p)*2 );

    mpi_mul(temp, sk->p, sk->q );
    rc = mpi_cmp( temp, sk->n );
    mpi_free(temp);
    return !rc;
}



/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
static void
public(MPI output, MPI input, RSA_public_key *pkey )
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
static void
secret(MPI output, MPI input, RSA_secret_key *skey )
{
    mpi_powm( output, input, skey->d, skey->n );
}


/*********************************************
 **************  interface  ******************
 *********************************************/

int
rsa_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{
    RSA_secret_key sk;

    if( !is_RSA(algo) )
	return G10ERR_PUBKEY_ALGO;

    generate( &sk, nbits );
    skey[0] = sk.n;
    skey[1] = sk.e;
    skey[2] = sk.d;
    skey[3] = sk.p;
    skey[4] = sk.q;
    skey[5] = sk.u;
    /* make an empty list of factors */
    *retfactors = m_alloc_clear( 1 * sizeof **retfactors );
    return 0;
}


int
rsa_check_secret_key( int algo, MPI *skey )
{
    RSA_secret_key sk;

    if( !is_RSA(algo) )
	return G10ERR_PUBKEY_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    if( !check_secret_key( &sk ) )
	return G10ERR_BAD_SECKEY;

    return 0;
}



int
rsa_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
    RSA_public_key pk;

    if( algo != 1 && algo != 2 )
	return G10ERR_PUBKEY_ALGO;

    pk.n = pkey[0];
    pk.e = pkey[1];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.n ) );
    public( resarr[0], data, &pk );
    return 0;
}

int
rsa_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    RSA_secret_key sk;

    if( algo != 1 && algo != 2 )
	return G10ERR_PUBKEY_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    *result = mpi_alloc_secure( mpi_get_nlimbs( sk.n ) );
    secret( *result, data[0], &sk );
    return 0;
}

int
rsa_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
    RSA_secret_key sk;

    if( algo != 1 && algo != 3 )
	return G10ERR_PUBKEY_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.n ) );
    secret( resarr[0], data, &sk );

    return 0;
}

int
rsa_verify( int algo, MPI hash, MPI *data, MPI *pkey,
	   int (*cmp)(void *opaque, MPI tmp), void *opaquev )
{
    RSA_public_key pk;
    MPI result;
    int rc;

    if( algo != 1 && algo != 3 )
	return G10ERR_PUBKEY_ALGO;
    pk.n = pkey[0];
    pk.e = pkey[1];
    result = mpi_alloc( (160+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB);
    public( result, data[0], &pk );
    /*rc = (*cmp)( opaquev, result );*/
    rc = mpi_cmp( result, hash )? G10ERR_BAD_SIGN:0;
    mpi_free(result);

    return rc;
}


unsigned int
rsa_get_nbits( int algo, MPI *pkey )
{
    if( !is_RSA(algo) )
	return 0;
    return mpi_get_nbits( pkey[0] );
}


/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 * Usage: Bit 0 set : allows signing
 *	      1 set : allows encryption
 */
const char *
rsa_get_info( int algo,
	      int *npkey, int *nskey, int *nenc, int *nsig, int *usage )
{
    *npkey = 2;
    *nskey = 6;
    *nenc = 1;
    *nsig = 1;

    switch( algo ) {
      case 1: *usage = PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC; return "RSA";
      case 2: *usage = PUBKEY_USAGE_ENC; return "RSA-E";
      case 3: *usage = PUBKEY_USAGE_SIG; return "RSA-S";
      default:*usage = 0; return NULL;
    }
}

