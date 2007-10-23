/* rsa.c  -  RSA function
 *	Copyright (C) 1997, 1998, 1999 by Werner Koch (dd9jn)
 *	Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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
 */

/* This code uses an algorithm protected by U.S. Patent #4,405,829
   which expires on September 20, 2000.  The patent holder placed that
   patent into the public domain on Sep 6th, 2000.
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
    MPI test = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    MPI out1 = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    MPI out2 = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );

    pk.n = sk->n;
    pk.e = sk->e;
    {	char *p = get_random_bits( nbits, 0, 0 );
	mpi_set_buffer( test, p, (nbits+7)/8, 0 );
	xfree(p);
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
 * Returns: 2 structures filled with all needed values
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
    MPI phi;  /* helper: (p-1)(q-1) */
    MPI g;
    MPI f;

    /* make sure that nbits is even so that we generate p, q of equal size */
    if ( (nbits&1) )
      nbits++; 

    n = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );

    p = q = NULL;
    do {
      /* select two (very secret) primes */
      if (p)
        mpi_free (p);
      if (q)
        mpi_free (q);
      p = generate_secret_prime( nbits / 2 );
      q = generate_secret_prime( nbits / 2 );
      if( mpi_cmp( p, q ) > 0 ) /* p shall be smaller than q (for calc of u)*/
        mpi_swap(p,q);
      /* calculate the modulus */
      mpi_mul( n, p, q );
    } while ( mpi_get_nbits(n) != nbits );

    /* calculate Euler totient: phi = (p-1)(q-1) */
    t1 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    t2 = mpi_alloc_secure( mpi_get_nlimbs(p) );
    phi = mpi_alloc_secure ( mpi_nlimb_hint_from_nbits (nbits) );
    g	= mpi_alloc_secure ( mpi_nlimb_hint_from_nbits (nbits) );
    f	= mpi_alloc_secure ( mpi_nlimb_hint_from_nbits (nbits) );
    mpi_sub_ui( t1, p, 1 );
    mpi_sub_ui( t2, q, 1 );
    mpi_mul( phi, t1, t2 );
    mpi_gcd(g, t1, t2);
    mpi_fdiv_q(f, phi, g);

    /* Find an public exponent.
       Benchmarking the RSA verify function with a 1024 bit key yields
       (2001-11-08):
         e=17    0.54 ms
         e=41    0.75 ms
         e=257   0.95 ms
         e=65537 1.80 ms

       This code used 41 until 2006-06-28 when it was changed to use
       65537 as the new best practice.  See FIPS-186-3.
     */
    e = mpi_alloc ( mpi_nlimb_hint_from_nbits (32) );
    mpi_set_ui( e, 65537); 
    while( !mpi_gcd(t1, e, phi) ) /* (while gcd is not 1) */
      mpi_add_ui( e, e, 2);

    /* calculate the secret key d = e^1 mod phi */
    d = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    mpi_invm(d, e, f );
    /* calculate the inverse of p and q (used for chinese remainder theorem)*/
    u = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
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

#if 0
static void
stronger_key_check ( RSA_secret_key *skey )
{
    MPI t = mpi_alloc_secure ( 0 );
    MPI t1 = mpi_alloc_secure ( 0 );
    MPI t2 = mpi_alloc_secure ( 0 );
    MPI phi = mpi_alloc_secure ( 0 );

    /* check that n == p * q */
    mpi_mul( t, skey->p, skey->q);
    if (mpi_cmp( t, skey->n) )
        log_info ( "RSA Oops: n != p * q\n" );

    /* check that p is less than q */
    if( mpi_cmp( skey->p, skey->q ) > 0 )
	log_info ("RSA Oops: p >= q\n");


    /* check that e divides neither p-1 nor q-1 */
    mpi_sub_ui(t, skey->p, 1 );
    mpi_fdiv_r(t, t, skey->e );
    if ( !mpi_cmp_ui( t, 0) )
        log_info ( "RSA Oops: e divides p-1\n" );
    mpi_sub_ui(t, skey->q, 1 );
    mpi_fdiv_r(t, t, skey->e );
    if ( !mpi_cmp_ui( t, 0) )
        log_info ( "RSA Oops: e divides q-1\n" );

    /* check that d is correct */
    mpi_sub_ui( t1, skey->p, 1 );
    mpi_sub_ui( t2, skey->q, 1 );
    mpi_mul( phi, t1, t2 );
    mpi_gcd(t, t1, t2);
    mpi_fdiv_q(t, phi, t);
    mpi_invm(t, skey->e, t );
    if ( mpi_cmp(t, skey->d ) )
        log_info ( "RSA Oops: d is wrong\n");

    /* check for crrectness of u */
    mpi_invm(t, skey->p, skey->q );
    if ( mpi_cmp(t, skey->u ) )
        log_info ( "RSA Oops: u is wrong\n");
   
    log_info ( "RSA secret key check finished\n");

    mpi_free (t);
    mpi_free (t1);
    mpi_free (t2);
    mpi_free (phi);
}
#endif


/****************
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *	m = c^d mod n
 *
 * Or faster:
 *
 *      m1 = c ^ (d mod (p-1)) mod p 
 *      m2 = c ^ (d mod (q-1)) mod q 
 *      h = u * (m2 - m1) mod q 
 *      m = m1 + h * p
 *
 * Where m is OUTPUT, c is INPUT and d,n,p,q,u are elements of SKEY.
 */
static void
secret(MPI output, MPI input, RSA_secret_key *skey )
{
#if 0
    mpi_powm( output, input, skey->d, skey->n );
#else
    MPI m1   = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );
    MPI m2   = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );
    MPI h    = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );

    /* m1 = c ^ (d mod (p-1)) mod p */
    mpi_sub_ui( h, skey->p, 1  );
    mpi_fdiv_r( h, skey->d, h );   
    mpi_powm( m1, input, h, skey->p );
    /* m2 = c ^ (d mod (q-1)) mod q */
    mpi_sub_ui( h, skey->q, 1  );
    mpi_fdiv_r( h, skey->d, h );
    mpi_powm( m2, input, h, skey->q );
    /* h = u * ( m2 - m1 ) mod q */
    mpi_sub( h, m2, m1 );
    if ( mpi_is_neg( h ) ) 
        mpi_add ( h, h, skey->q );
    mpi_mulm( h, skey->u, h, skey->q ); 
    /* m = m2 + h * p */
    mpi_mul ( h, h, skey->p );
    mpi_add ( output, m1, h );
    /* ready */
    
    mpi_free ( h );
    mpi_free ( m1 );
    mpi_free ( m2 );
#endif
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
    if (retfactors)
      *retfactors = xmalloc_clear( 1 * sizeof **retfactors );
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
rsa_verify( int algo, MPI hash, MPI *data, MPI *pkey )
{
    RSA_public_key pk;
    MPI result;
    int rc;

    if( algo != 1 && algo != 3 )
	return G10ERR_PUBKEY_ALGO;
    pk.n = pkey[0];
    pk.e = pkey[1];
    result = mpi_alloc ( mpi_nlimb_hint_from_nbits (160) );
    public( result, data[0], &pk );
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
	      int *npkey, int *nskey, int *nenc, int *nsig, int *r_usage )
{
    *npkey = 2;
    *nskey = 6;
    *nenc = 1;
    *nsig = 1;

    switch( algo ) {
      case 1: *r_usage = PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC; return "RSA";
      case 2: *r_usage = PUBKEY_USAGE_ENC; return "RSA-E";
      case 3: *r_usage = PUBKEY_USAGE_SIG; return "RSA-S";
      default:*r_usage = 0; return NULL;
    }
}
