/* elgamal.c  -  ElGamal Public Key encryption
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * For a description of the algorithm, see:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. Pages 476 ff.
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
#include "elgamal.h"


void
elg_free_public_key( ELG_public_key *pk )
{
    mpi_free( pk->p ); pk->p = NULL;
    mpi_free( pk->g ); pk->g = NULL;
    mpi_free( pk->y ); pk->y = NULL;
}

void
elg_free_secret_key( ELG_secret_key *sk )
{
    mpi_free( sk->p ); sk->p = NULL;
    mpi_free( sk->g ); sk->g = NULL;
    mpi_free( sk->y ); sk->y = NULL;
    mpi_free( sk->x ); sk->x = NULL;
}


static void
test_keys( ELG_public_key *pk, ELG_secret_key *sk, unsigned nbits )
{
    MPI test = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out1_a = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out1_b = mpi_alloc( nbits / BITS_PER_MPI_LIMB );
    MPI out2 = mpi_alloc( nbits / BITS_PER_MPI_LIMB );

    mpi_set_bytes( test, nbits, get_random_byte, 0 );

    elg_encrypt( out1_a, out1_b, test, pk );
    elg_decrypt( out2, out1_a, out1_b, sk );
    if( mpi_cmp( test, out2 ) )
	log_fatal("ElGamal operation: encrypt, decrypt failed\n");

    elg_sign( out1_a, out1_b, test, sk );
    if( !elg_verify( out1_a, out1_b, test, pk ) )
	log_fatal("ElGamal operation: sign, verify failed\n");

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
	mpi_set_bytes( k, nbits , get_random_byte, 1 );
	if( !(mpi_cmp( k, p_1 ) < 0) )	/* check: k < (p-1) */
	    continue; /* no  */
	if( !(mpi_cmp_ui( k, 0 ) > 0) ) /* check: k > 0 */
	    continue; /* no */
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
 *	    and an array with n-1 factors of (p-1)
 */
void
elg_generate( ELG_public_key *pk, ELG_secret_key *sk,
	      unsigned nbits, MPI **ret_factors )
{
    MPI p;    /* the prime */
    MPI p_min1;
    MPI g;
    MPI x;    /* the secret exponent */
    MPI y;
    MPI temp;
    unsigned qbits;

    p_min1 = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    temp   = mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB );
    if( nbits < 512 )
	qbits = 120;
    else if( nbits <= 1024 )
	qbits = 160;
    else if( nbits <= 2048 )
	qbits = 200;
    else
	qbits = 240;
    g = mpi_alloc(1);
    p = generate_elg_prime( nbits, qbits, g, ret_factors );
    mpi_sub_ui(p_min1, p, 1);


    /* select a random number which has these properties:
     *	 0 < x < p-1
     * This must be a very good random number because this is the
     * secret part.  The prime is public and may be shared anyware,
     * so a random generator level of 1 has been used for the prime
     */
    x = mpi_alloc_secure( nbits/BITS_PER_MPI_LIMB );
    if( DBG_CIPHER )
	log_debug("choosing a random x ");
    do {
	if( DBG_CIPHER )
	    fputc('.', stderr);
	mpi_set_bytes( x, nbits, get_random_byte, 2 );
    } while( !( mpi_cmp_ui( x, 0 )>0 && mpi_cmp( x, p_min1 )<0 ) );

    y = mpi_alloc(nbits/BITS_PER_MPI_LIMB);
    mpi_powm( y, g, x, p );

    if( DBG_CIPHER ) {
	fputc('\n', stderr);
	log_mpidump("elg  p= ", p );
	log_mpidump("elg  g= ", g );
	log_mpidump("elg  y= ", y );
	log_mpidump("elg  x= ", x );
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

    mpi_free( p_min1 );
    mpi_free( temp   );
}


/****************
 * Test wether the secret key is valid.
 * Returns: if this is a valid key.
 */
int
elg_check_secret_key( ELG_secret_key *sk )
{
    int rc;
    MPI y = mpi_alloc( mpi_get_nlimbs(sk->y) );

    mpi_powm( y, sk->g, sk->x, sk->p );
    rc = !mpi_cmp( y, sk->y );
    mpi_free( y );
    return rc;
}


void
elg_encrypt(MPI a, MPI b, MPI input, ELG_public_key *pkey )
{
    MPI k;

    k = gen_k( pkey->p );
    mpi_powm( a, pkey->g, k, pkey->p );
    /* b = (y^k * input) mod p
     *	 = ((y^k mod p) * (input mod p)) mod p
     * and because input is < p  (FIXME: check this!)
     *	 = ((y^k mod p) * input) mod p
     */
    mpi_powm( b, pkey->y, k, pkey->p );
    mpi_mulm( b, b, input, pkey->p );
  #if 0
    if( DBG_CIPHER ) {
	log_mpidump("elg encrypted y= ", pkey->y);
	log_mpidump("elg encrypted p= ", pkey->p);
	log_mpidump("elg encrypted k= ", k);
	log_mpidump("elg encrypted M= ", input);
	log_mpidump("elg encrypted a= ", a);
	log_mpidump("elg encrypted b= ", b);
    }
  #endif
    mpi_free(k);
}




void
elg_decrypt(MPI output, MPI a, MPI b, ELG_secret_key *skey )
{
    MPI t1 = mpi_alloc_secure( mpi_get_nlimbs( skey->p ) );

    /* output = b/(a^x) mod p */

    mpi_powm( t1, a, skey->x, skey->p );
    mpi_invm( t1, t1, skey->p );
    mpi_mulm( output, b, t1, skey->p );
  #if 0
    if( DBG_CIPHER ) {
	log_mpidump("elg decrypted x= ", skey->x);
	log_mpidump("elg decrypted p= ", skey->p);
	log_mpidump("elg decrypted a= ", a);
	log_mpidump("elg decrypted b= ", b);
	log_mpidump("elg decrypted M= ", output);
    }
  #endif
    mpi_free(t1);
}


/****************
 * Make an Elgamal signature out of INPUT
 */

void
elg_sign(MPI a, MPI b, MPI input, ELG_secret_key *skey )
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
	log_mpidump("elg sign p= ", skey->p);
	log_mpidump("elg sign g= ", skey->g);
	log_mpidump("elg sign y= ", skey->y);
	log_mpidump("elg sign x= ", skey->x);
	log_mpidump("elg sign k= ", k);
	log_mpidump("elg sign M= ", input);
	log_mpidump("elg sign a= ", a);
	log_mpidump("elg sign b= ", b);
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
elg_verify(MPI a, MPI b, MPI input, ELG_public_key *pkey )
{
    int rc;
    MPI t1;
    MPI t2;
    MPI base[4];
    MPI exp[4];

    if( !(mpi_cmp_ui( a, 0 ) > 0 && mpi_cmp( a, pkey->p ) < 0) )
	return 0; /* assertion	0 < a < p  failed */

    t1 = mpi_alloc( mpi_get_nlimbs(a) );
    t2 = mpi_alloc( mpi_get_nlimbs(a) );

  #if 0
    /* t1 = (y^a mod p) * (a^b mod p) mod p */
    mpi_powm( t1, pkey->y, a, pkey->p );
    mpi_powm( t2, a, b, pkey->p );
    mpi_mulm( t1, t1, t2, pkey->p );

    /* t2 = g ^ input mod p */
    mpi_powm( t2, pkey->g, input, pkey->p );

    rc = !mpi_cmp( t1, t2 );
  #elif 0
    /* t1 = (y^a mod p) * (a^b mod p) mod p */
    base[0] = pkey->y; exp[0] = a;
    base[1] = a;       exp[1] = b;
    base[2] = NULL;    exp[2] = NULL;
    mpi_mulpowm( t1, base, exp, pkey->p );

    /* t2 = g ^ input mod p */
    mpi_powm( t2, pkey->g, input, pkey->p );

    rc = !mpi_cmp( t1, t2 );
  #else
    /* t1 = g ^ - input * y ^ a * a ^ b  mod p */
    mpi_invm(t2, pkey->g, pkey->p );
    base[0] = t2     ; exp[0] = input;
    base[1] = pkey->y; exp[1] = a;
    base[2] = a;       exp[2] = b;
    base[3] = NULL;    exp[3] = NULL;
    mpi_mulpowm( t1, base, exp, pkey->p );
    rc = !mpi_cmp_ui( t1, 1 );

  #endif

    mpi_free(t1);
    mpi_free(t2);
    return rc;
}

