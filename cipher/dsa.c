/* dsa.c  -  DSA signature scheme
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
#include "util.h"
#include "mpi.h"
#include "cipher.h"
#include "dsa.h"


void
dsa_free_public_key( DSA_public_key *pk )
{
    mpi_free( pk->p ); pk->p = NULL;
    mpi_free( pk->q ); pk->q = NULL;
    mpi_free( pk->g ); pk->g = NULL;
    mpi_free( pk->y ); pk->y = NULL;
}

void
dsa_free_secret_key( DSA_secret_key *sk )
{
    mpi_free( sk->p ); sk->p = NULL;
    mpi_free( sk->q ); sk->q = NULL;
    mpi_free( sk->g ); sk->g = NULL;
    mpi_free( sk->y ); sk->y = NULL;
    mpi_free( sk->x ); sk->x = NULL;
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
 * Make a DSA signature out of INPUT
 */

void
dsa_sign(MPI r, MPI s, MPI input, DSA_secret_key *skey )
{
}


/****************
 * Returns true if the signature composed from R and S is valid.
 */
int
dsa_verify(MPI r, MPI s, MPI input, DSA_public_key *pkey )
{
    int rc;
    MPI w, u1, u2, v;
    MPI base[3];
    MPI exp[3];

    if( !(mpi_cmp_ui( r, 0 ) > 0 && mpi_cmp( r, pkey->q ) < 0) )
	return 0; /* assertion	0 < r < q  failed */
    if( !(mpi_cmp_ui( s, 0 ) > 0 && mpi_cmp( s, pkey->q ) < 0) )
	return 0; /* assertion	0 < s < q  failed */

    w  = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    u1 = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    u2 = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    v  = mpi_alloc( mpi_get_nlimbs(pkey->p) );

    /* w = s^(-1) mod q */
    mpi_invm( w, s, pkey->q );

    /* u1 = (input * w) mod q */
    mpi_mulm( u1, input, w, pkey->q );

    /* u2 = r * w mod q  */
    mpi_mulm( u2, r, w, pkey->q );

    /* v =  g^u1 * y^u2 mod p mod q */
    base[0] = pkey->g; exp[0] = u1;
    base[1] = pkey->y; exp[1] = u2;
    base[2] = NULL;    exp[2] = NULL;
    mpi_mulpowm( v, base, exp, pkey->p );
    mpi_fdiv_r( v, v, pkey->q );

    rc = !mpi_cmp( v, r );

    mpi_free(w);
    mpi_free(u1);
    mpi_free(u2);
    mpi_free(v);
    return rc;
}

