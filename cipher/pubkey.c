/* pubkey.c  -	pubkey dispatcher
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
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "errors.h"
#include "mpi.h"
#include "cipher.h"
#include "dynload.h"


/****************
 * This is the interface for the public key decryption.
 * ALGO gives the algorithm to use and this implicitly determines
 * the size of the arrays.
 * result is a pointer to a mpi variable which will receive a
 * newly allocated mpi or NULL in case of an error.
 */
int
pubkey_decrypt( int algo, MPI *result, int ndata, MPI *data,
				       int nskey, MPI *skey )
{
    MPI plain = NULL;

    *result = NULL; /* so the caller can do always do an mpi_free */
    if( DBG_CIPHER ) {
	int i;
	log_debug("pubkey_decrypt: algo=%d\n", algo );
	for(i=0; i < nskey; i++ )
	    log_mpidump("  skey:", skey[i] );
	for(i=0; i < ndata; i++ )
	    log_mpidump("  data:", data[i] );
    }
    if( is_ELGAMAL(algo) ) {
	ELG_secret_key sk;
	assert( ndata == 2 && nskey == 4 );
	sk.p = skey[0];
	sk.g = skey[1];
	sk.y = skey[2];
	sk.x = skey[3];
	plain = mpi_alloc_secure( mpi_get_nlimbs( sk.p ) );
	elg_decrypt( plain, data[0], data[1], &sk );
    }
    else if( is_RSA(k->pubkey_algo) ) {
	RSA_secret_key sk;
	assert( ndata == 1 && nskey == 6 );
	sk.e = skey[0];
	sk.n = skey[1];
	sk.p = skey[2];
	sk.q = skey[3];
	sk.d = skey[4];
	sk.u = skey[5];
	plain = mpi_alloc_secure( mpi_get_nlimbs(sk.n) );
	rsa_secret( plain, data[0], &sk );
    }
    else
	return G10ERR_PUBKEY_ALGO;
    *result = plain;
    return 0;
}


