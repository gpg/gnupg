/* rsa.h
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * ATTENTION: This code should not be exported from the United States
 * nor should it be used their without a license agreement with PKP.
 * The RSA alorithm is protected by U.S. Patent #4,405,829 which
 * expires on September 20, 2000!
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
#ifndef G10_RSA_H
#define G10_RSA_H

#include "mpi.h"

typedef struct {
    MPI e;	    /* exponent */
    MPI n;	    /* modulus */
} RSA_public_key;


typedef struct {
    MPI e;	    /* public exponent */
    MPI n;	    /* public modulus */
    MPI p;	    /* prime  p. */
    MPI q;	    /* prime  q. */
    MPI d;	    /* exponent */
    MPI u;	    /* inverse of p mod q. */
} RSA_secret_key;


void rsa_free_public_key( RSA_public_key *pk );
void rsa_free_secret_key( RSA_secret_key *sk );
void rsa_generate( RSA_public_key *pk, RSA_secret_key *sk, unsigned nbits );
void rsa_public(MPI output, MPI input, RSA_public_key *skey );
void rsa_secret(MPI output, MPI input, RSA_secret_key *skey );


#endif /*G10_RSA_H*/
