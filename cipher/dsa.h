/* dsa.h  -  DSA signature scheme
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
#ifndef G10_DSA_H
#define G10_DSA_H

#include "mpi.h"

typedef struct {
    MPI p;	    /* prime */
    MPI q;	    /* group order */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
} DSA_public_key;


typedef struct {
    MPI p;	    /* prime */
    MPI q;	    /* group order */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
    MPI x;	    /* secret exponent */
} DSA_secret_key;


void dsa_free_public_key( DSA_public_key *pk );
void dsa_free_secret_key( DSA_secret_key *sk );
void dsa_generate( DSA_public_key *pk, DSA_secret_key *sk, unsigned nbits );
int  dsa_check_secret_key( DSA_secret_key *sk );
void dsa_sign(MPI a, MPI b, MPI input, DSA_secret_key *skey);
int  dsa_verify(MPI a, MPI b, MPI input, DSA_public_key *pkey);

#endif /*G10_DSA_H*/
