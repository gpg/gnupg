/* elgamal.h
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
#ifndef G10_ELGAMAL_H
#define G10_ELGAMAL_H

#include "mpi.h"

typedef struct {
    MPI e;	    /* exponent */
    MPI n;	    /* modulus */
} ELG_public_key;


typedef struct {
    MPI e;	    /* public exponent */
    MPI n;	    /* public modulus */
    MPI p;	    /* prime  p. */
    MPI q;	    /* prime  q. */
    MPI d;	    /* exponent */
    MPI u;	    /* inverse of p mod q. */
} ELG_secret_key;


void elg_public(MPI output, MPI input, ELG_public_key *skey );
void elg_secret(MPI output, MPI input, ELG_secret_key *skey );


#endif /*G10_ELGAMAL_H*/
