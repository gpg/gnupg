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
#include "elgamal.h"


/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
void
elg_public(MPI output, MPI input, ELG_public_key *pkey )
{

}

/****************
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *
 *
 * Where m is OUTPUT, c is INPUT and d,n are elements of PKEY.
 */
void
elg_secret(MPI output, MPI input, ELG_secret_key *skey )
{

}



