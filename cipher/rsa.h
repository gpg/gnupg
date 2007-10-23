/* rsa.h
 *	Copyright (C) 1997,1998 by Werner Koch (dd9jn)
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

#ifndef G10_RSA_H
#define G10_RSA_H

int rsa_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors );
int rsa_check_secret_key( int algo, MPI *skey );
int rsa_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey );
int rsa_decrypt( int algo, MPI *result, MPI *data, MPI *skey );
int rsa_sign( int algo, MPI *resarr, MPI data, MPI *skey );
int rsa_verify( int algo, MPI hash, MPI *data, MPI *pkey );
unsigned rsa_get_nbits( int algo, MPI *pkey );
const char *rsa_get_info( int algo, int *npkey, int *nskey,
				    int *nenc, int *nsig, int *use );

#endif /*G10_RSA_H*/
