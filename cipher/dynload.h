/* dynload.5
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#ifndef G10_CIPHER_DYNLOAD_H
#define G10_CIPHER_DYNLOAD_H

#include "mpi.h"


void register_internal_cipher_extension( const char *module_id,
			      void * (*enumfunc)(int, int*, int*, int*) );

int
enum_gnupgext_digests( void **enum_context,
	    int *algo,
	    const char *(**r_get_info)( int, size_t*,byte**, int*, int*,
				       void (**)(void*),
				       void (**)(void*,byte*,size_t),
				       void (**)(void*),byte *(**)(void*)) );

const char *
enum_gnupgext_ciphers( void **enum_context, int *algo,
		       size_t *keylen, size_t *blocksize, size_t *contextsize,
		       int  (**setkeyf)( void *c, byte *key, unsigned keylen ),
		       void (**encryptf)( void *c, byte *outbuf, byte *inbuf ),
		       void (**decryptf)( void *c, byte *outbuf, byte *inbuf )
		     );


const char *
enum_gnupgext_pubkeys( void **enum_context, int *algo,
    int *npkey, int *nskey, int *nenc, int *nsig, int *use,
    int (**generate)( int algo, unsigned nbits, MPI *skey, MPI **retfactors ),
    int (**check_secret_key)( int algo, MPI *skey ),
    int (**encryptf)( int algo, MPI *resarr, MPI data, MPI *pkey ),
    int (**decryptf)( int algo, MPI *result, MPI *data, MPI *skey ),
    int (**sign)( int algo, MPI *resarr, MPI data, MPI *skey ),
    int (**verify)( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI), void *opaquev ),
    unsigned (**get_nbits)( int algo, MPI *pkey ) );


int (*dynload_getfnc_gather_random(void))( void (*)(const void*, size_t, int),
					   int, size_t, int);
void (*dynload_getfnc_fast_random_poll(void)
				)( void (*)(const void*, size_t, int), int );


/** This function is in construct.c **/
void cipher_modules_constructor(void);

#endif /*G10_CIPHER_DYNLOAD_H*/
