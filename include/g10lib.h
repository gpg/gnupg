/* g10lib.h -  internal defintions for libgcrypt
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This header is to be used inside of libgcrypt in place of gcrypt.h.
 * This way we can easily distinguish between internal and external
 * usage of gcrypt.h
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

#ifndef G10LIB_H
#define G10LIB_H 1

#ifdef _GCRYPT_H
  #error  gcrypt.h already included
#endif

#include <gcrypt.h>

#ifdef G10_I18N_H
  #error i18n should not be included here
#endif

#define _(a)  g10_gettext(a)
#define N_(a) (a)

/*-- gcrypt/global.c --*/
int set_lasterr( int ec );


void *g10_malloc( size_t n );
void *g10_calloc( size_t n, size_t m );
void *g10_malloc_secure( size_t n );
void *g10_calloc_secure( size_t n, size_t m );
void *g10_realloc( void *a, size_t n );
char *g10_strdup( const char * a);
void *g10_xmalloc( size_t n );
void *g10_xcalloc( size_t n, size_t m );
void *g10_xmalloc_secure( size_t n );
void *g10_xcalloc_secure( size_t n, size_t m );
void *g10_xrealloc( void *a, size_t n );
char *g10_xstrdup( const char * a);
void  g10_free( void *p );


/*-- gcrypt/misc.c --*/
const char *g10_gettext( const char *key );
int fatal_invalid_arg(const char *text);


/*-- cipher/pubkey.c --*/

#ifndef DID_MPI_TYPEDEF
 typedef struct gcry_mpi * MPI;
 #define DID_MPI_TYPEDEF
#endif

int string_to_pubkey_algo( const char *string );
const char * pubkey_algo_to_string( int algo );
unsigned pubkey_nbits( int algo, MPI *pkey );
int pubkey_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors );
int pubkey_check_secret_key( int algo, MPI *skey );
int pubkey_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey );
int pubkey_decrypt( int algo, MPI *result, MPI *data, MPI *skey );




/*-- primegen.c --*/
MPI generate_secret_prime( unsigned nbits );
MPI generate_public_prime( unsigned nbits );
MPI generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
					   MPI g, MPI **factors );



#endif /* G10LIB_H */
