/* cipher.h
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
#ifndef G10_CIPHER_H
#define G10_CIPHER_H

#define DBG_CIPHER g10c_debug_mode

#include "mpi.h"
#include "../cipher/md.h"
#ifdef HAVE_RSA_CIPHER
  #include "../cipher/rsa.h"
#endif
#include "../cipher/elgamal.h"
#include "../cipher/dsa.h"
#include "../cipher/random.h"


#define CIPHER_ALGO_NONE	 0
#define CIPHER_ALGO_IDEA	 1
#define CIPHER_ALGO_3DES	 2
#define CIPHER_ALGO_CAST5	 3
#define CIPHER_ALGO_BLOWFISH	 4  /* blowfish 128 bit key */
#define CIPHER_ALGO_SAFER_SK128  5
#define CIPHER_ALGO_DES_SK	 6
#define CIPHER_ALGO_BLOWFISH160 42  /* blowfish 160 bit key (not in OpenPGP)*/
#define CIPHER_ALGO_DUMMY      110  /* no encryption at all */

#define PUBKEY_ALGO_RSA        1
#define PUBKEY_ALGO_RSA_E      2     /* RSA encrypt only */
#define PUBKEY_ALGO_RSA_S      3     /* RSA sign only */
#define PUBKEY_ALGO_ELGAMAL_E 16     /* encrypt only ElGamal (but not vor v3)*/
#define PUBKEY_ALGO_DSA       17
#define PUBKEY_ALGO_ELGAMAL   20     /* sign and encrypt elgamal */

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_SHA1      2
#define DIGEST_ALGO_RMD160    3
#ifdef WITH_TIGER_HASH
#define DIGEST_ALGO_TIGER     6
#endif

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)

typedef struct {
    int algo;
    int keylen;
    byte key[20]; /* this is the largest used keylen */
} DEK;

typedef struct cipher_handle_s *CIPHER_HANDLE;

#ifndef DEFINES_CIPHER_HANDLE
struct cipher_handle_s { char does_not_matter[1]; };
#endif

#define CIPHER_MODE_ECB       1
#define CIPHER_MODE_CFB       2
#define CIPHER_MODE_PHILS_CFB 3
#define CIPHER_MODE_AUTO_CFB  4
#define CIPHER_MODE_DUMMY     5  /* used with algo DUMMY for no encryption */


int g10c_debug_mode;
int g10_opt_verbose;

/*-- dynload.c --*/
void register_cipher_extension( const char *fname );

/*-- cipher.c --*/
int string_to_cipher_algo( const char *string );
const char * cipher_algo_to_string( int algo );
int check_cipher_algo( int algo );
unsigned cipher_get_keylen( int algo );
CIPHER_HANDLE cipher_open( int algo, int mode, int secure );
void cipher_close( CIPHER_HANDLE c );
void cipher_setkey( CIPHER_HANDLE c, byte *key, unsigned keylen );
void cipher_setiv( CIPHER_HANDLE c, const byte *iv );
void cipher_encrypt( CIPHER_HANDLE c, byte *out, byte *in, unsigned nbytes );
void cipher_decrypt( CIPHER_HANDLE c, byte *out, byte *in, unsigned nbytes );
void cipher_sync( CIPHER_HANDLE c );

/*-- pubkey.c --*/
#define PUBKEY_MAX_NPKEY  4
#define PUBKEY_MAX_NSKEY  6
#define PUBKEY_MAX_NSIG   2
#define PUBKEY_MAX_NENC   2

int string_to_pubkey_algo( const char *string );
const char * pubkey_algo_to_string( int algo );
int check_pubkey_algo( int algo );
int check_pubkey_algo2( int algo, unsigned usage );
int pubkey_get_npkey( int algo );
int pubkey_get_nskey( int algo );
int pubkey_get_nsig( int algo );
int pubkey_get_nenc( int algo );
unsigned pubkey_nbits( int algo, MPI *pkey );
int pubkey_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors );
int pubkey_check_secret_key( int algo, MPI *skey );
int pubkey_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey );
int pubkey_decrypt( int algo, MPI *result, MPI *data, MPI *skey );
int pubkey_sign( int algo, MPI *resarr, MPI hash, MPI *skey );
int pubkey_verify( int algo, MPI hash, MPI *data, MPI *pkey );

/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- primegen.c --*/
MPI generate_secret_prime( unsigned nbits );
MPI generate_public_prime( unsigned nbits );
MPI generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
					   MPI g, MPI **factors );


#endif /*G10_CIPHER_H*/
