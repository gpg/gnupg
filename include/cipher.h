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

#define DBG_CIPHER cipher_debug_mode

#include "mpi.h"
#include "../cipher/md.h"
#ifdef HAVE_RSA_CIPHER
  #include "../cipher/rsa.h"
#endif
#include "../cipher/blowfish.h"
#include "../cipher/cast5.h"
#include "../cipher/elgamal.h"
#include "../cipher/dsa.h"
#include "../cipher/random.h"


#define CIPHER_ALGO_NONE	 0
#define CIPHER_ALGO_IDEA	 1
#define CIPHER_ALGO_3DES	 2
#define CIPHER_ALGO_CAST	 3
#define CIPHER_ALGO_BLOWFISH128  4  /* blowfish 128 bit key */
#define CIPHER_ALGO_ROT_N	 5
#define CIPHER_ALGO_SAFER_SK128  6
#define CIPHER_ALGO_DES_SK	 7
#define CIPHER_ALGO_BLOWFISH	42  /* blowfish 160 bit key (not in OpenPGP)*/

#define PUBKEY_ALGO_RSA        1
#define PUBKEY_ALGO_RSA_E      2     /* RSA encrypt only */
#define PUBKEY_ALGO_RSA_S      3     /* RSA sign only */
#define PUBKEY_ALGO_ELGAMAL   16
#define PUBKEY_ALGO_DSA       17

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_SHA1      2
#define DIGEST_ALGO_RMD160    3


typedef struct {
    int algo;
    int keylen;
    byte key[20]; /* this is the largest used keylen */
} DEK;


int cipher_debug_mode;


/*-- misc.c --*/
int string_to_cipher_algo( const char *string );
int string_to_pubkey_algo( const char *string );
int string_to_digest_algo( const char *string );
const char * cipher_algo_to_string( int algo );
const char * pubkey_algo_to_string( int algo );
const char * digest_algo_to_string( int algo );
int check_cipher_algo( int algo );
int check_pubkey_algo( int algo );
int check_digest_algo( int algo );


/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- primegen.c --*/
MPI generate_secret_prime( unsigned nbits );
MPI generate_public_prime( unsigned nbits );
MPI generate_elg_prime( unsigned pbits, unsigned qbits, MPI g, MPI **factors );


#endif /*G10_CIPHER_H*/
