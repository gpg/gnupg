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
#include "../cipher/md5.h"
#include "../cipher/rmd.h"
#ifdef HAVE_RSA_CIPHER
  #include "../cipher/rsa.h"
#endif
#include "../cipher/idea.h"
#include "../cipher/blowfish.h"
#include "../cipher/gost.h"
#include "../cipher/elgamal.h"


#define CIPHER_ALGO_NONE      0
#define CIPHER_ALGO_IDEA      1
#define CIPHER_ALGO_BLOWFISH 42
#define CIPHER_ALGO_GOST     43

#define PUBKEY_ALGO_RSA       1
#define PUBKEY_ALGO_ELGAMAL  42

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_RMD160   42

#define DEFAULT_CIPHER_ALGO  CIPHER_ALGO_BLOWFISH
#define DEFAULT_PUBKEY_ALGO  PUBKEY_ALGO_RSA
#define DEFAULT_DIGEST_ALGO  DIGEST_ALGO_RMD160

typedef struct {
    int algo;
    int keylen;
    byte key[20]; /* this is the largest used keylen */
} DEK;

typedef struct {
    int algo;	/* digest algo */
    union {
      MD5HANDLE md5;
      RMDHANDLE rmd;
    } u;
} MD_HANDLE;


int cipher_debug_mode;

/*-- random.c --*/
void randomize_buffer( byte *buffer, size_t length, int level );
byte get_random_byte( int level );

/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- primegen.c --*/
MPI generate_random_prime( unsigned nbits );

/*-- seskey.c --*/
void make_session_key( DEK *dek );
MPI encode_session_key( DEK *dek, unsigned nbits );


#endif /*G10_CIPHER_H*/
