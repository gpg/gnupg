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
#include "../cipher/sha1.h"
#ifdef HAVE_RSA_CIPHER
  #include "../cipher/rsa.h"
#endif
#include "../cipher/blowfish.h"
#include "../cipher/gost.h"
#include "../cipher/elgamal.h"


#define CIPHER_ALGO_NONE	 0
#define CIPHER_ALGO_IDEA	 1
#define CIPHER_ALGO_3DES	 2
#define CIPHER_ALGO_CAST	 3
#define CIPHER_ALGO_BLOWFISH128  4  /* blowfish 128 bit key */
#define CIPHER_ALGO_ROT_N	 5
#define CIPHER_ALGO_SAFER_SK128  6
#define CIPHER_ALGO_DES_SK	 7
#define CIPHER_ALGO_BLOWFISH	42  /* blowfish 160 bit key (not in OpenPGP)*/
#define CIPHER_ALGO_GOST	43  /* (Not in OpenPGP) */

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

typedef struct {
    int algo;	/* digest algo */
    union {
      MD5HANDLE md5;
      RMDHANDLE rmd;
      SHA1HANDLE sha1;
    } u;
    int datalen;
    char data[1];
} MD_HANDLE;


int cipher_debug_mode;

#ifdef HAVE_RSA_CIPHER
  #define is_valid_pubkey_algo(a) ( (a) == PUBKEY_ALGO_ELGAMAL	\
				    || (a) == PUBKEY_ALGO_RSA )
#else
  #define is_valid_pubkey_algo(a) ( (a) == PUBKEY_ALGO_ELGAMAL	)
#endif

/*-- misc.c --*/
int string_to_cipher_algo( const char *string );
int string_to_pubkey_algo( const char *string );
int string_to_digest_algo( const char *string );
int check_cipher_algo( int algo );
int check_pubkey_algo( int algo );
int check_digest_algo( int algo );

/*-- md.c --*/
int md_okay( int algo );
MD_HANDLE *md_open( int algo, int secure );
MD_HANDLE *md_copy( MD_HANDLE *a );
MD_HANDLE *md_makecontainer( int algo ); /* used for a bad kludge */
void md_write( MD_HANDLE *a, byte *inbuf, size_t inlen);
void md_putchar( MD_HANDLE *a, int c );
byte *md_final(MD_HANDLE *a);
void md_close(MD_HANDLE *a);

MD_HANDLE *md5_copy2md( MD5HANDLE a ); /* (in md5.c) */
MD_HANDLE *rmd160_copy2md( RMDHANDLE a ); /* (in rmd160.c) */

/*-- random.c --*/
void randomize_buffer( byte *buffer, size_t length, int level );
byte get_random_byte( int level );

/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- primegen.c --*/
MPI generate_secret_prime( unsigned nbits );
MPI generate_public_prime( unsigned nbits );
MPI generate_elg_prime( unsigned pbits, unsigned qbits, MPI g );


#endif /*G10_CIPHER_H*/
