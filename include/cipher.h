/* cipher.h
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
#include "../cipher/random.h"


#define CIPHER_ALGO_NONE	 0
#define CIPHER_ALGO_IDEA	 1
#define CIPHER_ALGO_3DES	 2
#define CIPHER_ALGO_CAST5	 3
#define CIPHER_ALGO_BLOWFISH	 4  /* blowfish 128 bit key */
#define CIPHER_ALGO_SAFER_SK128  5
#define CIPHER_ALGO_DES_SK	 6
#define CIPHER_ALGO_TWOFISH	10  /* twofish 256 bit */
#define CIPHER_ALGO_SKIPJACK   101  /* experimental: skipjack */
#define CIPHER_ALGO_TWOFISH_OLD 102 /* experimental: twofish 128 bit */
#define CIPHER_ALGO_DUMMY      110  /* no encryption at all */

#define PUBKEY_ALGO_RSA        1
#define PUBKEY_ALGO_RSA_E      2     /* RSA encrypt only */
#define PUBKEY_ALGO_RSA_S      3     /* RSA sign only */
#define PUBKEY_ALGO_ELGAMAL_E 16     /* encrypt only ElGamal (but not for v3)*/
#define PUBKEY_ALGO_DSA       17
#define PUBKEY_ALGO_ELGAMAL   20     /* sign and encrypt elgamal */

#define PUBKEY_USAGE_SIG     1	    /* key is good for signatures */
#define PUBKEY_USAGE_ENC     2	    /* key is good for encryption */

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_SHA1      2
#define DIGEST_ALGO_RMD160    3
#define DIGEST_ALGO_TIGER     6

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)

typedef struct {
    int algo;
    int keylen;
    byte key[32]; /* this is the largest used keylen (256 bit) */
} DEK;

struct cipher_handle_s;
typedef struct cipher_handle_s *CIPHER_HANDLE;


#define CIPHER_MODE_ECB       1
#define CIPHER_MODE_CFB       2
#define CIPHER_MODE_PHILS_CFB 3
#define CIPHER_MODE_AUTO_CFB  4
#define CIPHER_MODE_DUMMY     5  /* used with algo DUMMY for no encryption */
#define CIPHER_MODE_CBC       6

struct md_digest_list_s;

struct gcry_md_context {
    int  secure;
    FILE  *debug;
    int finalized;
    struct md_digest_list_s *list;
    int  bufcount;
    int  bufsize;
    byte buffer[1];
};

typedef struct gcry_md_context *MD_HANDLE;


int g10c_debug_mode;
int g10_opt_verbose;
const char *g10_opt_homedir;

/*-- dynload.c --*/
void register_cipher_extension( const char *mainpgm, const char *fname );

/*-- md.c --*/
int string_to_digest_algo( const char *string );
const char * digest_algo_to_string( int algo );
int check_digest_algo( int algo );
MD_HANDLE md_open( int algo, int secure );
void md_enable( MD_HANDLE hd, int algo );
MD_HANDLE md_copy( MD_HANDLE a );
void md_reset( MD_HANDLE a );
void md_close(MD_HANDLE a);
void md_write( MD_HANDLE a, byte *inbuf, size_t inlen);
void md_final(MD_HANDLE a);
byte *md_read( MD_HANDLE a, int algo );
int md_digest( MD_HANDLE a, int algo, byte *buffer, int buflen );
int md_get_algo( MD_HANDLE a );
int md_digest_length( int algo );
const byte *md_asn_oid( int algo, size_t *asnlen, size_t *mdlen );
void md_start_debug( MD_HANDLE a, const char *suffix );
void md_stop_debug( MD_HANDLE a );
#define md_is_secure(a) ((a)->secure)
#define md_putc(h,c)  \
	    do {					    \
		if( (h)->bufcount == (h)->bufsize )	    \
		    md_write( (h), NULL, 0 );		    \
		(h)->buffer[(h)->bufcount++] = (c) & 0xff;  \
	    } while(0)
/*-- rmd160.c --*/
void rmd160_hash_buffer( char *outbuf, const char *buffer, size_t length );


/*-- cipher.c --*/
int string_to_cipher_algo( const char *string );
const char * cipher_algo_to_string( int algo );
void disable_cipher_algo( int algo );
int check_cipher_algo( int algo );
unsigned cipher_get_keylen( int algo );
unsigned cipher_get_blocksize( int algo );
CIPHER_HANDLE cipher_open( int algo, int mode, int secure );
void cipher_close( CIPHER_HANDLE c );
int  cipher_setkey( CIPHER_HANDLE c, byte *key, unsigned keylen );
void cipher_setiv( CIPHER_HANDLE c, const byte *iv, unsigned ivlen );
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
void disable_pubkey_algo( int algo );
int check_pubkey_algo( int algo );
int check_pubkey_algo2( int algo, unsigned use );
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
int pubkey_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		      int (*cmp)(void *, MPI), void *opaque );

/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- primegen.c --*/
void register_primegen_progress ( void (*cb)( void *, int), void *cb_data );
MPI generate_secret_prime( unsigned nbits );
MPI generate_public_prime( unsigned nbits );
MPI generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
					   MPI g, MPI **factors );

/*-- elsewhere --*/
void register_pk_dsa_progress ( void (*cb)( void *, int), void *cb_data );
void register_pk_elg_progress ( void (*cb)( void *, int), void *cb_data );

#endif /*G10_CIPHER_H*/
