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

#include "gcrypt.h"

#ifdef G10_I18N_H
  #error i18n should not be included here
#endif

#define _(a)  g10_gettext(a)
#define N_(a) (a)

/*-- gcrypt/global.c --*/
int set_lasterr( int ec );

/*-- gcrypt/misc.c --*/
const char *g10_gettext( const char *key );
int fatal_invalid_arg(const char *text);

#if 0
/* This used to be the old include/g10lib.h */

#include "mpi.h"

int g10c_debug_mode;
int g10_opt_verbose;

/********************************
 *******  math functions  *******
 ********************************/
MPI  g10m_new( unsigned nbits );
MPI  g10m_new_secure( unsigned nbits );
void g10m_release( MPI a );
void g10m_resize( MPI a, unsigned nbits );
MPI  g10m_copy( MPI a );
void g10m_swap( MPI a, MPI b);
void g10m_set( MPI w, MPI u);
void g10m_set_ui( MPI w, unsigned long u);
void g10m_set_bytes( MPI a, unsigned nbits, unsigned char (*fnc)(int), int opaque );
int  g10m_cmp( MPI u, MPI v );
int  g10m_cmp_ui( MPI u, unsigned long v );


void g10m_add(MPI w, MPI u, MPI v);
void g10m_add_ui(MPI w, MPI u, unsigned long v );
void g10m_sub( MPI w, MPI u, MPI v);
void g10m_sub_ui(MPI w, MPI u, unsigned long v );

void g10m_mul_ui(MPI w, MPI u, unsigned long v );
void g10m_mul_2exp( MPI w, MPI u, unsigned long cnt);
void g10m_mul( MPI w, MPI u, MPI v);
void g10m_mulm( MPI w, MPI u, MPI v, MPI m);

void g10m_fdiv_q( MPI quot, MPI dividend, MPI divisor );

void g10m_powm( MPI res, MPI base, MPI exp, MPI mod);

int  g10m_gcd( MPI g, MPI a, MPI b );
int  g10m_invm( MPI x, MPI u, MPI v );

unsigned g10m_get_nbits( MPI a );
unsigned g10m_get_size( MPI a );

void g10m_set_buffer( MPI a, const char *buffer, unsigned nbytes, int sign );


/********************************************
 *******  symmetric cipher functions  *******
 ********************************************/



/*********************************************
 *******  asymmetric cipher functions  *******
 *********************************************/




/*********************************************
 *******  cryptograhic hash functions  *******
 *********************************************/


/*****************************************
 *******  miscellaneous functions  *******
 *****************************************/

const char *g10m_revision_string(int mode);
const char *g10c_revision_string(int mode);
const char *g10u_revision_string(int mode);

MPI   g10c_generate_secret_prime( unsigned nbits );
char *g10c_get_random_bits( unsigned nbits, int level, int secure );


void *g10_malloc( size_t n );
void *g10_calloc( size_t n );
void *g10_malloc_secure( size_t n );
void *g10_calloc_secure( size_t n );
void *g10_realloc( void *a, size_t n );
void  g10_free( void *p );
char *g10_strdup( const char * a);

void g10_log_bug( const char *fmt, ... );
void g10_log_bug0( const char *, int );
void g10_log_fatal( const char *fmt, ... );
void g10_log_error( const char *fmt, ... );
void g10_log_info( const char *fmt, ... );
void g10_log_debug( const char *fmt, ... );
void g10_log_hexdump( const char *text, char *buf, size_t len );
void g10_log_mpidump( const char *text, MPI a );


/***************************
 *******  constants  *******
 **************************/
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
#define DIGEST_ALGO_TIGER     6

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)

#define G10ERR_GENERAL	       1
#define G10ERR_PUBKEY_ALGO     4
#define G10ERR_DIGEST_ALGO     5
#define G10ERR_BAD_PUBKEY      6
#define G10ERR_BAD_SECKEY      7
#define G10ERR_BAD_SIGN        8
#define G10ERR_CIPHER_ALGO    12
#define G10ERR_WRONG_SECKEY   18
#define G10ERR_UNSUPPORTED    19
#define G10ERR_NI_PUBKEY      27
#define G10ERR_NI_CIPHER      28
#define G10ERR_BAD_MPI	      30
#define G10ERR_WR_PUBKEY_ALGO 41


/***********************************
 *******  some handy macros  *******
 ***********************************/

#ifndef BUG
  #define BUG() g10_log_bug0( __FILE__ , __LINE__ )
#endif

#ifndef STR
  #define STR(v) #v
  #define STR2(v) STR(v)
#endif

#ifndef DIM
  #define DIM(v) (sizeof(v)/sizeof((v)[0]))
  #define DIMof(type,member)   DIM(((type *)0)->member)
#endif


#define DBG_CIPHER  g10c_debug_mode
#define OPT_VERBOSE g10_opt_verbose

#endif /* if 0 */


#endif /* G10LIB_H */
