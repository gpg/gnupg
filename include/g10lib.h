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
/* because libgcrypt is distributed along with GnuPG, we need some way
 * to do a sanity check.  If this macro is defined, we are inside of
 * libgcrypt */
#define _GCRYPT_IN_LIBGCRYPT 1

#include <gcrypt.h>
#include "types.h"

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
int   g10_is_secure( const void *a );
void  g10_check_heap( const void *a );


/*-- gcrypt/misc.c --*/

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
#define G10_GCC_A_NR	    __attribute__ ((noreturn))
#define G10_GCC_A_PRINTF( f, a ) \
			    __attribute__ ((format (printf,f,a)))
#define G10_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
void g10_bug( const char *file, int line, const char *func ) G10_GCC_A_NR;
#else
#define G10_GCC_A_NR
#define G10_GCC_A_PRINTF( f, a )
#define G10_GCC_A_NR_PRINTF( f, a )
void g10_bug( const char *file, int line );
#endif

const char *g10_gettext( const char *key );
void g10_fatal_error(int rc, const char *text ) G10_GCC_A_NR;
void g10_log( int level, const char *fmt, ... ) G10_GCC_A_PRINTF(2,3);
void g10_log_bug( const char *fmt, ... )   G10_GCC_A_NR_PRINTF(1,2);
void g10_log_fatal( const char *fmt, ... ) G10_GCC_A_NR_PRINTF(1,2);
void g10_log_error( const char *fmt, ... ) G10_GCC_A_PRINTF(1,2);
void g10_log_info( const char *fmt, ... )  G10_GCC_A_PRINTF(1,2);
void g10_log_debug( const char *fmt, ... ) G10_GCC_A_PRINTF(1,2);


/*-- util/{secmem,memory}.c --*/

void *g10_private_malloc( size_t n );
void *g10_private_malloc_secure( size_t n );
int   g10_private_is_secure( const void *p );
void  g10_private_check_heap( const void *p );
void *g10_private_realloc( void *a, size_t n );
void  g10_private_free( void *p );



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



/* logging macros */
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
  #define BUG() g10_bug( __FILE__ , __LINE__, __FUNCTION__ )
#else
  #define BUG() g10_bug( __FILE__ , __LINE__ )
#endif

#define log_hexdump g10_log_hexdump
#define log_bug     g10_log_bug
#define log_fatal   g10_log_fatal
#define log_error   g10_log_error
#define log_info    g10_log_info
#define log_debug   g10_log_debug


/* replacements of missing functions */
#ifndef HAVE_MEMICMP
int memicmp( const char *a, const char *b, size_t n );
#endif
#ifndef HAVE_STPCPY
char *stpcpy(char *a,const char *b);
#endif
#ifndef HAVE_STRLWR
char *strlwr(char *a);
#endif
#ifndef HAVE_STRTOUL
  #define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
  #define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_STRICMP
  #define stricmp(a,b)	 strcasecmp( (a), (b) )
#endif
#ifndef HAVE_ATEXIT
  #define atexit(a)    (on_exit((a),0))
#endif
#ifndef HAVE_RAISE
  #define raise(a) kill(getpid(), (a))
#endif

/* some handy macros */
#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)


#endif /* G10LIB_H */
