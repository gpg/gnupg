/* pubkey.c  -	pubkey dispatcher
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "errors.h"
#include "mpi.h"
#include "cipher.h"
#include "elgamal.h"
#include "dsa.h"
#include "rsa.h"

#define TABLE_SIZE 10

struct pubkey_table_s {
    const char *name;
    int algo;
    int npkey;
    int nskey;
    int nenc;
    int nsig;
    int use;
    int (*generate)( int algo, unsigned nbits, MPI *skey, MPI **retfactors );
    int (*check_secret_key)( int algo, MPI *skey );
    int (*encrypt)( int algo, MPI *resarr, MPI data, MPI *pkey );
    int (*decrypt)( int algo, MPI *result, MPI *data, MPI *skey );
    int (*sign)( int algo, MPI *resarr, MPI data, MPI *skey );
    int (*verify)( int algo, MPI hash, MPI *data, MPI *pkey );
    unsigned (*get_nbits)( int algo, MPI *pkey );
};

static struct pubkey_table_s pubkey_table[TABLE_SIZE];
static int disabled_algos[TABLE_SIZE];


#if 0
static int
dummy_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{ log_bug("no generate() for %d\n", algo ); return G10ERR_PUBKEY_ALGO; }

static int
dummy_check_secret_key( int algo, MPI *skey )
{ log_bug("no check_secret_key() for %d\n", algo ); return G10ERR_PUBKEY_ALGO; }
#endif

static int
dummy_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{ log_bug("no encrypt() for %d\n", algo ); return G10ERR_PUBKEY_ALGO; }

static int
dummy_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{ log_bug("no decrypt() for %d\n", algo ); return G10ERR_PUBKEY_ALGO; }

static int
dummy_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{ log_bug("no sign() for %d\n", algo ); return G10ERR_PUBKEY_ALGO; }

static int
dummy_verify( int algo, MPI hash, MPI *data, MPI *pkey )
{ log_bug("no verify() for %d\n", algo ); return G10ERR_PUBKEY_ALGO; }

#if 0
static unsigned
dummy_get_nbits( int algo, MPI *pkey )
{ log_bug("no get_nbits() for %d\n", algo ); return 0; }
#endif

/****************
 * Put the static entries into the table.
 * This is out constructor function which fill the table
 * of algorithms with the one we have statically linked.
 */
static void
setup_pubkey_table(void)
{
    int i=0;

    pubkey_table[i].algo = PUBKEY_ALGO_ELGAMAL_E;
    pubkey_table[i].name = elg_get_info( pubkey_table[i].algo,
					 &pubkey_table[i].npkey,
					 &pubkey_table[i].nskey,
					 &pubkey_table[i].nenc,
					 &pubkey_table[i].nsig,
					 &pubkey_table[i].use );
    pubkey_table[i].generate	     = elg_generate;
    pubkey_table[i].check_secret_key = elg_check_secret_key;
    pubkey_table[i].encrypt	     = elg_encrypt;
    pubkey_table[i].decrypt	     = elg_decrypt;
    pubkey_table[i].sign	     = dummy_sign;
    pubkey_table[i].verify	     = dummy_verify;
    pubkey_table[i].get_nbits	     = elg_get_nbits;
    if( !pubkey_table[i].name )
	BUG();
    i++;
    pubkey_table[i].algo = PUBKEY_ALGO_DSA;
    pubkey_table[i].name = dsa_get_info( pubkey_table[i].algo,
					 &pubkey_table[i].npkey,
					 &pubkey_table[i].nskey,
					 &pubkey_table[i].nenc,
					 &pubkey_table[i].nsig,
					 &pubkey_table[i].use );
    pubkey_table[i].generate	     = dsa_generate;
    pubkey_table[i].check_secret_key = dsa_check_secret_key;
    pubkey_table[i].encrypt	     = dummy_encrypt;
    pubkey_table[i].decrypt	     = dummy_decrypt;
    pubkey_table[i].sign	     = dsa_sign;
    pubkey_table[i].verify	     = dsa_verify;
    pubkey_table[i].get_nbits	     = dsa_get_nbits;
    if( !pubkey_table[i].name )
	BUG();
    i++;

#ifdef USE_RSA
    pubkey_table[i].algo = PUBKEY_ALGO_RSA;
    pubkey_table[i].name = rsa_get_info( pubkey_table[i].algo,
					 &pubkey_table[i].npkey,
					 &pubkey_table[i].nskey,
					 &pubkey_table[i].nenc,
					 &pubkey_table[i].nsig,
					 &pubkey_table[i].use );
    pubkey_table[i].generate	     = rsa_generate;
    pubkey_table[i].check_secret_key = rsa_check_secret_key;
    pubkey_table[i].encrypt	     = rsa_encrypt;
    pubkey_table[i].decrypt	     = rsa_decrypt;
    pubkey_table[i].sign	     = rsa_sign;
    pubkey_table[i].verify	     = rsa_verify;
    pubkey_table[i].get_nbits	     = rsa_get_nbits;
    if( !pubkey_table[i].name )
	BUG();
    i++;
    pubkey_table[i].algo = PUBKEY_ALGO_RSA_E;
    pubkey_table[i].name = rsa_get_info( pubkey_table[i].algo,
					 &pubkey_table[i].npkey,
					 &pubkey_table[i].nskey,
					 &pubkey_table[i].nenc,
					 &pubkey_table[i].nsig,
					 &pubkey_table[i].use );
    pubkey_table[i].generate	     = rsa_generate;
    pubkey_table[i].check_secret_key = rsa_check_secret_key;
    pubkey_table[i].encrypt	     = rsa_encrypt;
    pubkey_table[i].decrypt	     = rsa_decrypt;
    pubkey_table[i].sign	     = dummy_sign;
    pubkey_table[i].verify	     = dummy_verify;
    pubkey_table[i].get_nbits	     = rsa_get_nbits;
    if( !pubkey_table[i].name )
	BUG();
    i++;
    pubkey_table[i].algo = PUBKEY_ALGO_RSA_S;
    pubkey_table[i].name = rsa_get_info( pubkey_table[i].algo,
					 &pubkey_table[i].npkey,
					 &pubkey_table[i].nskey,
					 &pubkey_table[i].nenc,
					 &pubkey_table[i].nsig,
					 &pubkey_table[i].use );
    pubkey_table[i].generate	     = rsa_generate;
    pubkey_table[i].check_secret_key = rsa_check_secret_key;
    pubkey_table[i].encrypt	     = dummy_encrypt;
    pubkey_table[i].decrypt	     = dummy_decrypt;
    pubkey_table[i].sign	     = rsa_sign;
    pubkey_table[i].verify	     = rsa_verify;
    pubkey_table[i].get_nbits	     = rsa_get_nbits;
    if( !pubkey_table[i].name )
	BUG();
    i++;
#endif /* USE_RSA */

    for( ; i < TABLE_SIZE; i++ )
	pubkey_table[i].name = NULL;
}


/****************
 * Try to load all modules and return true if new modules are available
 */
static int
load_pubkey_modules(void)
{
    static int initialized = 0;

    if( !initialized ) {
	setup_pubkey_table();
	initialized = 1;
	return 1;
    }
    return 0;
}


/****************
 * Map a string to the pubkey algo
 */
int
string_to_pubkey_algo( const char *string )
{
    int i;
    const char *s;

    do {
	for(i=0; (s=pubkey_table[i].name); i++ )
	    if( !ascii_strcasecmp( s, string ) )
		return pubkey_table[i].algo;
    } while( load_pubkey_modules() );
    return 0;
}


/****************
 * Map a pubkey algo to a string
 */
const char *
pubkey_algo_to_string( int algo )
{
    int i;

    if (algo == PUBKEY_ALGO_ELGAMAL)
      return "ELG";
    
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].name;
    } while( load_pubkey_modules() );
    return NULL;
}


void
disable_pubkey_algo( int algo )
{
    int i;

    for(i=0; i < DIM(disabled_algos); i++ ) {
	if( !disabled_algos[i] || disabled_algos[i] == algo ) {
	    disabled_algos[i] = algo;
	    return;
	}
    }
    log_fatal("can't disable pubkey algo %d: table full\n", algo );
}


int
check_pubkey_algo( int algo )
{
    return check_pubkey_algo2( algo, 0 );
}

/****************
 * a use of 0 means: don't care
 */
int
check_pubkey_algo2( int algo, unsigned use )
{
    int i;

    /* Map type 20 Elgamal algorithm to type 16 if it is used for
       decryption.  This allows to use legacy type 20 Elgamal keys for
       decryption.  */
    if (algo == PUBKEY_ALGO_ELGAMAL && use == PUBKEY_USAGE_ENC)
      algo = PUBKEY_ALGO_ELGAMAL_E;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		if( (use & PUBKEY_USAGE_SIG)
		    && !(pubkey_table[i].use & PUBKEY_USAGE_SIG) )
		    return G10ERR_WR_PUBKEY_ALGO;
		if( (use & PUBKEY_USAGE_ENC)
		    && !(pubkey_table[i].use & PUBKEY_USAGE_ENC) )
		    return G10ERR_WR_PUBKEY_ALGO;

		for(i=0; i < DIM(disabled_algos); i++ ) {
		    if( disabled_algos[i] == algo )
			return G10ERR_PUBKEY_ALGO;
		}
		return 0; /* okay */
	    }
    } while( load_pubkey_modules() );
    return G10ERR_PUBKEY_ALGO;
}




/****************
 * Return the number of public key material numbers
 */
int
pubkey_get_npkey( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].npkey;
    } while( load_pubkey_modules() );

#ifndef USE_RSA
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 2;	  /* see the RSA keyids */
#endif /* USE_RSA */

    if(algo==PUBKEY_ALGO_ELGAMAL)
      return 3;

    return 0;
}

/****************
 * Return the number of secret key material numbers
 */
int
pubkey_get_nskey( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].nskey;
    } while( load_pubkey_modules() );

#ifndef USE_RSA
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 6;	  /* see the RSA keyids */
#endif /* USE_RSA */

    if(algo==PUBKEY_ALGO_ELGAMAL)
      return 4;

    return 0;
}

/****************
 * Return the number of signature material numbers
 */
int
pubkey_get_nsig( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].nsig;
    } while( load_pubkey_modules() );

#ifndef USE_RSA
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 1;	  /* see the RSA keyids */
#endif /* USE_RSA */

    if(algo==PUBKEY_ALGO_ELGAMAL)
      return 2;

    return 0;
}

/****************
 * Return the number of encryption material numbers
 */
int
pubkey_get_nenc( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].nenc;
    } while( load_pubkey_modules() );

#ifndef USE_RSA
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 1;	  /* see the RSA keyids */
#endif /* USE_RSA */

    if(algo==PUBKEY_ALGO_ELGAMAL)
      return 2;

    return 0;
}

/****************
 * Get the number of nbits from the public key
 */
unsigned
pubkey_nbits( int algo, MPI *pkey )
{
    int i;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return (*pubkey_table[i].get_nbits)( algo, pkey );
    } while( load_pubkey_modules() );

#ifndef USE_RSA
    if( is_RSA(algo) )	/* we always wanna see the length of a key :-) */
	return mpi_get_nbits( pkey[0] );
#endif /* USE_RSA */

    if(algo==PUBKEY_ALGO_ELGAMAL)
      return mpi_get_nbits(pkey[0]);

    return 0;
}


int
pubkey_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{
    int i;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return (*pubkey_table[i].generate)( algo, nbits,
						    skey, retfactors );
    } while( load_pubkey_modules() );
    return G10ERR_PUBKEY_ALGO;
}


int
pubkey_check_secret_key( int algo, MPI *skey )
{
    int i;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return (*pubkey_table[i].check_secret_key)( algo, skey );
    } while( load_pubkey_modules() );
    return G10ERR_PUBKEY_ALGO;
}


/****************
 * This is the interface to the public key encryption.
 * Encrypt DATA with PKEY and put it into RESARR which
 * should be an array of MPIs of size PUBKEY_MAX_NENC (or less if the
 * algorithm allows this - check with pubkey_get_nenc() )
 */
int
pubkey_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
    int i, rc;

    if( DBG_CIPHER ) {
	log_debug("pubkey_encrypt: algo=%d\n", algo );
	for(i=0; i < pubkey_get_npkey(algo); i++ )
	    log_mpidump("  pkey:", pkey[i] );
	log_mpidump("  data:", data );
    }

    if (algo == PUBKEY_ALGO_ELGAMAL)
      algo = PUBKEY_ALGO_ELGAMAL_E;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].encrypt)( algo, resarr, data, pkey );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = G10ERR_PUBKEY_ALGO;
  ready:
    if( !rc && DBG_CIPHER ) {
	for(i=0; i < pubkey_get_nenc(algo); i++ )
	    log_mpidump("  encr:", resarr[i] );
    }
    return rc;
}



/****************
 * This is the interface to the public key decryption.
 * ALGO gives the algorithm to use and this implicitly determines
 * the size of the arrays.
 * result is a pointer to a mpi variable which will receive a
 * newly allocated mpi or NULL in case of an error.
 */
int
pubkey_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    int i, rc;

    *result = NULL; /* so the caller can always do an mpi_free */
    if( DBG_CIPHER ) {
	log_debug("pubkey_decrypt: algo=%d\n", algo );
	for(i=0; i < pubkey_get_nskey(algo); i++ )
	    log_mpidump("  skey:", skey[i] );
	for(i=0; i < pubkey_get_nenc(algo); i++ )
	    log_mpidump("  data:", data[i] );
    }

    if (algo == PUBKEY_ALGO_ELGAMAL)
      algo = PUBKEY_ALGO_ELGAMAL_E;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].decrypt)( algo, result, data, skey );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = G10ERR_PUBKEY_ALGO;
  ready:
    if( !rc && DBG_CIPHER ) {
	log_mpidump(" plain:", *result );
    }
    return rc;
}


/****************
 * This is the interface to the public key signing.
 * Sign data with skey and put the result into resarr which
 * should be an array of MPIs of size PUBKEY_MAX_NSIG (or less if the
 * algorithm allows this - check with pubkey_get_nsig() )
 */
int
pubkey_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
    int i, rc;

    if( DBG_CIPHER ) {
	log_debug("pubkey_sign: algo=%d\n", algo );
	for(i=0; i < pubkey_get_nskey(algo); i++ )
	    log_mpidump("  skey:", skey[i] );
	log_mpidump("  data:", data );
    }

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].sign)( algo, resarr, data, skey );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = G10ERR_PUBKEY_ALGO;
  ready:
    if( !rc && DBG_CIPHER ) {
	for(i=0; i < pubkey_get_nsig(algo); i++ )
	    log_mpidump("   sig:", resarr[i] );
    }
    return rc;
}

/****************
 * Verify a public key signature.
 * Return 0 if the signature is good
 */
int
pubkey_verify( int algo, MPI hash, MPI *data, MPI *pkey )
{
    int i, rc;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].verify)( algo, hash, data, pkey );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = G10ERR_PUBKEY_ALGO;
  ready:
    return rc;
}
