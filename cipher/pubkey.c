/* pubkey.c  -	pubkey dispatcher
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "elgamal.h"
#include "dsa.h"
#include "dynload.h"

/* FIXME: use set_lasterr() */

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
    int (*verify)( int algo, MPI hash, MPI *data, MPI *pkey,
		   int (*cmp)(void *, MPI), void *opaquev );
    unsigned (*get_nbits)( int algo, MPI *pkey );
};

static struct pubkey_table_s pubkey_table[TABLE_SIZE];
static int disabled_algos[TABLE_SIZE];

static struct { const char* name; int algo;
		const char* common_elements;
		const char* public_elements;
		const char* secret_elements;
} algo_info_table[] = {
	{  "dsa"            , PUBKEY_ALGO_DSA       , "pqgy", "", "x"    },
	{  "rsa"            , PUBKEY_ALGO_RSA       , "ne",   "", "dpqu" },
	{  "elg"            , PUBKEY_ALGO_ELGAMAL   , "pgy",  "", "x"    },
	{  "openpgp-dsa"    , PUBKEY_ALGO_DSA       , "pqgy", "", "x"    },
	{  "openpgp-rsa"    , PUBKEY_ALGO_RSA       , "pqgy", "", "x"    },
	{  "openpgp-elg"    , PUBKEY_ALGO_ELGAMAL_E , "pgy",  "", "x"    },
	{  "openpgp-elg-sig", PUBKEY_ALGO_ELGAMAL   , "pgy",  "", "x"    },
	{  NULL }};

static struct {
    const char* name; int algo;
    const char* elements;
} sig_info_table[] = {
	{  "dsa"            , PUBKEY_ALGO_DSA       , "rs" },
	{  "rsa"            , PUBKEY_ALGO_RSA       , "s"  },
	{  "elg"            , PUBKEY_ALGO_ELGAMAL   , "rs" },
	{  "openpgp-dsa"    , PUBKEY_ALGO_DSA       , "rs" },
	{  "openpgp-rsa"    , PUBKEY_ALGO_RSA       , "s"  },
	{  "openpgp-elg-sig", PUBKEY_ALGO_ELGAMAL   , "rs" },
	{  NULL }};

static struct {
    const char* name; int algo;
    const char* elements;
} enc_info_table[] = {
	{  "elg"            , PUBKEY_ALGO_ELGAMAL   , "ab" },
	{  "rsa"            , PUBKEY_ALGO_RSA       , "a"  },
	{  "openpgp-rsa"    , PUBKEY_ALGO_RSA       , "a"  },
	{  "openpgp-elg"    , PUBKEY_ALGO_ELGAMAL_E , "ab" },
	{  "openpgp-elg-sig", PUBKEY_ALGO_ELGAMAL   , "ab" },
	{  NULL }};


static int pubkey_sign( int algo, MPI *resarr, MPI hash, MPI *skey );
static int pubkey_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		      int (*cmp)(void *, MPI), void *opaque );

static int
dummy_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{ log_bug("no generate() for %d\n", algo ); return GCRYERR_INV_PK_ALGO; }

static int
dummy_check_secret_key( int algo, MPI *skey )
{ log_bug("no check_secret_key() for %d\n", algo ); return GCRYERR_INV_PK_ALGO; }

static int
dummy_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{ log_bug("no encrypt() for %d\n", algo ); return GCRYERR_INV_PK_ALGO; }

static int
dummy_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{ log_bug("no decrypt() for %d\n", algo ); return GCRYERR_INV_PK_ALGO; }

static int
dummy_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{ log_bug("no sign() for %d\n", algo ); return GCRYERR_INV_PK_ALGO; }

static int
dummy_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		int (*cmp)(void *, MPI), void *opaquev )
{ log_bug("no verify() for %d\n", algo ); return GCRYERR_INV_PK_ALGO; }

static unsigned
dummy_get_nbits( int algo, MPI *pkey )
{ log_bug("no get_nbits() for %d\n", algo ); return 0; }


/****************
 * Put the static entries into the table.
 * This is out constructor function which fill the table
 * of algorithms with the one we have statically linked.
 */
static void
setup_pubkey_table(void)
{
    int i;

    i = 0;
    pubkey_table[i].algo = PUBKEY_ALGO_ELGAMAL;
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
    pubkey_table[i].sign	     = elg_sign;
    pubkey_table[i].verify	     = elg_verify;
    pubkey_table[i].get_nbits	     = elg_get_nbits;
    if( !pubkey_table[i].name )
	BUG();
    i++;
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
    pubkey_table[i].sign	     = elg_sign;
    pubkey_table[i].verify	     = elg_verify;
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
    static int done = 0;
    void *context = NULL;
    struct pubkey_table_s *ct;
    int ct_idx;
    int i;
    const char *name;
    int any = 0;


    if( !initialized ) {
	cipher_modules_constructor();
	setup_pubkey_table();
	initialized = 1;
	return 1;
    }
    if( done )
	return 0;
    done = 1;
    for(ct_idx=0, ct = pubkey_table; ct_idx < TABLE_SIZE; ct_idx++,ct++ ) {
	if( !ct->name )
	    break;
    }
    if( ct_idx >= TABLE_SIZE-1 )
	BUG(); /* table already full */
    /* now load all extensions */
    while( (name = enum_gnupgext_pubkeys( &context, &ct->algo,
				&ct->npkey, &ct->nskey, &ct->nenc,
				&ct->nsig,  &ct->use,
				&ct->generate,
				&ct->check_secret_key,
				&ct->encrypt,
				&ct->decrypt,
				&ct->sign,
				&ct->verify,
				&ct->get_nbits )) ) {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == ct->algo )
		break;
	if( pubkey_table[i].name ) {
	    log_info("skipping pubkey %d: already loaded\n", ct->algo );
	    continue;
	}

	if( !ct->generate  )  ct->generate = dummy_generate;
	if( !ct->check_secret_key )  ct->check_secret_key =
						    dummy_check_secret_key;
	if( !ct->encrypt   )  ct->encrypt  = dummy_encrypt;
	if( !ct->decrypt   )  ct->decrypt  = dummy_decrypt;
	if( !ct->sign	   )  ct->sign	   = dummy_sign;
	if( !ct->verify    )  ct->verify   = dummy_verify;
	if( !ct->get_nbits )  ct->get_nbits= dummy_get_nbits;
	/* put it into the table */
	if( g10_opt_verbose > 1 )
	    log_info("loaded pubkey %d (%s)\n", ct->algo, name);
	ct->name = name;
	ct_idx++;
	ct++;
	any = 1;
	/* check whether there are more available table slots */
	if( ct_idx >= TABLE_SIZE-1 ) {
	    log_info("pubkey table full; ignoring other extensions\n");
	    break;
	}
    }
    enum_gnupgext_pubkeys( &context, NULL, NULL, NULL, NULL, NULL, NULL,
			       NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    return any;
}


/****************
 * Map a string to the pubkey algo
 */
int
gcry_pk_map_name( const char *string )
{
    int i;
    const char *s;

    do {
	for(i=0; (s=pubkey_table[i].name); i++ )
	    if( !stricmp( s, string ) )
		return pubkey_table[i].algo;
    } while( load_pubkey_modules() );
    return 0;
}


/****************
 * Map a pubkey algo to a string
 */
const char *
gcry_pk_algo_name( int algo )
{
    int i;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].name;
    } while( load_pubkey_modules() );
    return NULL;
}


static void
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


/****************
 * a use of 0 means: don't care
 */
static int
check_pubkey_algo( int algo, unsigned use )
{
    int i;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		if( (use & GCRY_PK_USAGE_SIGN)
		    && !(pubkey_table[i].use & GCRY_PK_USAGE_SIGN) )
		    return GCRYERR_WRONG_PK_ALGO;
		if( (use & GCRY_PK_USAGE_ENCR)
		    && !(pubkey_table[i].use & GCRY_PK_USAGE_ENCR) )
		    return GCRYERR_WRONG_PK_ALGO;

		for(i=0; i < DIM(disabled_algos); i++ ) {
		    if( disabled_algos[i] == algo )
			return GCRYERR_INV_PK_ALGO;
		}
		return 0; /* okay */
	    }
    } while( load_pubkey_modules() );
    return GCRYERR_INV_PK_ALGO;
}




/****************
 * Return the number of public key material numbers
 */
static int
pubkey_get_npkey( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].npkey;
    } while( load_pubkey_modules() );
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 2;	  /* see the RSA keyids */
    return 0;
}

/****************
 * Return the number of secret key material numbers
 */
static int
pubkey_get_nskey( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].nskey;
    } while( load_pubkey_modules() );
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 6;	  /* see the RSA keyids */
    return 0;
}

/****************
 * Return the number of signature material numbers
 */
static int
pubkey_get_nsig( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].nsig;
    } while( load_pubkey_modules() );
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 1;	  /* see the RSA keyids */
    return 0;
}

/****************
 * Return the number of encryption material numbers
 */
static int
pubkey_get_nenc( int algo )
{
    int i;
    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo )
		return pubkey_table[i].nenc;
    } while( load_pubkey_modules() );
    if( is_RSA(algo) )	  /* special hack, so that we are able to */
	return 1;	  /* see the RSA keyids */
    return 0;
}

/****************
 * Get the number of nbits from the public key
 * FIXME: This should also take a S-Expt but must be optimized in
 * some way becuase it is used in keylistsings ans such (store it with the
 * S-Exp as some private data?)
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
    if( is_RSA(algo) )	/* we always wanna see the length of a key :-) */
	return mpi_get_nbits( pkey[0] );
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
    return GCRYERR_INV_PK_ALGO;
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
    return GCRYERR_INV_PK_ALGO;
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

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].encrypt)( algo, resarr, data, pkey );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = GCRYERR_INV_PK_ALGO;
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

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].decrypt)( algo, result, data, skey );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = GCRYERR_INV_PK_ALGO;
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
static int
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
    rc = GCRYERR_INV_PK_ALGO;
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
static int
pubkey_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI), void *opaquev )
{
    int i, rc;

    do {
	for(i=0; pubkey_table[i].name; i++ )
	    if( pubkey_table[i].algo == algo ) {
		rc = (*pubkey_table[i].verify)( algo, hash, data, pkey,
							    cmp, opaquev );
		goto ready;
	    }
    } while( load_pubkey_modules() );
    rc = GCRYERR_INV_PK_ALGO;
  ready:
    return rc;
}


static void
release_mpi_array( MPI *array )
{
    for( ; *array; array++ ) {
	mpi_free(*array);
	*array = NULL;
    }
}

/****************
 * Convert a S-Exp with either a private or a public key to our
 * internal format. Currently we do only support the following
 * algorithms:
 *    dsa
 *    rsa
 *    openpgp-dsa
 *    openpgp-rsa
 *    openpgp-elg
 *    openpgp-elg-sig
 * Provide a SE with the first element be either "private-key" or
 * or "public-key". the followed by a list with its first element
 * be one of the above algorithm identifiers and the following
 * elements are pairs with parameter-id and value.
 * NOTE: we look through the list to find a list beginning with
 * "private-key" or "public-key" - the first one found is used.
 *
 * FIXME: Allow for encrypted secret keys here.
 *
 * Returns: A pointer to an allocated array of MPIs if the return value is
 *	    zero; the caller has to release this array.
 */
static int
sexp_to_key( GCRY_SEXP sexp, int want_private, MPI **retarray, int *retalgo)
{
    GCRY_SEXP list, l2;
    const char *name;
    const char *s;
    size_t n;
    int i, idx;
    int algo;
    const char *elems1, *elems2;
    GCRY_MPI *array;

    /* check that the first element is valid */
    list = gcry_sexp_find_token( sexp, want_private? "private-key"
						    :"public-key", 0 );
    if( !list )
	return GCRYERR_INV_OBJ; /* Does not contain a public- or private-key object */
    list = gcry_sexp_cdr( list );
    if( !list )
	return GCRYERR_NO_OBJ; /* no cdr for the key object */
    name = gcry_sexp_car_data( list, &n );
    if( !name )
	return GCRYERR_INV_OBJ; /* invalid structure of object */
    for(i=0; (s=algo_info_table[i].name); i++ ) {
	if( strlen(s) == n && !memcmp( s, name, n ) )
	    break;
    }
    if( !s )
	return GCRYERR_INV_PK_ALGO; /* unknown algorithm */
    algo = algo_info_table[i].algo;
    elems1 = algo_info_table[i].common_elements;
    elems2 = want_private? algo_info_table[i].secret_elements
			 : algo_info_table[i].public_elements;
    array = g10_calloc( strlen(elems1)+strlen(elems2)+1, sizeof *array );
    if( !array )
	return GCRYERR_NO_MEM;

    idx = 0;
    for(s=elems1; *s; s++, idx++ ) {
	l2 = gcry_sexp_find_token( list, s, 1 );
	if( !l2 ) {
	    g10_free( array );
	    return GCRYERR_NO_OBJ; /* required parameter not found */
	}
	array[idx] = gcry_sexp_cdr_mpi( l2, GCRYMPI_FMT_USG );
	if( !array[idx] ) {
	    g10_free( array );
	    return GCRYERR_INV_OBJ; /* required parameter is invalid */
	}
    }
    for(s=elems2; *s; s++, idx++ ) {
	l2 = gcry_sexp_find_token( list, s, 1 );
	if( !l2 ) {
	    g10_free( array );
	    return GCRYERR_NO_OBJ; /* required parameter not found */
	}
	/* FIXME: put the MPI in secure memory when needed */
	array[idx] = gcry_sexp_cdr_mpi( l2, GCRYMPI_FMT_USG );
	if( !array[idx] ) {
	    g10_free( array );
	    return GCRYERR_INV_OBJ; /* required parameter is invalid */
	}
    }

    *retarray = array;
    *retalgo = algo;

    return 0;
}

static int
sexp_to_sig( GCRY_SEXP sexp, MPI **retarray, int *retalgo)
{
    GCRY_SEXP list, l2;
    const char *name;
    const char *s;
    size_t n;
    int i, idx;
    int algo;
    const char *elems;
    GCRY_MPI *array;

    /* check that the first element is valid */
    list = gcry_sexp_find_token( sexp, "sig-val" , 0 );
    if( !list )
	return GCRYERR_INV_OBJ; /* Does not contain a signature value object */
    list = gcry_sexp_cdr( list );
    if( !list )
	return GCRYERR_NO_OBJ; /* no cdr for the sig object */
    name = gcry_sexp_car_data( list, &n );
    if( !name )
	return GCRYERR_INV_OBJ; /* invalid structure of object */
    for(i=0; (s=sig_info_table[i].name); i++ ) {
	if( strlen(s) == n && !memcmp( s, name, n ) )
	    break;
    }
    if( !s )
	return GCRYERR_INV_PK_ALGO; /* unknown algorithm */
    algo = sig_info_table[i].algo;
    elems = sig_info_table[i].elements;
    array = g10_calloc( (strlen(elems)+1) , sizeof *array );
    if( !array )
	return GCRYERR_NO_MEM;

    idx = 0;
    for(s=elems; *s; s++, idx++ ) {
	l2 = gcry_sexp_find_token( list, s, 1 );
	if( !l2 ) {
	    g10_free( array );
	    return GCRYERR_NO_OBJ; /* required parameter not found */
	}
	array[idx] = gcry_sexp_cdr_mpi( l2, GCRYMPI_FMT_USG );
	if( !array[idx] ) {
	    g10_free( array );
	    return GCRYERR_INV_OBJ; /* required parameter is invalid */
	}
    }

    *retarray = array;
    *retalgo = algo;

    return 0;
}





int
gcry_pk_encrypt( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP pkey )
{
	/* ... */
    return 0;
}

int
gcry_pk_decrypt( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP skey )
{
	/* ... */
    return 0;
}



/****************
 * Create a signature.
 *
 * Caller has to provide a secret kez as the SEXP skey and data expressed
 * as a SEXP list hash with only one emelennt which should instantly be
 * available as a MPI.	Later versions of this functions may provide padding
 * and other things depending on data.
 *
 * Returns: 0 or an errorcode.
 *	    In case of 0 the function returns a new SEXP with the
 *	    signature value; the structure of this signature depends on the
 *	    other arguments but is always suitable to be passed to
 *	    gcry_pk_verify
 */
int
gcry_pk_sign( GCRY_SEXP *r_sig, GCRY_SEXP s_hash, GCRY_SEXP s_skey )
{
    MPI *skey, hash;
    MPI *result;
    int i, algo, rc;
    const char *algo_name, *algo_elems;
    GCRY_SEXP s;

    rc = sexp_to_key( s_skey, 1, &skey, &algo );
    if( rc )
	return rc;

    /* get the name and the required size of the result array */
    for(i=0; (algo_name = sig_info_table[i].name); i++ ) {
	if( sig_info_table[i].algo == algo )
	    break;
    }
    if( !algo_name ) {
	release_mpi_array( skey );
	return -4; /* oops: unknown algorithm */
    }
    algo_elems = sig_info_table[i].elements;

    /* get the stuff we want to sign */
    hash = gcry_sexp_car_mpi( s_hash, 0 );
    if( !hash ) {
	release_mpi_array( skey );
	return -1; /* fixme: get a real errorcode for this */
    }
    result = g10_xcalloc( (strlen(algo_elems)+1) , sizeof *result );
    rc = pubkey_sign( algo, result, hash, skey );
    release_mpi_array( skey );
    mpi_free( hash );
    if( rc ) {
	g10_free( result );
	return rc;
    }

    s = SEXP_NEW( algo_name, 0 );
    for(i=0; algo_elems[i]; i++ ) {
	char tmp[2];
	tmp[0] = algo_elems[i];
	tmp[1] = 0;
	s = gcry_sexp_append( s, gcry_sexp_new_name_mpi( tmp, result[i] ) );
    }
    g10_free( result );
    *r_sig = SEXP_CONS( SEXP_NEW( "sig-val", 0 ), s );
    gcry_sexp_dump( *r_sig );
    return 0;
}


/****************
 * Verify a sgnature.  Caller has to supply the public key pkey,
 * the signature sig and his hashvalue data.  Public key has to be
 * a standard public key given as an S-Exp, sig is a S-Exp as returned
 * from gcry_pk_sign and data must be an S-Exp like the one in sign too.
 */
int
gcry_pk_verify( GCRY_SEXP s_sig, GCRY_SEXP s_hash, GCRY_SEXP s_pkey )
{
    MPI *pkey, hash, *sig;
    int algo, sigalgo;
    int rc;

    rc = sexp_to_key( s_pkey, 0, &pkey, &algo );
    if( rc )
	return rc;
    rc = sexp_to_sig( s_sig, &sig, &sigalgo );
    if( rc ) {
	release_mpi_array( pkey );
	return rc;
    }
    if( algo != sigalgo ) {
	release_mpi_array( pkey );
	release_mpi_array( sig );
	return -1; /* fixme: add real errornumber - algo does not match */
    }

    hash = gcry_sexp_car_mpi( s_hash, 0 );
    if( !hash ) {
	release_mpi_array( pkey );
	release_mpi_array( sig );
	return -1; /* fixme: get a real errorcode for this */
    }

    rc = pubkey_verify( algo, hash, sig, pkey, NULL, NULL );
    release_mpi_array( pkey );
    release_mpi_array( sig );
    mpi_free(hash);

    return rc;
}


int
gcry_pk_ctl( int cmd, void *buffer, size_t buflen)
{
    switch( cmd ) {
      case GCRYCTL_DISABLE_ALGO:
	/* this one expects a buffer pointing to an
	 * integer with the algo number.
	 */
	if( !buffer || buflen != sizeof(int) )
	    return set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	disable_pubkey_algo( *(int*)buffer );
	break;

      default:
	return set_lasterr( GCRYERR_INV_OP );
    }
    return 0;
}


/****************
 * Return information about the given algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	Buffer must be NULL, nbytes  may have the address of a variable
 *	with the required usage of the algorithm. It may be 0 for don't
 *	care or a combination of the GCRY_PK_USAGE_xxx flags;
 *
 * On error the value -1 is returned and the error reason may be
 * retrieved by gcry_errno().
 * Note:  Because this function is in most caes used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
int
gcry_pk_algo_info( int algo, int what, void *buffer, size_t *nbytes)
{
    switch( what ) {
      case GCRYCTL_TEST_ALGO: {
	    int use = nbytes? *nbytes: 0;
	    if( buffer ) {
		set_lasterr( GCRYERR_INV_ARG );
		return -1;
	    }
	    if( check_pubkey_algo( algo, use ) ) {
		set_lasterr( GCRYERR_INV_PK_ALGO );
		return -1;
	    }
	}
	break;

      case GCRYCTL_GET_ALGO_NPKEY: return pubkey_get_npkey( algo );
      case GCRYCTL_GET_ALGO_NSKEY: return pubkey_get_nskey( algo );
      case GCRYCTL_GET_ALGO_NSIGN: return pubkey_get_nsig( algo );
      case GCRYCTL_GET_ALGO_NENCR: return pubkey_get_nenc( algo );

      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
}


