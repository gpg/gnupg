/* cipher.c  -	cipher dispatcher
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include "cipher.h"
#include "des.h"
#include "blowfish.h"
#include "cast5.h"
#include "arcfour.h"
#include "dynload.h"

#define MAX_BLOCKSIZE 16
#define TABLE_SIZE 14
#define CTX_MAGIC_NORMAL 0x24091964
#define CTX_MAGIC_SECURE 0x46919042

struct cipher_table_s {
    const char *name;
    int algo;
    size_t blocksize;
    size_t keylen;
    size_t contextsize; /* allocate this amount of context */
    int  (*setkey)( void *c, byte *key, unsigned keylen );
    void (*encrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*decrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*stencrypt)( void *c, byte *outbuf, byte *inbuf, unsigned int n );
    void (*stdecrypt)( void *c, byte *outbuf, byte *inbuf, unsigned int n );
};

static struct cipher_table_s cipher_table[TABLE_SIZE];
static int disabled_algos[TABLE_SIZE];

struct gcry_cipher_handle {
    int magic;
    int  algo;
    int  mode;
    unsigned int flags;
    size_t blocksize;
    byte iv[MAX_BLOCKSIZE];	/* (this should be ulong aligned) */
    byte lastiv[MAX_BLOCKSIZE];
    int  unused;  /* in IV */
    int  (*setkey)( void *c, byte *key, unsigned keylen );
    void (*encrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*decrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*stencrypt)( void *c, byte *outbuf, byte *inbuf, unsigned int n );
    void (*stdecrypt)( void *c, byte *outbuf, byte *inbuf, unsigned int n );
    PROPERLY_ALIGNED_TYPE context;
};


static int
dummy_setkey( void *c, byte *key, unsigned keylen ) { return 0; }
static void
dummy_encrypt_block( void *c, byte *outbuf, byte *inbuf ) { BUG(); }
static void
dummy_decrypt_block( void *c, byte *outbuf, byte *inbuf ) { BUG(); }
static void
dummy_encrypt_stream( void *c, byte *outbuf, byte *inbuf, unsigned int n )
{ BUG(); }
static void
dummy_decrypt_stream( void *c, byte *outbuf, byte *inbuf, unsigned int n )
{ BUG(); }



/****************
 * Put the static entries into the table.
 */
static void
setup_cipher_table(void)
{
    int i;

    for (i=0; i < TABLE_SIZE; i++ ) {
        cipher_table[i].encrypt = dummy_encrypt_block;
        cipher_table[i].decrypt = dummy_decrypt_block;
        cipher_table[i].stencrypt = dummy_encrypt_stream;
        cipher_table[i].stdecrypt = dummy_decrypt_stream;
    }
    
    i = 0;
    cipher_table[i].algo = GCRY_CIPHER_RIJNDAEL;
    cipher_table[i].name = rijndael_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_RIJNDAEL192;
    cipher_table[i].name = rijndael_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_RIJNDAEL256;
    cipher_table[i].name = rijndael_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_TWOFISH;
    cipher_table[i].name = twofish_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_BLOWFISH;
    cipher_table[i].name = blowfish_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_CAST5;
    cipher_table[i].name = cast5_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_3DES;
    cipher_table[i].name = des_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].encrypt,
					 &cipher_table[i].decrypt     );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = GCRY_CIPHER_ARCFOUR;
    cipher_table[i].name = arcfour_get_info( cipher_table[i].algo,
					 &cipher_table[i].keylen,
					 &cipher_table[i].blocksize,
					 &cipher_table[i].contextsize,
					 &cipher_table[i].setkey,
					 &cipher_table[i].stencrypt,
					 &cipher_table[i].stdecrypt   );
    if( !cipher_table[i].name )
	BUG();
    i++;
    cipher_table[i].algo = CIPHER_ALGO_DUMMY;
    cipher_table[i].name = "DUMMY";
    cipher_table[i].blocksize = 8;
    cipher_table[i].keylen = 128;
    cipher_table[i].contextsize = 0;
    cipher_table[i].setkey = dummy_setkey;
    i++;

    for( ; i < TABLE_SIZE; i++ )
	cipher_table[i].name = NULL;
}


/****************
 * Try to load all modules and return true if new modules are available
 */
static int
load_cipher_modules(void)
{
    static int done = 0;
    static int initialized = 0;
    void *context = NULL;
    struct cipher_table_s *ct;
    int ct_idx;
    int i;
    const char *name;
    int any = 0;

    if( !initialized ) {
	cipher_modules_constructor();
	setup_cipher_table(); /* load static modules on the first call */
	initialized = 1;
	return 1;
    }

    if( done )
	return 0;
    done = 1;

    for(ct_idx=0, ct = cipher_table; ct_idx < TABLE_SIZE; ct_idx++,ct++ ) {
	if( !ct->name )
	    break;
    }
    if( ct_idx >= TABLE_SIZE-1 )
	BUG(); /* table already full */
    /* now load all extensions */
    while( (name = enum_gnupgext_ciphers( &context, &ct->algo,
				&ct->keylen, &ct->blocksize, &ct->contextsize,
				&ct->setkey, &ct->encrypt, &ct->decrypt)) ) {
	if( ct->blocksize != 8 && ct->blocksize != 16 ) {
	    log_info("skipping cipher %d: unsupported blocksize\n", ct->algo);
	    continue;
	}
	for(i=0; cipher_table[i].name; i++ )
	    if( cipher_table[i].algo == ct->algo )
		break;
	if( cipher_table[i].name ) {
	    log_info("skipping cipher %d: already loaded\n", ct->algo );
	    continue;
	}
	/* put it into the table */
	if( g10_log_verbosity( 2 ) )
	    log_info("loaded cipher %d (%s)\n", ct->algo, name);
	ct->name = name;
	ct_idx++;
	ct++;
	any = 1;
	/* check whether there are more available table slots */
	if( ct_idx >= TABLE_SIZE-1 ) {
	    log_info("cipher table full; ignoring other extensions\n");
	    break;
	}
    }
    enum_gnupgext_ciphers( &context, NULL, NULL, NULL, NULL,
					   NULL, NULL, NULL );
    return any;
}


/****************
 * Map a string to the cipher algo.
 * Returns: The algo ID of the cipher for the gioven name or
 *	    0 if the name is not known.
 */
int
gcry_cipher_map_name( const char *string )
{
    int i;
    const char *s;

    do {
	for(i=0; (s=cipher_table[i].name); i++ )
	    if( !stricmp( s, string ) )
		return cipher_table[i].algo;
    } while( load_cipher_modules() );
    return 0;
}

/****************
 * Map a cipher algo to a string
 */
static const char *
cipher_algo_to_string( int algo )
{
    int i;

    do {
	for(i=0; cipher_table[i].name; i++ )
	    if( cipher_table[i].algo == algo )
		return cipher_table[i].name;
    } while( load_cipher_modules() );
    return NULL;
}

/****************
 * This function simply returns the name of the algorithm or some constant
 * string when there is no algo.  It will never return NULL.
 */
const char *
gcry_cipher_algo_name( int algo )
{
    const char *s = cipher_algo_to_string( algo );
    return s? s: "";
}



static void
disable_cipher_algo( int algo )
{
    int i;

    for(i=0; i < DIM(disabled_algos); i++ ) {
	if( !disabled_algos[i] || disabled_algos[i] == algo ) {
	    disabled_algos[i] = algo;
	    return;
	}
    }
    /* fixme: we should use a linked list */
    log_fatal("can't disable cipher algo %d: table full\n", algo );
}

/****************
 * Return 0 if the cipher algo is available
 */
static int
check_cipher_algo( int algo )
{
    int i;

    do {
       for(i=0; cipher_table[i].name; i++ )
	   if( cipher_table[i].algo == algo ) {
		for(i=0; i < DIM(disabled_algos); i++ ) {
		   if( disabled_algos[i] == algo )
		       return GCRYERR_INV_CIPHER_ALGO;
		}
		return 0; /* okay */
	   }
    } while( load_cipher_modules() );
    return GCRYERR_INV_CIPHER_ALGO;
}


static unsigned
cipher_get_keylen( int algo )
{
    int i;
    unsigned len = 0;

    do {
	for(i=0; cipher_table[i].name; i++ ) {
	    if( cipher_table[i].algo == algo ) {
		len = cipher_table[i].keylen;
		if( !len )
		    log_bug("cipher %d w/o key length\n", algo );
		return len;
	    }
	}
    } while( load_cipher_modules() );
    log_bug("cipher %d not found\n", algo );
    return 0;
}

static unsigned
cipher_get_blocksize( int algo )
{
    int i;
    unsigned len = 0;

    do {
	for(i=0; cipher_table[i].name; i++ ) {
	    if( cipher_table[i].algo == algo ) {
		len = cipher_table[i].blocksize;
		if( !len )
		    log_bug("cipher %d w/o blocksize\n", algo );
		return len;
	    }
	}
    } while( load_cipher_modules() );
    log_bug("cipher %d not found\n", algo );
    return 0;
}


/****************
 * Open a cipher handle for use with algorithm ALGO, in mode MODE
 * and return the handle.  Return NULL and set the internal error variable
 * if something goes wrong.
 */

GCRY_CIPHER_HD
gcry_cipher_open( int algo, int mode, unsigned int flags )
{
    GCRY_CIPHER_HD h;
    int idx;
    int secure = (flags & GCRY_CIPHER_SECURE);

    fast_random_poll();

    /* check whether the algo is available */
    if( check_cipher_algo( algo ) ) {
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	return NULL;
    }

    /* check flags */
    if( (flags & ~(GCRY_CIPHER_SECURE|GCRY_CIPHER_ENABLE_SYNC)) ) {
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	return NULL;
    }

    /* get the table index of the algo */
    for(idx=0; cipher_table[idx].name; idx++ )
	if( cipher_table[idx].algo == algo )
	    break;
    if( !cipher_table[idx].name )
	BUG(); /* check_cipher_algo() should have loaded the algo */

    if( algo == CIPHER_ALGO_DUMMY )
	mode = GCRY_CIPHER_MODE_NONE;  /* force this mode for dummy algo */

    /* check that a valid mode has been requested */
    switch( mode ) {
      case GCRY_CIPHER_MODE_ECB:
      case GCRY_CIPHER_MODE_CBC:
      case GCRY_CIPHER_MODE_CFB:
        if ( cipher_table[idx].encrypt == dummy_encrypt_block
             || cipher_table[idx].decrypt == dummy_decrypt_block ) {
            set_lasterr( GCRYERR_INV_CIPHER_MODE );
            return NULL;
        }
        break;
      case GCRY_CIPHER_MODE_STREAM:
        if ( cipher_table[idx].stencrypt == dummy_encrypt_stream
             || cipher_table[idx].stdecrypt == dummy_decrypt_stream ) {
            set_lasterr( GCRYERR_INV_CIPHER_MODE );
            return NULL;
        }
	break;
      case GCRY_CIPHER_MODE_NONE:
	/* FIXME: issue a warning when this mode is used */
	break;
      default:
	set_lasterr( GCRYERR_INV_CIPHER_MODE );
	return NULL;
    }

    /* ? perform selftest here and mark this with a flag in cipher_table ? */

    h = secure ? g10_calloc_secure( 1, sizeof *h
				       + cipher_table[idx].contextsize
				       - sizeof(PROPERLY_ALIGNED_TYPE) )
	       : g10_calloc( 1, sizeof *h + cipher_table[idx].contextsize
                                       - sizeof(PROPERLY_ALIGNED_TYPE)  );
    if( !h ) {
	set_lasterr( GCRYERR_NO_MEM );
	return NULL;
    }
    h->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
    h->algo = algo;
    h->mode = mode;
    h->flags = flags;
    h->blocksize = cipher_table[idx].blocksize;
    h->setkey  = cipher_table[idx].setkey;
    h->encrypt = cipher_table[idx].encrypt;
    h->decrypt = cipher_table[idx].decrypt;
    h->stencrypt = cipher_table[idx].stencrypt;
    h->stdecrypt = cipher_table[idx].stdecrypt;

    return h;
}


void
gcry_cipher_close( GCRY_CIPHER_HD h )
{
    if( !h )
	return;
    if( h->magic != CTX_MAGIC_SECURE && h->magic != CTX_MAGIC_NORMAL )
	g10_fatal_error(GCRYERR_INTERNAL,
			"gcry_cipher_close: already closed/invalid handle");
    h->magic = 0;
    g10_free(h);
}


static int
cipher_setkey( GCRY_CIPHER_HD c, byte *key, unsigned keylen )
{
    return (*c->setkey)( &c->context.c, key, keylen );
}


static void
cipher_setiv( GCRY_CIPHER_HD c, const byte *iv, unsigned ivlen )
{
    memset( c->iv, 0, c->blocksize );
    if( iv ) {
	if( ivlen != c->blocksize )
	    log_info("WARNING: cipher_setiv: ivlen=%u blklen=%u\n",
					     ivlen, (unsigned)c->blocksize );
	if( ivlen > c->blocksize )
	    ivlen = c->blocksize;
	memcpy( c->iv, iv, ivlen );
    }
    c->unused = 0;
}



static void
do_ecb_encrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->encrypt)( &c->context.c, outbuf, (byte*)/*arggg*/inbuf );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_ecb_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->decrypt)( &c->context.c, outbuf, (byte*)/*arggg*/inbuf );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_cbc_encrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nblocks )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->blocksize;

    for(n=0; n < nblocks; n++ ) {
	/* fixme: the xor should works on words and not on
	 * bytes.  Maybe it is a good idea to enhance the cipher backend
	 * API to allow for CBC handling in the backend */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    outbuf[i] = inbuf[i] ^ *ivp++;
	(*c->encrypt)( &c->context.c, outbuf, outbuf );
	memcpy(c->iv, outbuf, blocksize );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_cbc_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nblocks )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->blocksize;

    for(n=0; n < nblocks; n++ ) {
	/* because outbuf and inbuf might be the same, we have
	 * to save the original ciphertext block.  We use lastiv
	 * for this here because it is not used otherwise */
	memcpy(c->lastiv, inbuf, blocksize );
	(*c->decrypt)( &c->context.c, outbuf, (char*)/*argggg*/inbuf );
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    outbuf[i] ^= *ivp++;
	memcpy(c->iv, c->lastiv, blocksize );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}


static void
do_cfb_encrypt( GCRY_CIPHER_HD c,
                byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    byte *ivp;
    size_t blocksize = c->blocksize;

    if( nbytes <= c->unused ) {
	/* short enough to be encoded by the remaining XOR mask */
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv+c->blocksize - c->unused; nbytes; nbytes--, c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+blocksize - c->unused; c->unused; c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }

    /* now we can process complete blocks */
    while( nbytes >= blocksize ) {
	int i;
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->encrypt)( &c->context.c, c->iv, c->iv );
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	nbytes -= blocksize;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->encrypt)( &c->context.c, c->iv, c->iv );
	c->unused = blocksize;
	/* and apply the xor */
	c->unused -= nbytes;
	for(ivp=c->iv; nbytes; nbytes-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }
}

static void
do_cfb_decrypt( GCRY_CIPHER_HD c,
                byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    byte *ivp;
    ulong temp;
    size_t blocksize = c->blocksize;

    if( nbytes <= c->unused ) {
	/* short enough to be encoded by the remaining XOR mask */
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv+blocksize - c->unused; nbytes; nbytes--,c->unused--){
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+blocksize - c->unused; c->unused; c->unused-- ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
    }

    /* now we can process complete blocks */
    while( nbytes >= blocksize ) {
	int i;
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->encrypt)( &c->context.c, c->iv, c->iv );
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < blocksize; i++ ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
	nbytes -= blocksize;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->encrypt)( &c->context.c, c->iv, c->iv );
	c->unused = blocksize;
	/* and apply the xor */
	c->unused -= nbytes;
	for(ivp=c->iv; nbytes; nbytes-- ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
    }
}




/****************
 * Encrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some contraints apply to NBYTES.
 */
static void
cipher_encrypt( GCRY_CIPHER_HD c, byte *outbuf,
				  const byte *inbuf, unsigned int nbytes )
{
    switch( c->mode ) {
      case GCRY_CIPHER_MODE_ECB:
	assert(!(nbytes%8));
	do_ecb_encrypt(c, outbuf, inbuf, nbytes/8 );
	break;
      case GCRY_CIPHER_MODE_CBC:
	assert(!(nbytes%8));  /* fixme: should be blocksize */
	do_cbc_encrypt(c, outbuf, inbuf, nbytes/8 );
	break;
      case GCRY_CIPHER_MODE_CFB:
	do_cfb_encrypt(c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_STREAM:
        (*c->stencrypt)( &c->context.c,
                         outbuf, (byte*)/*arggg*/inbuf, nbytes );
        break;
      case GCRY_CIPHER_MODE_NONE:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default: log_fatal("cipher_encrypt: invalid mode %d\n", c->mode );
    }
}


/****************
 * Encrypt IN and write it to OUT.  If IN is NULL, in-place encryption has
 * been requested,
 */
int
gcry_cipher_encrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				       const byte  *in, size_t inlen )
{
    if( !in ) {
	/* caller requested in-place encryption */
	/* actullay cipher_encrypt() does not need to know about it, but
	 * we may chnage this to get better performace */
	cipher_encrypt( h, out, out, outsize );
    }
    else {
	if( outsize < inlen )
	    return set_lasterr( GCRYERR_TOO_SHORT );
	/* fixme: check that the inlength is a multipe of the blocksize
	 * if a blockoriented mode is used, or modify cipher_encrypt to
	 * return an error in this case */
	cipher_encrypt( h, out, in, inlen );
    }
    return 0;
}



/****************
 * Decrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some some contraints apply to NBYTES.
 */
static void
cipher_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf,
							unsigned nbytes )
{
    switch( c->mode ) {
      case GCRY_CIPHER_MODE_ECB:
	assert(!(nbytes%8));
	do_ecb_decrypt(c, outbuf, inbuf, nbytes/8 );
	break;
      case GCRY_CIPHER_MODE_CBC:
	assert(!(nbytes%8));	/* fixme: should assert on blocksize */
	do_cbc_decrypt(c, outbuf, inbuf, nbytes/8 );
	break;
      case GCRY_CIPHER_MODE_CFB:
	do_cfb_decrypt(c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_STREAM:
        (*c->stdecrypt)( &c->context.c,
                         outbuf, (byte*)/*arggg*/inbuf, nbytes );
        break;
      case GCRY_CIPHER_MODE_NONE:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default: log_fatal("cipher_decrypt: invalid mode %d\n", c->mode );
    }
}


int
gcry_cipher_decrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				 const byte  *in, size_t inlen )
{
    if( !in ) {
	/* caller requested in-place encryption */
	/* actullay cipher_encrypt() does not need to know about it, but
	 * we may chnage this to get better performace */
	cipher_decrypt( h, out, out, outsize );
    }
    else {
	if( outsize < inlen )
	    return set_lasterr( GCRYERR_TOO_SHORT );
	/* fixme: check that the inlength is a multipe of the blocksize
	 * if a blockoriented mode is used, or modify cipher_encrypt to
	 * return an error in this case */
	cipher_decrypt( h, out, in, inlen );
    }
    return 0;
}



/****************
 * Used for PGP's somewhat strange CFB mode. Only works if
 * the corresponding flag is set.
 */
static void
cipher_sync( GCRY_CIPHER_HD c )
{
    if( (c->flags & GCRY_CIPHER_ENABLE_SYNC) && c->unused ) {
	memmove(c->iv + c->unused, c->iv, c->blocksize - c->unused );
	memcpy(c->iv, c->lastiv + c->blocksize - c->unused, c->unused);
	c->unused = 0;
    }
}


int
gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, void *buffer, size_t buflen)
{
    switch( cmd ) {
      case GCRYCTL_SET_KEY:
	cipher_setkey( h, buffer, buflen );
	break;
      case GCRYCTL_SET_IV:
	cipher_setiv( h, buffer, buflen );
	break;
      case GCRYCTL_CFB_SYNC:
	cipher_sync( h );
	break;

      case GCRYCTL_DISABLE_ALGO:
	/* this one expects a NULL handle and buffer pointing to an
	 * integer with the algo number.
	 */
	if( h || !buffer || buflen != sizeof(int) )
	    return set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	disable_cipher_algo( *(int*)buffer );
	break;

      default:
	return set_lasterr( GCRYERR_INV_OP );
    }
    return 0;
}


/****************
 * Return information about the cipher handle.
 * -1 is returned on error and gcry_errno() may be used to get more information
 * about the error.
 */
int
gcry_cipher_info( GCRY_CIPHER_HD h, int cmd, void *buffer, size_t *nbytes)
{
    switch( cmd ) {
      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
}

/****************
 * Return information about the given cipher algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_GET_KEYLEN:
 *	Return the length of the key, if the algorithm
 *	supports multiple key length, the maximum supported value
 *	is returnd.  The length is return as number of octets.
 *	buffer and nbytes must be zero.
 *	The keylength is returned in _bytes_.
 *  GCRYCTL_GET_BLKLEN:
 *	Return the blocklength of the algorithm counted in octets.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	buffer and nbytes must be zero.
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
gcry_cipher_algo_info( int algo, int what, void *buffer, size_t *nbytes)
{
    unsigned int ui;

    switch( what ) {
      case GCRYCTL_GET_KEYLEN:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	    break;
	}
	ui = cipher_get_keylen( algo );
	if( ui > 0 && ui <= 512 )
	    return (int)ui/8;
	/* the only reason is an invalid algo or a strange blocksize */
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	break;

      case GCRYCTL_GET_BLKLEN:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	    break;
	}
	ui = cipher_get_blocksize( algo );
	if( ui > 0 && ui < 10000 )
	    return (int)ui;
	/* the only reason is an invalid algo or a strange blocksize */
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	break;

      case GCRYCTL_TEST_ALGO:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_ARG );
	    break;
	}
	if( check_cipher_algo( algo ) ) {
	    set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	    break;
	}
	return 0;

      default:
	set_lasterr( GCRYERR_INV_OP );
    }
    return -1;
}



