/* cipher.c  -	cipher dispatcher
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

#define DEFINES_CIPHER_HANDLE 1

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "errors.h"
#include "cipher.h"
#include "blowfish.h"
#include "cast5.h"
#include "dynload.h"


#define MAX_BLOCKSIZE 16
#define TABLE_SIZE 10

struct cipher_table_s {
    const char *name;
    int algo;
    size_t blocksize;
    size_t keylen;
    size_t contextsize; /* allocate this amount of context */
    void (*setkey)( void *c, byte *key, unsigned keylen );
    void (*encrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*decrypt)( void *c, byte *outbuf, byte *inbuf );
};

static struct cipher_table_s cipher_table[TABLE_SIZE];


struct cipher_handle_s {
    int  algo;
    int  mode;
    size_t blocksize;
    byte iv[MAX_BLOCKSIZE];	/* (this should be ulong aligned) */
    byte lastiv[MAX_BLOCKSIZE];
    int  unused;  /* in IV */
    void (*setkey)( void *c, byte *key, unsigned keylen );
    void (*encrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*decrypt)( void *c, byte *outbuf, byte *inbuf );
    byte context[1];
};


static void
dummy_setkey( void *c, byte *key, unsigned keylen ) { }
static void
dummy_encrypt_block( void *c, byte *outbuf, byte *inbuf ) { BUG(); }
static void
dummy_decrypt_block( void *c, byte *outbuf, byte *inbuf ) { BUG(); }



/****************
 * Put the static entries into the table.
 */
static void
setup_cipher_table()
{

    int i;

    i = 0;
    cipher_table[i].algo = CIPHER_ALGO_BLOWFISH;
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
    cipher_table[i].algo = CIPHER_ALGO_CAST5;
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
    cipher_table[i].algo = CIPHER_ALGO_BLOWFISH160;
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
    cipher_table[i].algo = CIPHER_ALGO_DUMMY;
    cipher_table[i].name = "DUMMY";
    cipher_table[i].blocksize = 8;
    cipher_table[i].keylen = 128;
    cipher_table[i].contextsize = 0;
    cipher_table[i].setkey = dummy_setkey;
    cipher_table[i].encrypt = dummy_encrypt_block;
    cipher_table[i].decrypt = dummy_decrypt_block;
    i++;

    for( ; i < TABLE_SIZE; i++ )
	cipher_table[i].name = NULL;
}


/****************
 * Try to load all modules and return true if new modules are available
 */
static int
load_cipher_modules()
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
	if( g10_opt_verbose > 1 )
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
 * Map a string to the cipher algo
 */
int
string_to_cipher_algo( const char *string )
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
const char *
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
 * Return 0 if the cipher algo is available
 */
int
check_cipher_algo( int algo )
{
    int i;

    do {
       for(i=0; cipher_table[i].name; i++ )
	   if( cipher_table[i].algo == algo )
	       return 0; /* okay */
    } while( load_cipher_modules() );
    return G10ERR_CIPHER_ALGO;
}


unsigned
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

unsigned
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
 * and put it into secure memory if SECURE is true.
 */
CIPHER_HANDLE
cipher_open( int algo, int mode, int secure )
{
    CIPHER_HANDLE hd;
    int i;

    fast_random_poll();
    do {
	for(i=0; cipher_table[i].name; i++ )
	    if( cipher_table[i].algo == algo )
		break;
    } while( !cipher_table[i].name && load_cipher_modules() );
    if( !cipher_table[i].name ) {
	log_fatal("cipher_open: algorithm %d not available\n", algo );
	return NULL;
    }

    /* ? perform selftest here and mark this with a flag in cipher_table ? */

    hd = secure ? m_alloc_secure_clear( sizeof *hd
					+ cipher_table[i].contextsize )
		: m_alloc_clear( sizeof *hd + cipher_table[i].contextsize );
    hd->algo = algo;
    hd->blocksize = cipher_table[i].blocksize;
    hd->setkey	= cipher_table[i].setkey;
    hd->encrypt = cipher_table[i].encrypt;
    hd->decrypt = cipher_table[i].decrypt;
    if( algo == CIPHER_ALGO_DUMMY )
	hd->mode = CIPHER_MODE_DUMMY;
    else if( mode == CIPHER_MODE_AUTO_CFB ) {
	if( algo == CIPHER_ALGO_BLOWFISH160 || algo >= 100 )
	    hd->mode = CIPHER_MODE_CFB;
	else
	    hd->mode = CIPHER_MODE_PHILS_CFB;
    }
    else
	hd->mode = mode;

    return hd;
}


void
cipher_close( CIPHER_HANDLE c )
{
    m_free(c);
}


void
cipher_setkey( CIPHER_HANDLE c, byte *key, unsigned keylen )
{
    (*c->setkey)( &c->context, key, keylen );
}



void
cipher_setiv( CIPHER_HANDLE c, const byte *iv )
{
    if( iv )
	memcpy( c->iv, iv, c->blocksize );
    else
	memset( c->iv, 0, c->blocksize );
    c->unused = 0;
}



static void
do_ecb_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->encrypt)( &c->context, outbuf, inbuf );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}

static void
do_ecb_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->decrypt)( &c->context, outbuf, inbuf );
	inbuf  += c->blocksize;
	outbuf += c->blocksize;
    }
}


static void
do_cfb_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
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
	(*c->encrypt)( &c->context, c->iv, c->iv );
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	nbytes -= blocksize;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->encrypt)( &c->context, c->iv, c->iv );
	c->unused = blocksize;
	/* and apply the xor */
	c->unused -= nbytes;
	for(ivp=c->iv; nbytes; nbytes-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }
}

static void
do_cfb_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
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
	(*c->encrypt)( &c->context, c->iv, c->iv );
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
	(*c->encrypt)( &c->context, c->iv, c->iv );
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
 * Depending on the mode some some contraints apply to NBYTES.
 */
void
cipher_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
    switch( c->mode ) {
      case CIPHER_MODE_ECB:
	assert(!(nbytes%8));
	do_ecb_encrypt(c, outbuf, inbuf, nbytes/8 );
	break;
      case CIPHER_MODE_CFB:
      case CIPHER_MODE_PHILS_CFB:
	do_cfb_encrypt(c, outbuf, inbuf, nbytes );
	break;
      case CIPHER_MODE_DUMMY:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default: log_fatal("cipher_encrypt: invalid mode %d\n", c->mode );
    }
}


/****************
 * Decrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some some contraints apply to NBYTES.
 */
void
cipher_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
    switch( c->mode ) {
      case CIPHER_MODE_ECB:
	assert(!(nbytes%8));
	do_ecb_decrypt(c, outbuf, inbuf, nbytes/8 );
	break;
      case CIPHER_MODE_CFB:
      case CIPHER_MODE_PHILS_CFB:
	do_cfb_decrypt(c, outbuf, inbuf, nbytes );
	break;
      case CIPHER_MODE_DUMMY:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default: log_fatal("cipher_decrypt: invalid mode %d\n", c->mode );
    }
}



/****************
 * Used for PGP's somewhat strange CFB mode. Only works if
 * the handle is in PHILS_CFB mode
 */
void
cipher_sync( CIPHER_HANDLE c )
{
    if( c->mode == CIPHER_MODE_PHILS_CFB && c->unused ) {
	memmove(c->iv + c->unused, c->iv, c->blocksize - c->unused );
	memcpy(c->iv, c->lastiv + c->blocksize - c->unused, c->unused);
	c->unused = 0;
    }
}

