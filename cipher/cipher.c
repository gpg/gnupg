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

#define STD_BLOCKSIZE 8

#if BLOWFISH_BLOCKSIZE != STD_BLOCKSIZE
  #error Invalid BLOWFISH blocksize
#elif CAST5_BLOCKSIZE != STD_BLOCKSIZE
  #error Invalid CAST blocksize
#endif


static struct { const char *name; int algo;} cipher_names[] = {
    { "IDEA",        CIPHER_ALGO_IDEA        },
    { "3DES",        CIPHER_ALGO_3DES        },
    { "CAST",        CIPHER_ALGO_CAST        },
    { "BLOWFISH128", CIPHER_ALGO_BLOWFISH128 },
    { "ROT_N",       CIPHER_ALGO_ROT_N       },
    { "SAFER_SK128", CIPHER_ALGO_SAFER_SK128 },
    { "DES_SK",      CIPHER_ALGO_DES_SK      },
    { "BLOWFISH",    CIPHER_ALGO_BLOWFISH    },
    {NULL} };


/* Hmmm, no way for a void arg in function pointer? */
#define FNCCAST_SETKEY(f)  (void(*)(void*, byte*, unsigned))(f)
#define FNCCAST_CRYPT(f)   (void(*)(void*, byte*, byte*))(f)


struct cipher_handle_s {
    int  algo;
    int  mode;
    byte iv[STD_BLOCKSIZE];	/* (this should be ulong aligned) */
    byte lastiv[STD_BLOCKSIZE];
    int  unused;  /* in IV */
    void (*setkey)( void *c, byte *key, unsigned keylen );
    void (*encrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*decrypt)( void *c, byte *outbuf, byte *inbuf );
    void (*sync_cfb)( void *c );
    union {
	int		 context;
	BLOWFISH_context blowfish;
	CAST5_context cast5;
    } c;
};


/****************
 * Map a string to the cipher algo
 */
int
string_to_cipher_algo( const char *string )
{
    int i;
    const char *s;

    for(i=0; (s=cipher_names[i].name); i++ )
	if( !stricmp( s, string ) )
	    return cipher_names[i].algo;
    return 0;
}

/****************
 * Map a cipher algo to a string
 */
const char *
cipher_algo_to_string( int algo )
{
    int i;

    for(i=0; cipher_names[i].name; i++ )
	if( cipher_names[i].algo == algo )
	    return cipher_names[i].name;
    return NULL;
}

/****************
 * Return 0 if the cipher algo is available
 */
int
check_cipher_algo( int algo )
{
    switch( algo ) {
      case CIPHER_ALGO_BLOWFISH128:
      case CIPHER_ALGO_BLOWFISH:
      case CIPHER_ALGO_CAST:
	return 0;
      default:
	return G10ERR_CIPHER_ALGO;
    }
}


/****************
 * Open a cipher handle for use with algorithm ALGO, in mode MODE
 * and put it into secure memory if SECURE is true.
 */
CIPHER_HANDLE
cipher_open( int algo, int mode, int secure )
{
    CIPHER_HANDLE hd;

    fast_random_poll();
    /* performance hint:
     * It is possible to allocate less memory depending on the cipher */
    hd = secure ? m_alloc_secure_clear( sizeof *hd )
		: m_alloc_clear( sizeof *hd );
    hd->algo = algo;
    if( mode == CIPHER_MODE_AUTO_CFB ) {
	if( algo == CIPHER_ALGO_CAST )
	    hd->mode = CIPHER_MODE_PHILS_CFB;
	else
	    hd->mode = CIPHER_MODE_CFB;
    }
    else
	hd->mode = mode;
    switch( algo )  {
      case CIPHER_ALGO_BLOWFISH:
      case CIPHER_ALGO_BLOWFISH128:
	hd->setkey  = FNCCAST_SETKEY(blowfish_setkey);
	hd->encrypt = FNCCAST_CRYPT(blowfish_encrypt_block);
	hd->decrypt = FNCCAST_CRYPT(blowfish_decrypt_block);
	break;

      case CIPHER_ALGO_CAST:
	hd->setkey  = FNCCAST_SETKEY(cast5_setkey);
	hd->encrypt = FNCCAST_CRYPT(cast5_encrypt_block);
	hd->decrypt = FNCCAST_CRYPT(cast5_decrypt_block);
	break;

      default: log_fatal("cipher_open: invalid algo %d\n", algo );
    }

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
    (*c->setkey)( &c->c.context, key, keylen );
}


void
cipher_setiv( CIPHER_HANDLE c, const byte *iv )
{
    if( iv )
	memcpy( c->iv, iv, STD_BLOCKSIZE );
    else
	memset( c->iv, 0, STD_BLOCKSIZE );
    c->unused = 0;
}



static void
do_ecb_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->encrypt)( &c->c.context, outbuf, inbuf );
	inbuf  += CAST5_BLOCKSIZE;;
	outbuf += CAST5_BLOCKSIZE;
    }
}

static void
do_ecb_decrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->decrypt)( &c->c.context, outbuf, inbuf );
	inbuf  += CAST5_BLOCKSIZE;;
	outbuf += CAST5_BLOCKSIZE;
    }
}


static void
do_cfb_encrypt( CIPHER_HANDLE c, byte *outbuf, byte *inbuf, unsigned nbytes )
{
    byte *ivp;

    if( nbytes <= c->unused ) {
	/* short enough to be encoded by the remaining XOR mask */
	/* XOR the input with the IV and store input into IV */
	c->unused -= nbytes;
	for(ivp=c->iv+STD_BLOCKSIZE - c->unused; nbytes; nbytes-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+STD_BLOCKSIZE - c->unused; c->unused; c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }

    /* now we can process complete blocks */
    while( nbytes >= STD_BLOCKSIZE ) {
	int i;
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, STD_BLOCKSIZE );
	(*c->encrypt)( &c->c.context, c->iv, c->iv );
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < STD_BLOCKSIZE; i++ )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	nbytes -= STD_BLOCKSIZE;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, STD_BLOCKSIZE );
	(*c->encrypt)( &c->c.context, c->iv, c->iv );
	c->unused = STD_BLOCKSIZE;
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

    if( nbytes <= c->unused ) {
	/* short enough to be encoded by the remaining XOR mask */
	/* XOR the input with the IV and store input into IV */
	c->unused -= nbytes;
	for(ivp=c->iv+STD_BLOCKSIZE - c->unused; nbytes; nbytes-- ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+STD_BLOCKSIZE - c->unused; c->unused; c->unused-- ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
    }

    /* now we can process complete blocks */
  #ifdef BIG_ENDIAN_HOST
    /* This does only make sense for big endian hosts, due to ... ivp = temp*/
    if( !((ulong)inbuf % SIZEOF_UNSIGNED_LONG) ) {
	while( nbytes >= STD_BLOCKSIZE ) {
	    /* encrypt the IV (and save the current one) */
	    memcpy( c->lastiv, c->iv, STD_BLOCKSIZE );
	    (*c->encrypt)( &c->c.context, c->iv, c->iv );
	    ivp = c->iv;
	    /* XOR the input with the IV and store input into IV */
	  #if SIZEOF_UNSIGNED_LONG == STD_BLOCKSIZE
	    temp = *(ulong*)inbuf;
	    *(ulong*)outbuf = *(ulong*)c->iv ^ temp;
	    *(ulong*)ivp    = temp;
	  #elif (2*SIZEOF_UNSIGNED_LONG) == STD_BLOCKSIZE
	    temp = ((ulong*)inbuf)[0];
	    ((ulong*)outbuf)[0] = ((ulong*)c->iv)[0] ^ temp;
	    ((ulong*)ivp)[0] = temp;
	    temp = ((ulong*)inbuf)[1];
	    ((ulong*)outbuf)[1] = ((ulong*)c->iv)[1] ^ temp;
	    ((ulong*)ivp)[1] = temp;
	  #elif (4*SIZEOF_UNSIGNED_LONG) == STD_BLOCKSIZE
	    temp = ((ulong*)inbuf)[0];
	    ((ulong*)outbuf)[0] = ((ulong*)c->iv)[0] ^ temp;
	    ((ulong*)ivp)[0] = temp;
	    temp = ((ulong*)inbuf)[1];
	    ((ulong*)outbuf)[1] = ((ulong*)c->iv)[1] ^ temp;
	    ((ulong*)ivp)[1] = temp;
	    temp = ((ulong*)inbuf)[2];
	    ((ulong*)outbuf)[2] = ((ulong*)c->iv)[2] ^ temp;
	    ((ulong*)ivp)[2] = temp;
	    temp = ((ulong*)inbuf)[3];
	    ((ulong*)outbuf)[3] = ((ulong*)c->iv)[3] ^ temp;
	    ((ulong*)ivp)[3] = temp;
	  #else
	    #error Please disable the align test.
	  #endif
	    nbytes -= STD_BLOCKSIZE;
	}
    }
    else { /* non aligned version */
  #endif /* BIG_ENDIAN_HOST */
	while( nbytes >= STD_BLOCKSIZE ) {
	    int i;
	    /* encrypt the IV (and save the current one) */
	    memcpy( c->lastiv, c->iv, STD_BLOCKSIZE );
	    (*c->encrypt)( &c->c.context, c->iv, c->iv );
	    /* XOR the input with the IV and store input into IV */
	    for(ivp=c->iv,i=0; i < STD_BLOCKSIZE; i++ ) {
		temp = *inbuf++;
		*outbuf++ = *ivp ^ temp;
		*ivp++ = temp;
	    }
	    nbytes -= STD_BLOCKSIZE;
	}
   #ifdef BIG_ENDIAN_HOST
    }
   #endif
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, STD_BLOCKSIZE );
	(*c->encrypt)( &c->c.context, c->iv, c->iv );
	c->unused = STD_BLOCKSIZE;
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
      default: log_fatal("cipher_decrypt: invalid mode %d\n", c->mode );
    }
}



/****************
 * Used for PGP's somewhat strange CFB mode. Does only work if
 * the handle is in PHILS_CFB mode
 */
void
cipher_sync( CIPHER_HANDLE c )
{
    if( c->mode == CIPHER_MODE_PHILS_CFB && c->unused ) {
	memmove(c->iv + c->unused, c->iv, CAST5_BLOCKSIZE - c->unused );
	memcpy(c->iv, c->lastiv + CAST5_BLOCKSIZE - c->unused, c->unused);
	c->unused = 0;
    }
}

