/* arcfour.c  -  The arcfour stream cipher
 *	Copyright (C) 2000 Free Software Foundation, Inc.
 *
 * For a description of the algorithm, see:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. Pages 397 ff.
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
#include "types.h"
#include "g10lib.h"
#include "arcfour.h"

static const char *selftest(void);


typedef struct {
    int idx_i, idx_j;
    byte sbox[256];
} ARCFOUR_context;


static void
encrypt_stream( ARCFOUR_context *ctx,
                byte *outbuf, const byte *inbuf, unsigned int length )
{
    int t;  
    int i = ctx->idx_i;
    int j = ctx->idx_j;
    byte *sbox = ctx->sbox;

    while ( length-- ) {
        i = (i+1) % 256;
        j = (j + sbox[i]) % 256;
        t = sbox[i]; sbox[i] = sbox[j]; sbox[j] = t;
        *outbuf++ = *inbuf++ ^ sbox[(sbox[i] + sbox[j]) % 256];
    }

    ctx->idx_i = i;
    ctx->idx_j = j;
}


static int
arcfour_setkey( ARCFOUR_context *ctx, const byte *key, unsigned int keylen )
{
    static int initialized;
    static const char* selftest_failed;
    int i, j;
    byte karr[256];

    if( !initialized ) {
	initialized = 1;
	selftest_failed = selftest();
	if( selftest_failed )
	    fprintf(stderr,"ARCFOUR selftest failed (%s)\n", selftest_failed );
    }
    if( selftest_failed )
	return GCRYERR_SELFTEST;

    if( keylen < 40 )
	return GCRYERR_INV_KEYLEN;

    ctx->idx_i = ctx->idx_j = 0;
    for (i=0; i < 256; i++ )
        ctx->sbox[i] = i;
    for (i=0; i < 256; i++ )
        karr[i] = key[i%keylen];
    for (i=j=0; i < 256; i++ ) {
        int t;
        j = (j + ctx->sbox[i] + karr[i]) % 256;
        t = ctx->sbox[i];
        ctx->sbox[i] = ctx->sbox[j];
        ctx->sbox[j] = t;
    } 
    memset( karr, 0, 256 );

    return 0;
}


static const char*
selftest(void)
{
    ARCFOUR_context ctx;
    byte scratch[16];	   
    
    /* Test vector from Cryptlib labeled there:
     * "from the State/Commerce Department" */
    static const byte key_1[] =
        { 0x61, 0x8A, 0x63, 0xD2, 0xFB };
    static const byte plaintext_1[] =
        { 0xDC, 0xEE, 0x4C, 0xF9, 0x2C };
    static const byte ciphertext_1[] =
        { 0xF1, 0x38, 0x29, 0xC9, 0xDE };

    arcfour_setkey( &ctx, key_1, sizeof(key_1));
    encrypt_stream( &ctx, scratch, plaintext_1, sizeof(plaintext_1));
    if (memcmp (scratch, ciphertext_1, sizeof (ciphertext_1)))
        return "Arcfour encryption test 1 failed.";
    encrypt_stream(&ctx, scratch, scratch, sizeof(plaintext_1)); /* decrypt */
    if ( memcmp (scratch, plaintext_1, sizeof (plaintext_1)))
        return "Arcfour decryption test 1 failed.";
    return NULL;
}


/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 * NOTE: This is a special get_info function which is different from all
 * others because arcfour is a stream cipher.  We use this hack until
 * we have redesign the interface.
 */
const char *
arcfour_get_info( int algo, size_t *keylen, size_t *blocksize,
		   size_t *contextsize,
		   int	(**r_setkey)( void *c, byte *key, unsigned keylen ),
		   void (**r_stencrypt)( void *c, byte *outbuf,
                                       byte *inbuf, unsigned int nbytes ),
		   void (**r_stdecrypt)( void *c, byte *outbuf,
                                       byte *inbuf, unsigned int nbytes )
		 )
{
    *keylen = 128; /* arbitrary value */
    *blocksize = 1;
    *contextsize = sizeof(ARCFOUR_context);
    *(int  (**)(ARCFOUR_context*, byte*, unsigned))r_setkey
							= arcfour_setkey;
    *(void (**)(ARCFOUR_context*, byte*, const byte*, unsigned))r_stencrypt
							= encrypt_stream;
    *(void (**)(ARCFOUR_context*, byte*, const byte*, unsigned))r_stdecrypt
							= encrypt_stream;


    if( algo == 301 )
	return "ARCFOUR";
    return NULL;
}




