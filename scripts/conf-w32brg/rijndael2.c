/* Rijndael (AES) for GnuPG
 *	Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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
 *******************************************************************
 A version of rijndael.c modified by Brian Gladman to use his AES code  
 */

#include <stdlib.h>
#include <string.h> /* for memcmp() */

#include "util.h"

#include "aes.h"

typedef struct
{	aes_encrypt_ctx	ectx[1];
	aes_decrypt_ctx	dctx[1];
	unsigned int	klen;
	unsigned int	dkey;
} RIJNDAEL_context;

static const char *selftest(void);
static int tested = 0;

static void
burn_stack (int bytes)
{
    char buf[64];
    
    wipememory(buf,sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        burn_stack (bytes);
}

static int
rijndael_setkey (RIJNDAEL_context *ctx, const byte *key, const unsigned keylen)
{	int		rc;

	if(!tested)
	{	const char	*tr;
		tested = 1;
		tr = selftest();
        if(tr)
		{
            fprintf(stderr, "%s\n", tr );
			return G10ERR_SELFTEST_FAILED;		
		}
	}

	ctx->klen = keylen;
	ctx->dkey = 0;
	rc = 0;
	if(keylen == 16 || keylen == 24 || keylen == 32)
		aes_encrypt_key(key, keylen, ctx->ectx);
	else
		rc = 1;
    burn_stack ( 100 + 16*sizeof(int));
    return rc;
}

static void
rijndael_encrypt (const RIJNDAEL_context *ctx, byte *b, const byte *a)
{
    aes_encrypt(a, b, ctx->ectx);
    burn_stack (16 + 2*sizeof(int));
}

static void
rijndael_decrypt (RIJNDAEL_context *ctx, byte *b, const byte *a)
{
	if(!(ctx->dkey))
	{
		aes_decrypt_key((byte*)ctx->ectx, ctx->klen, ctx->dctx);
		ctx->dkey = 1;
	}
    aes_decrypt(a, b, ctx->dctx);
    burn_stack (16+2*sizeof(int));
}

/* Test a single encryption and decryption with each key size. */

static const char*
selftest (void)
{
    RIJNDAEL_context ctx;
    byte scratch[16];	   

    /* The test vectors are from the AES supplied ones; more or less 
     * randomly taken from ecb_tbl.txt (I=42,81,14)
     */
    static const byte plaintext[16] = {
       0x01,0x4B,0xAF,0x22,0x78,0xA6,0x9D,0x33,
       0x1D,0x51,0x80,0x10,0x36,0x43,0xE9,0x9A
    };
    static const byte key[16] = {
        0xE8,0xE9,0xEA,0xEB,0xED,0xEE,0xEF,0xF0,
        0xF2,0xF3,0xF4,0xF5,0xF7,0xF8,0xF9,0xFA
    };
    static const byte ciphertext[16] = {
        0x67,0x43,0xC3,0xD1,0x51,0x9A,0xB4,0xF2,
        0xCD,0x9A,0x78,0xAB,0x09,0xA5,0x11,0xBD
    };

    static const byte plaintext_192[16] = {
        0x76,0x77,0x74,0x75,0xF1,0xF2,0xF3,0xF4,
        0xF8,0xF9,0xE6,0xE7,0x77,0x70,0x71,0x72
    };
    static const byte key_192[24] = {
        0x04,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0C,
        0x0E,0x0F,0x10,0x11,0x13,0x14,0x15,0x16,
        0x18,0x19,0x1A,0x1B,0x1D,0x1E,0x1F,0x20
    };
    static const byte ciphertext_192[16] = {
        0x5D,0x1E,0xF2,0x0D,0xCE,0xD6,0xBC,0xBC,
        0x12,0x13,0x1A,0xC7,0xC5,0x47,0x88,0xAA
    };
    
    static const byte plaintext_256[16] = {
        0x06,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,
        0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x21
    };
    static const byte key_256[32] = {
        0x08,0x09,0x0A,0x0B,0x0D,0x0E,0x0F,0x10,
        0x12,0x13,0x14,0x15,0x17,0x18,0x19,0x1A,
        0x1C,0x1D,0x1E,0x1F,0x21,0x22,0x23,0x24,
        0x26,0x27,0x28,0x29,0x2B,0x2C,0x2D,0x2E
    };
    static const byte ciphertext_256[16] = {
        0x08,0x0E,0x95,0x17,0xEB,0x16,0x77,0x71,
        0x9A,0xCF,0x72,0x80,0x86,0x04,0x0A,0xE3
    };

    rijndael_setkey (&ctx, key, sizeof(key));
    rijndael_encrypt (&ctx, scratch, plaintext);
    if (memcmp (scratch, ciphertext, sizeof (ciphertext)))
        return "Rijndael-128 test encryption failed.";
    rijndael_decrypt (&ctx, scratch, scratch);
    if (memcmp (scratch, plaintext, sizeof (plaintext)))
        return "Rijndael-128 test decryption failed.";

    rijndael_setkey (&ctx, key_192, sizeof(key_192));
    rijndael_encrypt (&ctx, scratch, plaintext_192);
    if (memcmp (scratch, ciphertext_192, sizeof (ciphertext_192)))
        return "Rijndael-192 test encryption failed.";
    rijndael_decrypt (&ctx, scratch, scratch);
    if (memcmp (scratch, plaintext_192, sizeof (plaintext_192)))
        return "Rijndael-192 test decryption failed.";
    
    rijndael_setkey (&ctx, key_256, sizeof(key_256));
    rijndael_encrypt (&ctx, scratch, plaintext_256);
    if (memcmp (scratch, ciphertext_256, sizeof (ciphertext_256)))
        return "Rijndael-256 test encryption failed.";
    rijndael_decrypt (&ctx, scratch, scratch);
    if (memcmp (scratch, plaintext_256, sizeof (plaintext_256)))
        return "Rijndael-256 test decryption failed.";
    
    return NULL;
}

#ifdef IS_MODULE
static
#endif
       const char *
		  rijndael_get_info (int algo, size_t *keylen,
		  size_t *blocksize, size_t *contextsize,
		  int  (**r_setkey) (void *c, byte *key, unsigned keylen),
		  void (**r_encrypt) (void *c, byte *outbuf, byte *inbuf),
		  void (**r_decrypt) (void *c, byte *outbuf, byte *inbuf)
		 )
{
    *keylen = algo==7? 128 :  algo==8? 192 : 256;
    *blocksize = 16;
    *contextsize = sizeof (RIJNDAEL_context);

    *(int  (**)(RIJNDAEL_context*, const byte*, const unsigned))r_setkey
							= rijndael_setkey;
    *(void (**)(const RIJNDAEL_context*, byte*, const byte*))r_encrypt
							= rijndael_encrypt;
    *(void (**)(RIJNDAEL_context*, byte*, const byte*))r_decrypt
							= rijndael_decrypt;

    if( algo == 7 )
	return "AES";
    if (algo == 8)
        return "AES192";
    if (algo == 9)
        return "AES256";
    return NULL;
}


#ifdef IS_MODULE
static
const char * const gnupgext_version = "RIJNDAEL ($Revision$)";

static struct {
    int class;
    int version;
    int  value;
    void (*func)(void);
} func_table[] = {
    { 20, 1, 0, (void*)rijndael_get_info },
    { 21, 1, 7  },
    { 21, 1, 8  },
    { 21, 1, 9  },
};



/****************
 * Enumerate the names of the functions together with information about
 * this function. Set sequence to an integer with a initial value of 0 and
 * do not change it.
 * If what is 0 all kind of functions are returned.
 * Return values: class := class of function:
 *			   10 = message digest algorithm info function
 *			   11 = integer with available md algorithms
 *			   20 = cipher algorithm info function
 *			   21 = integer with available cipher algorithms
 *			   30 = public key algorithm info function
 *			   31 = integer with available pubkey algorithms
 *		  version = interface version of the function/pointer
 *			    (currently this is 1 for all functions)
 */
static
void *
gnupgext_enum_func ( int what, int *sequence, int *class, int *vers )
{
    void *ret;
    int i = *sequence;

    do {
	if ( i >= DIM(func_table) || i < 0 ) {
	    return NULL;
	}
	*class = func_table[i].class;
	*vers  = func_table[i].version;
	switch( *class ) {
	  case 11:
	  case 21:
	  case 31:
	    ret = &func_table[i].value;
	    break;
	  default:
	    ret = func_table[i].func;
	    break;
	}
	i++;
    } while ( what && what != *class );

    *sequence = i;
    return ret;
}
#endif









