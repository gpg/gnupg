/* camellia-glue.c - Glue for the Camellia cipher
 * Copyright (C) 2007 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* I put the GnuPG-specific stuff in this file to keep the
   camellia.c/camellia.h files exactly as provided by NTT.  If they
   update their code, this should make it easier to bring the changes
   in. - dshaw */

#include <config.h>
#include <sys/types.h>
#include <string.h>
#include "types.h"
#include "cipher.h"
#include "algorithms.h"
#include "util.h"
#include "errors.h"
#include "camellia.h"

typedef struct
{
  int keybitlength;
  KEY_TABLE_TYPE keytable;
} CAMELLIA_context;

static const char *selftest(void);

static void
burn_stack(int bytes)
{
  char buf[128];

  wipememory(buf,sizeof buf);
  bytes -= sizeof buf;
  if (bytes > 0)
    burn_stack (bytes);
}

static int
camellia_setkey(void *c, const byte *key, unsigned keylen)
{
  CAMELLIA_context *ctx=c;
  static int initialized=0;
  static const char *selftest_failed=NULL;

  if(keylen!=16 && keylen!=32)
    return G10ERR_WRONG_KEYLEN;

  if(!initialized)
    {
      initialized=1;
      selftest_failed=selftest();
      if(selftest_failed)
        log_error("%s\n",selftest_failed);
    }

  if(selftest_failed)
    return G10ERR_SELFTEST_FAILED;

  ctx->keybitlength=keylen*8;
  Camellia_Ekeygen(ctx->keybitlength,key,ctx->keytable); 

  burn_stack
    ((19+34+34)*sizeof(u32)+2*sizeof(void*) /* camellia_setup256 */
     +(4+32)*sizeof(u32)+2*sizeof(void*)    /* camellia_setup192 */
     +0+sizeof(int)+2*sizeof(void*)         /* Camellia_Ekeygen */
     +3*2*sizeof(void*)                     /* Function calls.  */
     );

  return 0;
}

static void
camellia_encrypt(void *c, byte *outbuf, const byte *inbuf)
{
  CAMELLIA_context *ctx=c;

  Camellia_EncryptBlock(ctx->keybitlength,inbuf,ctx->keytable,outbuf);
  burn_stack
    (sizeof(int)+2*sizeof(unsigned char *)+sizeof(KEY_TABLE_TYPE)
     +4*sizeof(u32)
     +2*sizeof(u32*)+4*sizeof(u32)
     +2*2*sizeof(void*) /* Function calls.  */
    );
}

static void
camellia_decrypt(void *c, byte *outbuf, const byte *inbuf)
{
  CAMELLIA_context *ctx=c;

  Camellia_DecryptBlock(ctx->keybitlength,inbuf,ctx->keytable,outbuf);
  burn_stack
    (sizeof(int)+2*sizeof(unsigned char *)+sizeof(KEY_TABLE_TYPE)
     +4*sizeof(u32)
     +2*sizeof(u32*)+4*sizeof(u32)
     +2*2*sizeof(void*) /* Function calls.  */
    );
}

static const char *
selftest(void)
{
  CAMELLIA_context ctx;
  /* These test vectors are from RFC-3713 */
  const byte plaintext[]=
    {
      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
      0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
  const byte key_128[]=
    {
      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
      0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
  const byte ciphertext_128[]=
    {
      0x67,0x67,0x31,0x38,0x54,0x96,0x69,0x73,
      0x08,0x57,0x06,0x56,0x48,0xea,0xbe,0x43
    };
  const byte key_256[]=
    {
      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,
      0x98,0x76,0x54,0x32,0x10,0x00,0x11,0x22,0x33,0x44,0x55,
      0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
  const byte ciphertext_256[]=
    {
      0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,
      0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09
    };
  byte scratch[sizeof(plaintext)];

  camellia_setkey(&ctx,key_128,sizeof(key_128));
  camellia_encrypt(&ctx,scratch,plaintext);
  if(memcmp(scratch,ciphertext_128,sizeof(scratch))!=0)
    return "CAMELLIA128 test encryption failed.";
  camellia_decrypt(&ctx,scratch,scratch);
  if(memcmp(scratch,plaintext,sizeof(scratch))!=0)
    return "CAMELLIA128 test decryption failed.";

  camellia_setkey(&ctx,key_256,sizeof(key_256));
  camellia_encrypt(&ctx,scratch,plaintext);
  if(memcmp(scratch,ciphertext_256,sizeof(scratch))!=0)
    return "CAMELLIA256 test encryption failed.";
  camellia_decrypt(&ctx,scratch,scratch);
  if(memcmp(scratch,plaintext,sizeof(scratch))!=0)
    return "CAMELLIA256 test decryption failed.";

  return NULL;
}

const char *
camellia_get_info(int algo, size_t *keylen,
		  size_t *blocksize, size_t *contextsize,
		  int (**r_setkey)(void *c, const byte *key, unsigned keylen),
		  void (**r_encrypt)(void *c, byte *outbuf, const byte *inbuf),
		  void (**r_decrypt)(void *c, byte *outbuf, const byte *inbuf)
		  )
{
  *blocksize = CAMELLIA_BLOCK_SIZE;
  *contextsize = sizeof (CAMELLIA_context);

  *r_setkey = camellia_setkey;
  *r_encrypt = camellia_encrypt;
  *r_decrypt = camellia_decrypt;

  if(algo==CIPHER_ALGO_CAMELLIA128)
    {
      *keylen = 128;
      return "CAMELLIA128";
    }
  else if(algo==CIPHER_ALGO_CAMELLIA256)
    {
      *keylen = 256;
      return "CAMELLIA256";
    }
  else
    return NULL;
}
