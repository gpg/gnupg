/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 30/06/2004

 This file contains the definitions required to use AES in C. See aesopt.h
 for optimisation details.
*/

#ifndef _AES_H
#define _AES_H

/*  This include is used to find 8 & 32 bit unsigned integer types  */
#include "limits.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define AES_128     /* define if AES with 128 bit keys is needed    */
#define AES_192     /* define if AES with 192 bit keys is needed    */
#define AES_256     /* define if AES with 256 bit keys is needed    */
#define AES_VAR     /* define if a variable key size is needed      */
#define AES_MODES   /* define if support is needed for modes        */

/* The following must also be set in assembler files if being used  */

#define AES_ENCRYPT /* if support for encryption is needed          */
#define AES_DECRYPT /* if support for decryption is needed          */
#define AES_ERR_CHK /* for parameter checks & error return codes    */
#define AES_REV_DKS /* define to reverse decryption key schedule    */

#if UCHAR_MAX == 0xff                   /* an unsigned 8 bit type   */
  typedef unsigned char      aes_08t;
#else
# error Please define aes_08t as an 8-bit unsigned integer type in aes.h
#endif

#if UINT_MAX == 4294967295              /* an unsigned 32 bit type  */
  typedef   unsigned int     aes_32t;
#elif ULONG_MAX == 4294967295ul
  typedef   unsigned long    aes_32t;
#else
# error Please define aes_32t as a 32-bit unsigned integer type in aes.h
#endif

#define AES_BLOCK_SIZE  16  /* the AES block size in bytes          */
#define N_COLS           4  /* the number of columns in the state   */

/* The key schedule length is 11, 13 or 15 16-byte blocks for 128,  */
/* 192 or 256-bit keys respectively. That is 176, 208 or 240 bytes  */
/* or 44, 52 or 60 32-bit words. For simplicity this code allocates */
/* the maximum 60 word array for the key schedule for all key sizes */

#if defined( AES_VAR ) || defined( AES_256 )
#define KS_LENGTH       60
#elif defined( AES_192 )
#define KS_LENGTH       52
#else
#define KS_LENGTH       44
#endif

#if defined( AES_ERR_CHK )
#define aes_ret     int
#define aes_good    0
#define aes_error  -1
#else
#define aes_ret     void
#endif

#if !defined( AES_DLL )     /* implement normal or DLL functions   */
#define aes_rval    aes_ret
#else
#define aes_rval    aes_ret __declspec(dllexport) _stdcall
#endif

/* the character array 'inf' in the following structures is used    */
/* to hold AES context information. This AES code uses cx->inf.b[0] */
/* to hold the number of rounds multiplied by 16. The other three   */
/* elements can be used by code that implements additional modes    */

typedef union
{   aes_32t l;
    aes_08t b[4];
} aes_inf;

typedef struct
{   aes_32t ks[KS_LENGTH];
    aes_inf inf;
} aes_encrypt_ctx;

typedef struct
{   aes_32t ks[KS_LENGTH];
    aes_inf inf;
} aes_decrypt_ctx;

/* This routine must be called before first use if non-static       */
/* tables are being used                                            */

aes_rval gen_tabs(void);

/* The key length (klen) is input in bytes when it is in the range  */
/* 16 <= klen <= 32 or in bits when in the range 128 <= klen <= 256 */

#if defined( AES_ENCRYPT )

#if defined(AES_128) || defined(AES_VAR)
aes_rval aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
aes_rval aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
aes_rval aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
aes_rval aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1]);
#endif

aes_rval aes_encrypt(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1]);

#endif

#if defined( AES_DECRYPT )

#if defined(AES_128) || defined(AES_VAR)
aes_rval aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
aes_rval aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
aes_rval aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
aes_rval aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1]);
#endif

aes_rval aes_decrypt(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1]);

#endif

#if defined(AES_MODES)

aes_rval aes_ecb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_encrypt_ctx cx[1]);

aes_rval aes_ecb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_decrypt_ctx cx[1]);

aes_rval aes_cbc_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, const aes_encrypt_ctx cx[1]);

aes_rval aes_cbc_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, const aes_decrypt_ctx cx[1]);

aes_rval aes_mode_reset(aes_encrypt_ctx cx[1]);

aes_rval aes_cfb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, aes_encrypt_ctx cx[1]);

aes_rval aes_cfb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, aes_encrypt_ctx cx[1]);

#define aes_ofb_encrypt aes_ofb_crypt
#define aes_ofb_decrypt aes_ofb_crypt

aes_rval aes_ofb_crypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, aes_encrypt_ctx cx[1]);

typedef void cbuf_inc(unsigned char *cbuf);

#define aes_ctr_encrypt aes_ctr_crypt
#define aes_ctr_decrypt aes_ctr_crypt

aes_rval aes_ctr_crypt(const unsigned char *ibuf, unsigned char *obuf,
            int len, unsigned char *cbuf, cbuf_inc ctr_inc, aes_encrypt_ctx cx[1]);

#endif

#if defined(__cplusplus)
}
#endif

#endif
