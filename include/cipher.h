/* cipher.h - Definitions for OpenPGP
 * Copyright (C) 1998, 1999, 2000, 2001, 2006,
 *               2007  Free Software Foundation, Inc.
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
#ifndef G10_CIPHER_H
#define G10_CIPHER_H

#include <gcrypt.h>

/* Macros for compatibility with older libgcrypt versions. */
#ifndef GCRY_PK_USAGE_CERT
# define GCRY_PK_USAGE_CERT 4
# define GCRY_PK_USAGE_AUTH 8
# define GCRY_PK_USAGE_UNKN 128
#endif


/* Constants for OpenPGP. */

#define CIPHER_ALGO_NONE	 /*  0 */  GCRY_CIPHER_NONE
#define CIPHER_ALGO_IDEA	 /*  1 */  GCRY_CIPHER_IDEA
#define CIPHER_ALGO_3DES	 /*  2 */  GCRY_CIPHER_3DES
#define CIPHER_ALGO_CAST5	 /*  3 */  GCRY_CIPHER_CAST5
#define CIPHER_ALGO_BLOWFISH	 /*  4 */  GCRY_CIPHER_BLOWFISH /* 128 bit */
/* 5 & 6 are reserved */
#define CIPHER_ALGO_AES          /*  7 */  GCRY_CIPHER_AES
#define CIPHER_ALGO_AES192       /*  8 */  GCRY_CIPHER_AES192
#define CIPHER_ALGO_AES256       /*  9 */  GCRY_CIPHER_AES256
#define CIPHER_ALGO_RIJNDAEL     CIPHER_ALGO_AES
#define CIPHER_ALGO_RIJNDAEL192  CIPHER_ALGO_AES192
#define CIPHER_ALGO_RIJNDAEL256  CIPHER_ALGO_AES256
#define CIPHER_ALGO_TWOFISH	 /* 10 */  GCRY_CIPHER_TWOFISH  /* 256 bit */
/* Note: Camellia ids don't match those used by libgcrypt. */
#define CIPHER_ALGO_CAMELLIA128     11
#define CIPHER_ALGO_CAMELLIA192     12
#define CIPHER_ALGO_CAMELLIA256     13
#define CIPHER_ALGO_DUMMY          110    /* No encryption at all. */

#define PUBKEY_ALGO_RSA          /*  1 */ GCRY_PK_RSA
#define PUBKEY_ALGO_RSA_E        /*  2 */ GCRY_PK_RSA_E /* RSA encrypt only. */
#define PUBKEY_ALGO_RSA_S        /*  3 */ GCRY_PK_RSA_S /* RSA sign only.    */
#define PUBKEY_ALGO_ELGAMAL_E    /* 16 */ GCRY_PK_ELG_E /* Elgamal encr only */
#define PUBKEY_ALGO_DSA          /* 17 */ GCRY_PK_DSA
#define PUBKEY_ALGO_ECDH            18
#define PUBKEY_ALGO_ECDSA           19
#define PUBKEY_ALGO_ELGAMAL      /* 20 */ GCRY_PK_ELG   /* Elgamal encr+sign */

#define PUBKEY_USAGE_SIG     GCRY_PK_USAGE_SIGN  /* Good for signatures. */
#define PUBKEY_USAGE_ENC     GCRY_PK_USAGE_ENCR  /* Good for encryption. */
#define PUBKEY_USAGE_CERT    GCRY_PK_USAGE_CERT  /* Also good to certify keys. */
#define PUBKEY_USAGE_AUTH    GCRY_PK_USAGE_AUTH  /* Good for authentication. */
#define PUBKEY_USAGE_UNKNOWN GCRY_PK_USAGE_UNKN  /* Unknown usage flag. */

#define DIGEST_ALGO_MD5       /*  1 */ GCRY_MD_MD5
#define DIGEST_ALGO_SHA1      /*  2 */ GCRY_MD_SHA1
#define DIGEST_ALGO_RMD160    /*  3 */ GCRY_MD_RMD160
/* 4, 5, 6, and 7 are reserved */
#define DIGEST_ALGO_SHA256    /*  8 */ GCRY_MD_SHA256
#define DIGEST_ALGO_SHA384    /*  9 */ GCRY_MD_SHA384
#define DIGEST_ALGO_SHA512    /* 10 */ GCRY_MD_SHA512
/* SHA224 is only available in libgcrypt 1.4.0; thus we
   can't use the GCRY macro here.  */
#define DIGEST_ALGO_SHA224    /* 11 */ 11 /* GCRY_MD_SHA224 */

#define COMPRESS_ALGO_NONE 0
#define COMPRESS_ALGO_ZIP  1
#define COMPRESS_ALGO_ZLIB 2
#define COMPRESS_ALGO_BZIP2  3

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL_E)
#define is_DSA(a)     ((a)==PUBKEY_ALGO_DSA)

/* The data encryption key object. */
typedef struct
{
  int algo;
  int keylen;
  int algo_info_printed;
  int use_mdc;
  int symmetric;
  byte key[32]; /* This is the largest used keylen (256 bit). */
  char s2k_cacheid[1+16+1];
} DEK;



/* Constants to allocate static MPI arrays. */
#define PUBKEY_MAX_NPKEY  4
#define PUBKEY_MAX_NSKEY  6
#define PUBKEY_MAX_NSIG   2
#define PUBKEY_MAX_NENC   2

#endif /*G10_CIPHER_H*/
