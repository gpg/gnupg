/* cipher.h
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#ifndef G10_CIPHER_H
#define G10_CIPHER_H

#define DBG_CIPHER g10c_debug_mode

#include <gcrypt.h>

#define CIPHER_ALGO_NONE	 GCRY_CIPHER_NONE
#define CIPHER_ALGO_IDEA	 GCRY_CIPHER_IDEA
#define CIPHER_ALGO_3DES	 GCRY_CIPHER_3DES
#define CIPHER_ALGO_CAST5	 GCRY_CIPHER_CAST5
#define CIPHER_ALGO_BLOWFISH	 GCRY_CIPHER_BLOWFISH /* 128 bit */
#define CIPHER_ALGO_SAFER_SK128  GCRY_CIPHER_SK128
#define CIPHER_ALGO_DES_SK	 GCRY_CIPHER_DES_SK
#define CIPHER_ALGO_AES          GCRY_CIPHER_AES
#define CIPHER_ALGO_AES192       GCRY_CIPHER_AES192
#define CIPHER_ALGO_AES256       GCRY_CIPHER_AES256
#define CIPHER_ALGO_RIJNDAEL     CIPHER_ALGO_AES
#define CIPHER_ALGO_RIJNDAEL192  CIPHER_ALGO_AES192
#define CIPHER_ALGO_RIJNDAEL256  CIPHER_ALGO_AES256
#define CIPHER_ALGO_TWOFISH	 GCRY_CIPHER_TWOFISH  /* 256 bit */
#define CIPHER_ALGO_DUMMY      110  /* no encryption at all */

#define PUBKEY_ALGO_RSA        GCRY_PK_RSA
#define PUBKEY_ALGO_RSA_E      GCRY_PK_RSA_E
#define PUBKEY_ALGO_RSA_S      GCRY_PK_RSA_S
#define PUBKEY_ALGO_ELGAMAL_E  GCRY_PK_ELG_E 
#define PUBKEY_ALGO_DSA        GCRY_PK_DSA
#define PUBKEY_ALGO_ELGAMAL    GCRY_PK_ELG

#define PUBKEY_USAGE_SIG     GCRY_PK_USAGE_SIGN	 
#define PUBKEY_USAGE_ENC     GCRY_PK_USAGE_ENCR
#define PUBKEY_USAGE_CERT    4      /* key is also good to certify other keys*/

#define DIGEST_ALGO_MD5       GCRY_MD_MD5
#define DIGEST_ALGO_SHA1      GCRY_MD_SHA1
#define DIGEST_ALGO_RMD160    GCRY_MD_RMD160
#define DIGEST_ALGO_TIGER     GCRY_MD_TIGER
#define DIGEST_ALGO_SHA256    GCRY_MD_SHA256
#define DIGEST_ALGO_SHA384    GCRY_MD_SHA384
#define DIGEST_ALGO_SHA512    GCRY_MD_SHA512

#define COMPRESS_ALGO_NONE 0
#define COMPRESS_ALGO_ZIP  1
#define COMPRESS_ALGO_ZLIB 2

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)

typedef struct {
    int algo;
    int keylen;
    int algo_info_printed;
    int use_mdc;
    byte key[32]; /* this is the largest used keylen (256 bit) */
} DEK;


#ifndef EXTERN_UNLESS_MAIN_MODULE
#if defined (__riscos__) && !defined (INCLUDED_BY_MAIN_MODULE)
#define EXTERN_UNLESS_MAIN_MODULE extern
#else
#define EXTERN_UNLESS_MAIN_MODULE 
#endif
#endif
EXTERN_UNLESS_MAIN_MODULE int g10c_debug_mode;
EXTERN_UNLESS_MAIN_MODULE int g10_opt_verbose;
EXTERN_UNLESS_MAIN_MODULE const char *g10_opt_homedir;



#define PUBKEY_MAX_NPKEY  4
#define PUBKEY_MAX_NSKEY  6
#define PUBKEY_MAX_NSIG   2
#define PUBKEY_MAX_NENC   2

#define MD_HANDLE gcry_md_hd_t
#define CIPHER_HANDLE gcry_cipher_hd_t

#endif /*G10_CIPHER_H*/
