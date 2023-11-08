/* openpgpdefs.h - Constants from the OpenPGP standard (rfc2440)
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_OPENPGPDEFS_H
#define GNUPG_COMMON_OPENPGPDEFS_H

typedef enum
  {
    PKT_NONE	      = 0,
    PKT_PUBKEY_ENC    = 1,  /* Public key encrypted packet. */
    PKT_SIGNATURE     = 2,  /* Secret key encrypted packet. */
    PKT_SYMKEY_ENC    = 3,  /* Session key packet. */
    PKT_ONEPASS_SIG   = 4,  /* One pass sig packet. */
    PKT_SECRET_KEY    = 5,  /* Secret key. */
    PKT_PUBLIC_KEY    = 6,  /* Public key. */
    PKT_SECRET_SUBKEY = 7,  /* Secret subkey. */
    PKT_COMPRESSED    = 8,  /* Compressed data packet. */
    PKT_ENCRYPTED     = 9,  /* Conventional encrypted data. */
    PKT_MARKER	      = 10, /* Marker packet. */
    PKT_PLAINTEXT     = 11, /* Literal data packet. */
    PKT_RING_TRUST    = 12, /* Keyring trust packet. */
    PKT_USER_ID	      = 13, /* User id packet. */
    PKT_PUBLIC_SUBKEY = 14, /* Public subkey. */
    PKT_OLD_COMMENT   = 16, /* Comment packet from an OpenPGP draft. */
    PKT_ATTRIBUTE     = 17, /* PGP's attribute packet. */
    PKT_ENCRYPTED_MDC = 18, /* Integrity protected encrypted data. */
    PKT_MDC 	      = 19, /* Manipulation detection code packet. */
    PKT_ENCRYPTED_AEAD= 20, /* AEAD encrypted data packet. */
    PKT_COMMENT	      = 61, /* new comment packet (GnuPG specific). */
    PKT_GPG_CONTROL   = 63  /* internal control packet (GnuPG specific). */
  }
pkttype_t;

static inline const char *
pkttype_str (pkttype_t type)
{
  switch (type)
    {
    case PKT_PUBKEY_ENC: return "PUBKEY_ENC";
    case PKT_SIGNATURE: return "SIGNATURE";
    case PKT_SYMKEY_ENC: return "SYMKEY_ENC";
    case PKT_ONEPASS_SIG: return "ONEPASS_SIG";
    case PKT_SECRET_KEY: return "SECRET_KEY";
    case PKT_PUBLIC_KEY: return "PUBLIC_KEY";
    case PKT_SECRET_SUBKEY: return "SECRET_SUBKEY";
    case PKT_COMPRESSED: return "COMPRESSED";
    case PKT_ENCRYPTED: return "ENCRYPTED";
    case PKT_MARKER: return "MARKER";
    case PKT_PLAINTEXT: return "PLAINTEXT";
    case PKT_RING_TRUST: return "RING_TRUST";
    case PKT_USER_ID: return "USER_ID";
    case PKT_PUBLIC_SUBKEY: return "PUBLIC_SUBKEY";
    case PKT_OLD_COMMENT: return "OLD_COMMENT";
    case PKT_ATTRIBUTE: return "ATTRIBUTE";
    case PKT_ENCRYPTED_MDC: return "ENCRYPTED_MDC";
    case PKT_MDC: return "MDC";
    case PKT_COMMENT: return "COMMENT";
    case PKT_GPG_CONTROL: return "GPG_CONTROL";
    default: return "unknown packet type";
    }
}

typedef enum
  {
    SIGSUBPKT_TEST_CRITICAL = -3,
    SIGSUBPKT_LIST_UNHASHED = -2,
    SIGSUBPKT_LIST_HASHED   = -1,
    SIGSUBPKT_NONE	    =  0,
    SIGSUBPKT_SIG_CREATED   =  2, /* Signature creation time. */
    SIGSUBPKT_SIG_EXPIRE    =  3, /* Signature expiration time. */
    SIGSUBPKT_EXPORTABLE    =  4, /* Exportable. */
    SIGSUBPKT_TRUST	    =  5, /* Trust signature. */
    SIGSUBPKT_REGEXP	    =  6, /* Regular expression. */
    SIGSUBPKT_REVOCABLE     =  7, /* Revocable. */
    SIGSUBPKT_KEY_EXPIRE    =  9, /* Key expiration time. */
    SIGSUBPKT_ARR	    = 10, /* Additional recipient request. */
    SIGSUBPKT_PREF_SYM	    = 11, /* Preferred symmetric algorithms. */
    SIGSUBPKT_REV_KEY	    = 12, /* Revocation key. */
    SIGSUBPKT_ISSUER	    = 16, /* Issuer key ID. */
    SIGSUBPKT_NOTATION	    = 20, /* Notation data. */
    SIGSUBPKT_PREF_HASH     = 21, /* Preferred hash algorithms. */
    SIGSUBPKT_PREF_COMPR    = 22, /* Preferred compression algorithms. */
    SIGSUBPKT_KS_FLAGS	    = 23, /* Key server preferences. */
    SIGSUBPKT_PREF_KS	    = 24, /* Preferred keyserver. */
    SIGSUBPKT_PRIMARY_UID   = 25, /* Primary user id. */
    SIGSUBPKT_POLICY	    = 26, /* Policy URL. */
    SIGSUBPKT_KEY_FLAGS     = 27, /* Key flags. */
    SIGSUBPKT_SIGNERS_UID   = 28, /* Signer's user id. */
    SIGSUBPKT_REVOC_REASON  = 29, /* Reason for revocation. */
    SIGSUBPKT_FEATURES      = 30, /* Feature flags. */

    SIGSUBPKT_SIGNATURE     = 32, /* Embedded signature. */
    SIGSUBPKT_ISSUER_FPR    = 33, /* Issuer fingerprint. */
    SIGSUBPKT_PREF_AEAD     = 34, /* Preferred AEAD algorithms. */

    SIGSUBPKT_ATTST_SIGS    = 37, /* Attested Certifications.  */
    SIGSUBPKT_KEY_BLOCK     = 38, /* Entire key used.          */

    SIGSUBPKT_META_HASH     = 40, /* Literal Data Meta Hash.   */
    SIGSUBPKT_TRUST_ALIAS   = 41, /* Trust Alias.              */

    SIGSUBPKT_FLAG_CRITICAL = 128
  }
sigsubpkttype_t;


typedef enum
  {
    CIPHER_ALGO_NONE	    =  0,
    CIPHER_ALGO_IDEA	    =  1,
    CIPHER_ALGO_3DES	    =  2,
    CIPHER_ALGO_CAST5	    =  3,
    CIPHER_ALGO_BLOWFISH    =  4, /* 128 bit */
    /* 5 & 6 are reserved */
    CIPHER_ALGO_AES         =  7,
    CIPHER_ALGO_AES192      =  8,
    CIPHER_ALGO_AES256      =  9,
    CIPHER_ALGO_TWOFISH	    = 10, /* 256 bit */
    CIPHER_ALGO_CAMELLIA128 = 11,
    CIPHER_ALGO_CAMELLIA192 = 12,
    CIPHER_ALGO_CAMELLIA256 = 13,
    CIPHER_ALGO_PRIVATE10   = 110
  }
cipher_algo_t;


/* Note that we encode the AEAD algo in a 3 bit field at some places.  */
typedef enum
  {
    AEAD_ALGO_NONE	    =  0,
    AEAD_ALGO_EAX	    =  1,
    AEAD_ALGO_OCB	    =  2
  }
aead_algo_t;


typedef enum
  {
    PUBKEY_ALGO_RSA         =  1,
    PUBKEY_ALGO_RSA_E       =  2, /* RSA encrypt only (legacy). */
    PUBKEY_ALGO_RSA_S       =  3, /* RSA sign only (legacy).    */
    PUBKEY_ALGO_ELGAMAL_E   = 16, /* Elgamal encrypt only.      */
    PUBKEY_ALGO_DSA         = 17,
    PUBKEY_ALGO_ECDH        = 18, /* RFC-6637  */
    PUBKEY_ALGO_ECDSA       = 19, /* RFC-6637  */
    PUBKEY_ALGO_ELGAMAL     = 20, /* Elgamal encrypt+sign (legacy).  */
    /*                        21     reserved by OpenPGP.            */
    PUBKEY_ALGO_EDDSA       = 22, /* EdDSA (not yet assigned).       */
    PUBKEY_ALGO_PRIVATE10   = 110
  }
pubkey_algo_t;


typedef enum
  {
    DIGEST_ALGO_MD5         =  1,
    DIGEST_ALGO_SHA1        =  2,
    DIGEST_ALGO_RMD160      =  3,
    /* 4, 5, 6, and 7 are reserved. */
    DIGEST_ALGO_SHA256      =  8,
    DIGEST_ALGO_SHA384      =  9,
    DIGEST_ALGO_SHA512      = 10,
    DIGEST_ALGO_SHA224      = 11,
    DIGEST_ALGO_PRIVATE10   = 110
  }
digest_algo_t;


typedef enum
  {
    COMPRESS_ALGO_NONE      =  0,
    COMPRESS_ALGO_ZIP       =  1,
    COMPRESS_ALGO_ZLIB      =  2,
    COMPRESS_ALGO_BZIP2     =  3,
    COMPRESS_ALGO_PRIVATE10 = 110
  }
compress_algo_t;

/* Limits to be used for static arrays.  */
#define OPENPGP_MAX_NPKEY  5  /* Maximum number of public key parameters. */
#define OPENPGP_MAX_NSKEY  7  /* Maximum number of secret key parameters. */
#define OPENPGP_MAX_NSIG   2  /* Maximum number of signature parameters.  */
#define OPENPGP_MAX_NENC   2  /* Maximum number of encryption parameters. */


/* Decode an rfc4880 encoded S2K count.  */
#define S2K_DECODE_COUNT(_val) ((16ul + ((_val) & 15)) << (((_val) >> 4) + 6))


/*-- openpgp-s2k.c --*/
unsigned char encode_s2k_iterations (int iterations);

/*-- openpgp-fpr.c --*/
gpg_error_t compute_openpgp_fpr (int keyversion, int pgpalgo,
                                 unsigned long timestamp,
                                 gcry_buffer_t *iov, int iovcnt,
                                 unsigned char *result,
                                 unsigned int *r_resultlen);
gpg_error_t compute_openpgp_fpr_rsa (int keyversion,
                                     unsigned long timestamp,
                                     const unsigned char *m, unsigned int mlen,
                                     const unsigned char *e, unsigned int elen,
                                     unsigned char *result,
                                     unsigned int *r_resultlen);
gpg_error_t compute_openpgp_fpr_ecc (int keyversion,
                                     unsigned long timestamp,
                                     const char *curvename, int for_encryption,
                                     const unsigned char *q, unsigned int qlen,
                                     const unsigned char *kdf,
                                     unsigned int kdflen,
                                     unsigned char *result,
                                     unsigned int *r_resultlen);

/*-- openpgp-oid.c --*/
pubkey_algo_t map_gcry_pk_to_openpgp (enum gcry_pk_algos algo);
enum gcry_pk_algos map_openpgp_pk_to_gcry (pubkey_algo_t algo);



#endif /*GNUPG_COMMON_OPENPGPDEFS_H*/
