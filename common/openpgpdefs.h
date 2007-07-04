/* openpgpdefs.h - Constants from the OpenPGP standard (rfc2440)
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006 Free Software Foundation, Inc.
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
    PKT_COMMENT	      = 61, /* new comment packet (GnuPG specific). */
    PKT_GPG_CONTROL   = 63  /* internal control packet (GnuPG specific). */
  } 
pkttype_t;


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
    SIGSUBPKT_PREF_KS	    = 24, /* Preferred key server. */
    SIGSUBPKT_PRIMARY_UID   = 25, /* Primary user id. */
    SIGSUBPKT_POLICY	    = 26, /* Policy URL. */
    SIGSUBPKT_KEY_FLAGS     = 27, /* Key flags. */
    SIGSUBPKT_SIGNERS_UID   = 28, /* Signer's user id. */
    SIGSUBPKT_REVOC_REASON  = 29, /* Reason for revocation. */
    SIGSUBPKT_FEATURES      = 30, /* Feature flags. */
                              
    SIGSUBPKT_SIGNATURE     = 32, /* Embedded signature. */
                              
    SIGSUBPKT_FLAG_CRITICAL = 128
  } 
sigsubpkttype_t;


#endif /*GNUPG_COMMON_OPENPGPDEFS_H*/
