/* errors.h - erro code
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
#ifndef G10_ERRORS_H
#define G10_ERRORS_H


/* FIXME: some constants have to be the same as the ones from
 * libgcrypt - include gcrypt.h and use those constants */
#define G10ERR_GENERAL	       101
#define G10ERR_UNKNOWN_PACKET  102
#define G10ERR_UNKNOWN_VERSION 103 /* Unknown version (in packet) */
#define G10ERR_PUBKEY_ALGO	 4 /* Unknown pubkey algorithm */
#define G10ERR_DIGEST_ALGO	 5 /* Unknown digest algorithm */
#define G10ERR_BAD_PUBKEY	 6 /* Bad public key */
#define G10ERR_BAD_SECKEY	 7 /* Bad secret key */
#define G10ERR_BAD_SIGN 	 8 /* Bad signature */
#define G10ERR_NO_PUBKEY       109 /* public key not found */
#define G10ERR_CHECKSUM        110 /* checksum error */
#define G10ERR_BAD_PASS        111 /* Bad passphrase */
#define G10ERR_CIPHER_ALGO	12 /* Unknown cipher algorithm */
#define G10ERR_KEYRING_OPEN    113
#define G10ERR_INVALID_PACKET  114
#define G10ERR_INVALID_ARMOR   115
#define G10ERR_NO_USER_ID      116
#define G10ERR_NO_SECKEY       117 /* secret key not available */
#define G10ERR_WRONG_SECKEY    118 /* wrong seckey used */
#define G10ERR_UNSUPPORTED     119
#define G10ERR_BAD_KEY	       120 /* bad (session) key */
#define G10ERR_READ_FILE       121
#define G10ERR_WRITE_FILE      122
#define G10ERR_COMPR_ALGO      123 /* Unknown compress algorithm */
#define G10ERR_OPEN_FILE       124
#define G10ERR_CREATE_FILE     125
#define G10ERR_PASSPHRASE      126 /* invalid passphrase */
#define G10ERR_NI_PUBKEY       127
#define G10ERR_NI_CIPHER       128
#define G10ERR_SIG_CLASS       129
#define G10ERR_BAD_MPI		30
#define G10ERR_RESOURCE_LIMIT  131
#define G10ERR_INV_KEYRING     132
#define G10ERR_TRUSTDB	       133 /* a problem with the trustdb */
#define G10ERR_BAD_CERT        134 /* bad certicate */
#define G10ERR_INV_USER_ID     135
#define G10ERR_CLOSE_FILE      136
#define G10ERR_RENAME_FILE     137
#define G10ERR_DELETE_FILE     138
#define G10ERR_UNEXPECTED      139
#define G10ERR_TIME_CONFLICT   140
#define G10ERR_WR_PUBKEY_ALGO	41 /* unusabe pubkey algo */
#define G10ERR_FILE_EXISTS     142
#define G10ERR_WEAK_KEY 	43 /* NOTE: hardcoded into the cipher modules */
#define G10ERR_WRONG_KEYLEN	44 /* NOTE: hardcoded into the cipher modules */
#define G10ERR_INV_ARG	       145
#define G10ERR_BAD_URI	       146  /* syntax error in URI */
#define G10ERR_INVALID_URI     147  /* e.g. unsupported scheme */
#define G10ERR_NETWORK	       148  /* general network error */
#define G10ERR_UNKNOWN_HOST    149
#define G10ERR_SELFTEST_FAILED	50
#define G10ERR_NOT_ENCRYPTED   151

#ifndef HAVE_STRERROR
char *strerror( int n );
#endif

#endif /*G10_ERRORS_H*/
