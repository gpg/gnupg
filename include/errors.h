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
#ifndef GPG_ERRORS_H
#define GPG_ERRORS_H


/* FIXME: some constants have to be the same as the ones from
 * libgcrypt - include gcrypt.h and use those constants */
#define GPGERR_GENERAL	       101
#define GPGERR_UNKNOWN_PACKET  102
#define GPGERR_UNKNOWN_VERSION 103 /* Unknown version (in packet) */
#define GPGERR_PUBKEY_ALGO	 4 /* Unknown pubkey algorithm */
#define GPGERR_DIGEST_ALGO	 5 /* Unknown digest algorithm */
#define GPGERR_BAD_PUBKEY	 6 /* Bad public key */
#define GPGERR_BAD_SECKEY	 7 /* Bad secret key */
#define GPGERR_BAD_SIGN 	 8 /* Bad signature */
#define GPGERR_NO_PUBKEY       109 /* public key not found */
#define GPGERR_CHECKSUM        110 /* checksum error */
#define GPGERR_BAD_PASS        111 /* Bad passphrase */
#define GPGERR_CIPHER_ALGO	12 /* Unknown cipher algorithm */
#define GPGERR_KEYRING_OPEN    113
#define GPGERR_INVALID_PACKET  114
#define GPGERR_INVALID_ARMOR   115
#define GPGERR_NO_USER_ID      116
#define GPGERR_NO_SECKEY       117 /* secret key not available */
#define GPGERR_WRONG_SECKEY    118 /* wrong seckey used */
#define GPGERR_UNSUPPORTED     119
#define GPGERR_BAD_KEY	       120 /* bad (session) key */
#define GPGERR_READ_FILE       121
#define GPGERR_WRITE_FILE      122
#define GPGERR_COMPR_ALGO      123 /* Unknown compress algorithm */
#define GPGERR_OPEN_FILE       124
#define GPGERR_CREATE_FILE     125
#define GPGERR_PASSPHRASE      126 /* invalid passphrase */
#define GPGERR_NI_PUBKEY       127
#define GPGERR_NI_CIPHER       128
#define GPGERR_SIG_CLASS       129
#define GPGERR_BAD_MPI		30
#define GPGERR_RESOURCE_LIMIT  131
#define GPGERR_INV_KEYRING     132
#define GPGERR_TRUSTDB	       133 /* a problem with the trustdb */
#define GPGERR_BAD_CERT        134 /* bad certicate */
#define GPGERR_INV_USER_ID     135
#define GPGERR_CLOSE_FILE      136
#define GPGERR_RENAME_FILE     137
#define GPGERR_DELETE_FILE     138
#define GPGERR_UNEXPECTED      139
#define GPGERR_TIME_CONFLICT   140
#define GPGERR_WR_PUBKEY_ALGO	41 /* unusabe pubkey algo */
#define GPGERR_FILE_EXISTS     142
#define GPGERR_WEAK_KEY 	43 /* NOTE: hardcoded into the cipher modules */
#define GPGERR_WRONG_KEYLEN	44 /* NOTE: hardcoded into the cipher modules */
#define GPGERR_INV_ARG	       145
#define GPGERR_BAD_URI	       146  /* syntax error in URI */
#define GPGERR_INVALID_URI     147  /* e.g. unsupported scheme */
#define GPGERR_NETWORK	       148  /* general network error */
#define GPGERR_UNKNOWN_HOST    149
#define GPGERR_SELFTEST_FAILED	50
#define GPGERR_NOT_ENCRYPTED   151

#ifndef HAVE_STRERROR
char *strerror( int n );
#endif

#endif /*GPG_ERRORS_H*/
