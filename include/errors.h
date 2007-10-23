/* errors.h - erro code
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#ifndef G10_ERRORS_H
#define G10_ERRORS_H

#define G10ERR_GENERAL	       1
#define G10ERR_UNKNOWN_PACKET  2
#define G10ERR_UNKNOWN_VERSION 3 /* Unknown version (in packet) */
#define G10ERR_PUBKEY_ALGO     4 /* Unknown pubkey algorithm */
#define G10ERR_DIGEST_ALGO     5 /* Unknown digest algorithm */
#define G10ERR_BAD_PUBKEY      6 /* Bad public key */
#define G10ERR_BAD_SECKEY      7 /* Bad secret key */
#define G10ERR_BAD_SIGN        8 /* Bad signature */
#define G10ERR_NO_PUBKEY       9 /* public key not found */
#define G10ERR_CHECKSUM       10 /* checksum error */
#define G10ERR_BAD_PASS       11 /* Bad passphrase */
#define G10ERR_CIPHER_ALGO    12 /* Unknown cipher algorithm */
#define G10ERR_KEYRING_OPEN   13
#define G10ERR_INVALID_PACKET 14
#define G10ERR_INVALID_ARMOR  15
#define G10ERR_NO_USER_ID     16
#define G10ERR_NO_SECKEY      17 /* secret key not available */
#define G10ERR_WRONG_SECKEY   18 /* wrong seckey used */
#define G10ERR_UNSUPPORTED    19
#define G10ERR_BAD_KEY	      20 /* bad (session) key */
#define G10ERR_READ_FILE      21
#define G10ERR_WRITE_FILE     22
#define G10ERR_COMPR_ALGO     23 /* Unknown compress algorithm */
#define G10ERR_OPEN_FILE      24
#define G10ERR_CREATE_FILE    25
#define G10ERR_PASSPHRASE     26 /* invalid passphrase */
#define G10ERR_NI_PUBKEY      27
#define G10ERR_NI_CIPHER      28
#define G10ERR_SIG_CLASS      29
#define G10ERR_BAD_MPI	      30
#define G10ERR_RESOURCE_LIMIT 31
#define G10ERR_INV_KEYRING    32
#define G10ERR_TRUSTDB	      33 /* a problem with the trustdb */
#define G10ERR_BAD_CERT       34 /* bad certicate */
#define G10ERR_INV_USER_ID    35
#define G10ERR_CLOSE_FILE     36
#define G10ERR_RENAME_FILE    37
#define G10ERR_DELETE_FILE    38
#define G10ERR_UNEXPECTED     39
#define G10ERR_TIME_CONFLICT  40
#define G10ERR_WR_PUBKEY_ALGO 41 /* unusabe pubkey algo */
#define G10ERR_FILE_EXISTS    42
#define G10ERR_WEAK_KEY       43 /* NOTE: hardcoded into the cipher modules */
#define G10ERR_WRONG_KEYLEN   44 /* NOTE: hardcoded into the cipher modules */
#define G10ERR_INV_ARG	      45
#define G10ERR_BAD_URI	      46  /* syntax error in URI */
#define G10ERR_INVALID_URI    47  /* e.g. unsupported scheme */
#define G10ERR_NETWORK	      48  /* general network error */
#define G10ERR_UNKNOWN_HOST   49
#define G10ERR_SELFTEST_FAILED 50
#define G10ERR_NOT_ENCRYPTED  51
#define G10ERR_NOT_PROCESSED  52
#define G10ERR_UNU_PUBKEY     53
#define G10ERR_UNU_SECKEY     54
#define G10ERR_KEYSERVER      55
#define G10ERR_CANCELED       56
#define G10ERR_NO_CARD        57
#define G10ERR_NO_DATA        58

#ifndef HAVE_STRERROR
char *strerror (int n);
#endif

#ifdef _WIN32
const char * w32_strerror (int w32_errno);
#endif

#endif /*G10_ERRORS_H*/
