/* errors.h - erro code
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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
#define G10ERR_BAD_RING       15
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

#endif /*G10_ERRORS_H*/
