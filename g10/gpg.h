/* gpg.h - top level include file for gpg etc.
 * Copyright (C) 2003, 2006 Free Software Foundation, Inc.
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
#ifndef GNUPG_G10_GPG_H
#define GNUPG_G10_GPG_H

/* Note, that this file should be the first one after the system
   header files.  This is required to set the error source to the
   correct value and may be of advantage if we ever have to do
   special things. */

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_GPG
#define map_assuan_err(a) \
        map_assuan_err_with_source (GPG_ERR_SOURCE_DEFAULT, (a))
#include <gpg-error.h>
#include <gcrypt.h>


/* Number of bits we accept when reading or writing MPIs. */
#define MAX_EXTERN_MPI_BITS 16384

/* The maximum length of a binary fingerprints.  */
#define MAX_FINGERPRINT_LEN 20


/*
   Forward declarations.
 */

/* Object used to keep state locally to server.c . */
struct server_local_s;

/* Object used to describe a keyblok node.  */
typedef struct kbnode_struct *KBNODE;
/* Object used for looking ob keys.  */
typedef struct keydb_search_desc KEYDB_SEARCH_DESC;



/* Session control object.  This object is passed to most functions to
   convey the status of a session.  Note that the defaults are set by
   gpg_init_default_ctrl(). */
struct server_control_s
{
  struct server_local_s *server_local;
};





/*
     Compatibility stuff to be faded out over time.
 */

/* Simple wrappers. */
#define g10_errstr(a)  gpg_strerror ((a))


/* Mapping of the old error codes to the gpg-error ones.  Fixme: This
   is just a temporary solution: We need to do all these gpg_error()
   calls in the code.  */
#define G10ERR_BAD_KEY         GPG_ERR_BAD_KEY
#define G10ERR_BAD_PASS        GPG_ERR_BAD_PASS
#define G10ERR_BAD_PUBKEY      GPG_ERR_BAD_PUBKEY
#define G10ERR_BAD_SIGN        GPG_ERR_BAD_SIGNATURE
#define G10ERR_BAD_URI         GPG_ERR_BAD_URI
#define G10ERR_CHECKSUM        GPG_ERR_CHECKSUM
#define G10ERR_CIPHER_ALGO     GPG_ERR_CIPHER_ALGO
#define G10ERR_CLOSE_FILE      GPG_ERR_CLOSE_FILE
#define G10ERR_COMPR_ALGO      GPG_ERR_COMPR_ALGO
#define G10ERR_CREATE_FILE     GPG_ERR_CREATE_FILE
#define G10ERR_DIGEST_ALGO     GPG_ERR_DIGEST_ALGO
#define G10ERR_FILE_EXISTS     GPG_ERR_EEXIST
#define G10ERR_GENERAL         GPG_ERR_GENERAL
#define G10ERR_INV_ARG         GPG_ERR_INV_ARG
#define G10ERR_INV_KEYRING     GPG_ERR_INV_KEYRING
#define G10ERR_INV_USER_ID     GPG_ERR_INV_USER_ID
#define G10ERR_INVALID_ARMOR   GPG_ERR_INV_ARMOR
#define G10ERR_INVALID_PACKET  GPG_ERR_INV_PACKET
#define G10ERR_KEYRING_OPEN    GPG_ERR_KEYRING_OPEN
#define G10ERR_KEYSERVER       GPG_ERR_KEYSERVER
#define G10ERR_NO_DATA         GPG_ERR_NO_DATA
#define G10ERR_NO_PUBKEY       GPG_ERR_NO_PUBKEY
#define G10ERR_NO_SECKEY       GPG_ERR_NO_SECKEY
#define G10ERR_NO_USER_ID      GPG_ERR_NO_USER_ID
#define G10ERR_NOT_PROCESSED   GPG_ERR_NOT_PROCESSED
#define G10ERR_OPEN_FILE       GPG_ERR_OPEN_FILE
#define G10ERR_PASSPHRASE      GPG_ERR_PASSPHRASE
#define G10ERR_PUBKEY_ALGO     GPG_ERR_PUBKEY_ALGO
#define G10ERR_READ_FILE       GPG_ERR_READ_FILE
#define G10ERR_RENAME_FILE     GPG_ERR_RENAME_FILE
#define G10ERR_RESOURCE_LIMIT  GPG_ERR_RESOURCE_LIMIT
#define G10ERR_SIG_CLASS       GPG_ERR_SIG_CLASS
#define G10ERR_TIME_CONFLICT   GPG_ERR_TIME_CONFLICT
#define G10ERR_TRUSTDB         GPG_ERR_TRUSTDB
#define G10ERR_UNEXPECTED      GPG_ERR_UNEXPECTED
#define G10ERR_UNKNOWN_PACKET  GPG_ERR_UNKNOWN_PACKET
#define G10ERR_UNSUPPORTED     GPG_ERR_NOT_SUPPORTED
#define G10ERR_UNU_PUBKEY      GPG_ERR_UNUSABLE_PUBKEY
#define G10ERR_UNU_SECKEY      GPG_ERR_UNUSABLE_SECKEY
#define G10ERR_WRONG_SECKEY    GPG_ERR_WRONG_SECKEY

#endif /*GNUPG_G10_GPG_H*/
