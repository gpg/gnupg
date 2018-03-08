/* gpg.h - top level include file for gpg etc.
 * Copyright (C) 2003, 2006, 2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_G10_GPG_H
#define GNUPG_G10_GPG_H

/* Note, that this file should be the first one after the system
   header files.  This is required to set the error source to the
   correct value and may be of advantage if we ever have to do
   special things. */

#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN 1
#endif

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

/* The maximum length of a binary fingerprints.  This is used to
   provide a static buffer and will be increased if we need to support
   longer fingerprints.
   Warning: At some places we still use 20 instead of this macro. */
#define MAX_FINGERPRINT_LEN 20

/* The maximum length of a formatted fingerprint as returned by
   format_hexfingerprint().  */
#define MAX_FORMATTED_FINGERPRINT_LEN 50


/*
   Forward declarations.
 */

/* Object used to keep state locally to server.c . */
struct server_local_s;

/* Object used to keep state locally to call-dirmngr.c .  */
struct dirmngr_local_s;
typedef struct dirmngr_local_s *dirmngr_local_t;

/* Object used to describe a keyblock node.  */
typedef struct kbnode_struct *KBNODE;   /* Deprecated use kbnode_t. */
typedef struct kbnode_struct *kbnode_t;

/* The handle for keydb operations.  */
typedef struct keydb_handle *KEYDB_HANDLE;

/* TOFU database meta object.  */
struct tofu_dbs_s;
typedef struct tofu_dbs_s *tofu_dbs_t;


#if SIZEOF_UNSIGNED_LONG == 8
# define SERVER_CONTROL_MAGIC 0x53616c696e676572
#else
# define SERVER_CONTROL_MAGIC 0x53616c69
#endif

/* Session control object.  This object is passed to most functions to
   convey the status of a session.  Note that the defaults are set by
   gpg_init_default_ctrl(). */
struct server_control_s
{
  /* Always has the value SERVER_CONTROL_MAGIC.  */
  unsigned long magic;

  /* Local data for server.c  */
  struct server_local_s *server_local;

  /* Local data for call-dirmngr.c  */
  dirmngr_local_t dirmngr_local;

  /* Local data for tofu.c  */
  struct {
    tofu_dbs_t dbs;
    int batch_updated_wanted;
  } tofu;

  /* This is used to cache a key data base handle.  */
  KEYDB_HANDLE cached_getkey_kdb;
};



#endif /*GNUPG_G10_GPG_H*/
