/* keybox.h - Keybox operations
 * Copyright (C) 2001, 2003, 2012 Free Software Foundation, Inc.
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

#ifndef KEYBOX_H
#define KEYBOX_H 1
#ifdef __cplusplus
extern "C" {
#if 0
 }
#endif
#endif

#include "../common/iobuf.h"
#include "keybox-search-desc.h"

#ifdef KEYBOX_WITH_X509
# include <ksba.h>
#endif

typedef struct keybox_handle *KEYBOX_HANDLE;


typedef enum
  {
    KEYBOX_FLAG_BLOB,       /* The blob flags. */
    KEYBOX_FLAG_VALIDITY,   /* The validity of the entire key. */
    KEYBOX_FLAG_OWNERTRUST, /* The assigned ownertrust. */
    KEYBOX_FLAG_KEY,        /* The key flags; requires a key index. */
    KEYBOX_FLAG_UID,        /* The user ID flags; requires an uid index. */
    KEYBOX_FLAG_UID_VALIDITY,/* The validity of a specific uid, requires
                               an uid index. */
    KEYBOX_FLAG_CREATED_AT, /* The date the block was created. */
    KEYBOX_FLAG_SIG_INFO,   /* The signature info block.  */
  } keybox_flag_t;

/* Flag values used with KEYBOX_FLAG_BLOB.  */
#define KEYBOX_FLAG_BLOB_SECRET     1
#define KEYBOX_FLAG_BLOB_EPHEMERAL  2

/* The keybox blob types.  */
typedef enum
  {
    KEYBOX_BLOBTYPE_EMPTY  = 0,
    KEYBOX_BLOBTYPE_HEADER = 1,
    KEYBOX_BLOBTYPE_PGP    = 2,
    KEYBOX_BLOBTYPE_X509   = 3
  } keybox_blobtype_t;


/*-- keybox-init.c --*/
gpg_error_t keybox_register_file (const char *fname, int secret,
                                  void **r_token);
int keybox_is_writable (void *token);

KEYBOX_HANDLE keybox_new_openpgp (void *token, int secret);
KEYBOX_HANDLE keybox_new_x509 (void *token, int secret);
void keybox_release (KEYBOX_HANDLE hd);
void keybox_push_found_state (KEYBOX_HANDLE hd);
void keybox_pop_found_state (KEYBOX_HANDLE hd);
const char *keybox_get_resource_name (KEYBOX_HANDLE hd);
int keybox_set_ephemeral (KEYBOX_HANDLE hd, int yes);

gpg_error_t keybox_lock (KEYBOX_HANDLE hd, int yes);

/*-- keybox-file.c --*/
/* Fixme: This function does not belong here: Provide a better
   interface to create a new keybox file.  */
int _keybox_write_header_blob (FILE *fp, int openpgp_flag);

/*-- keybox-search.c --*/
gpg_error_t keybox_get_keyblock (KEYBOX_HANDLE hd, iobuf_t *r_iobuf,
                                 int *r_uid_no, int *r_pk_no);
#ifdef KEYBOX_WITH_X509
int keybox_get_cert (KEYBOX_HANDLE hd, ksba_cert_t *ret_cert);
#endif /*KEYBOX_WITH_X509*/
int keybox_get_flags (KEYBOX_HANDLE hd, int what, int idx, unsigned int *value);

gpg_error_t keybox_search_reset (KEYBOX_HANDLE hd);
gpg_error_t keybox_search (KEYBOX_HANDLE hd,
                           KEYBOX_SEARCH_DESC *desc, size_t ndesc,
                           keybox_blobtype_t want_blobtype,
                           size_t *r_descindex, unsigned long *r_skipped);

off_t keybox_offset (KEYBOX_HANDLE hd);
gpg_error_t keybox_seek (KEYBOX_HANDLE hd, off_t offset);

/*-- keybox-update.c --*/
gpg_error_t keybox_insert_keyblock (KEYBOX_HANDLE hd,
                                    const void *image, size_t imagelen);
gpg_error_t keybox_update_keyblock (KEYBOX_HANDLE hd,
                                    const void *image, size_t imagelen);

#ifdef KEYBOX_WITH_X509
int keybox_insert_cert (KEYBOX_HANDLE hd, ksba_cert_t cert,
                        unsigned char *sha1_digest);
int keybox_update_cert (KEYBOX_HANDLE hd, ksba_cert_t cert,
                        unsigned char *sha1_digest);
#endif /*KEYBOX_WITH_X509*/
int keybox_set_flags (KEYBOX_HANDLE hd, int what, int idx, unsigned int value);

int keybox_delete (KEYBOX_HANDLE hd);
int keybox_compress (KEYBOX_HANDLE hd);


/*--  --*/

#if 0
int keybox_locate_writable (KEYBOX_HANDLE hd);
int keybox_rebuild_cache (void *);
#endif


/*-- keybox-util.c --*/
void keybox_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                               void *(*new_realloc_func)(void *p, size_t n),
                               void (*new_free_func)(void*) );

gpg_error_t keybox_tmp_names (const char *filename, int for_keyring,
                              char **r_bakname, char **r_tmpname);


#ifdef __cplusplus
}
#endif
#endif /*KEYBOX_H*/
