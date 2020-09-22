/* keydb-private.h - Common definitions for keydb.c and call-keyboxd.c
 * Copyright (C) 2019 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef G10_KEYDB_PRIVATE_H
#define G10_KEYDB_PRIVATE_H

#include <assuan.h>
#include "../common/membuf.h"


/* Ugly forward declarations.  */
struct keyring_handle;
typedef struct keyring_handle *KEYRING_HANDLE;
struct keybox_handle;
typedef struct keybox_handle *KEYBOX_HANDLE;


/* This is for keydb.c and only used in non-keyboxd mode. */
#define MAX_KEYDB_RESOURCES 40

/* This is for keydb.c and only used in non-keyboxd mode. */
typedef enum
  {
    KEYDB_RESOURCE_TYPE_NONE = 0,
    KEYDB_RESOURCE_TYPE_KEYRING,
    KEYDB_RESOURCE_TYPE_KEYBOX
  } KeydbResourceType;

/* This is for keydb.c and only used in non-keyboxd mode. */
struct resource_item
{
  KeydbResourceType type;
  union {
    KEYRING_HANDLE kr;
    KEYBOX_HANDLE kb;
  } u;
  void *token;
};


/* This is a simple cache used to return the last result of a
 * successful fingerprint search.  This works only for keybox
 * resources because (due to lack of a copy_keyblock function) we need
 * to store an image of the keyblock which is fortunately instantly
 * available for keyboxes.   Only used in non-keyboxd mode.  */
enum keyblock_cache_states {
  KEYBLOCK_CACHE_EMPTY,
  KEYBLOCK_CACHE_PREPARED,
  KEYBLOCK_CACHE_FILLED
};

struct keyblock_cache {
  enum keyblock_cache_states state;
  byte fpr[MAX_FINGERPRINT_LEN];
  byte fprlen;
  iobuf_t iobuf; /* Image of the keyblock.  */
  int pk_no;
  int uid_no;
  /* Offset of the record in the keybox.  */
  int resource;
  off_t offset;
};


/* The definition of the KEYDB_HANDLE as used internally by keydb.c and
 * the newer call-keyboxd.  */
struct keydb_handle_s
{
  /* Flag set if this handles pertains to call-keyboxd.c.  */
  int use_keyboxd;

  /* BEGIN USE_KEYBOXD */
  /* (These fields are only valid if USE_KEYBOXD is set.) */

  /* A shallow pointer with the CTRL used to create this handle.  */
  ctrl_t ctrl;

  /* Connection info which also keeps the local state.  (This points
   * into the CTRL->keybox_local list.) */
  keyboxd_local_t kbl;

  /* Various flags.  */
  unsigned int last_ubid_valid:1;

  /* The UBID of the last returned keyblock.  */
  unsigned char last_ubid[UBID_LEN];

  /* The ordinals from the last search operations; valid if
   * last_ubid_valid is set.  */
  int last_uid_no;
  int last_pk_no;

  /* END USE_KEYBOXD */

  /* BEGIN !USE_KEYBOXD */
  /* (The remaining fields are only valid if USE_KEYBOXD is cleared.)  */

  /* When we locked all of the resources in ACTIVE (using keyring_lock
   * / keybox_lock, as appropriate).  */
  int locked;

  /* If this flag is set a lock will only be released by
   * keydb_release.  */
  int keep_lock;

  /* The index into ACTIVE of the resources in which the last search
     result was found.  Initially -1.  */
  int found;

  /* Initially -1 (invalid).  This is used to save a search result and
     later restore it as the selected result.  */
  int saved_found;

  /* The number of skipped long blobs since the last search
     (keydb_search_reset).  */
  unsigned long skipped_long_blobs;

  /* If set, this disables the use of the keyblock cache.  */
  int no_caching;

  /* Whether the next search will be from the beginning of the
     database (and thus consider all records).  */
  int is_reset;

  /* The "file position."  In our case, this is index of the current
     resource in ACTIVE.  */
  int current;

  /* The number of resources in ACTIVE.  */
  int used;

  /* Cache of the last found and parsed key block (only used for
     keyboxes, not keyrings).  */
  struct keyblock_cache keyblock_cache;

  /* Copy of ALL_RESOURCES when keydb_new is called.  */
  struct resource_item active[MAX_KEYDB_RESOURCES];

  /* END !USE_KEYBOXD */
};


/*-- keydb.c --*/


gpg_error_t keydb_parse_keyblock (iobuf_t iobuf, int pk_no, int uid_no,
                                  kbnode_t *r_keyblock);

/* These are the functions call-keyboxd diverts to if the keyboxd is
 * not used.  */

gpg_error_t internal_keydb_init (KEYDB_HANDLE hd);
void internal_keydb_deinit (KEYDB_HANDLE hd);
gpg_error_t internal_keydb_lock (KEYDB_HANDLE hd);

gpg_error_t internal_keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb);
gpg_error_t internal_keydb_update_keyblock (ctrl_t ctrl,
                                            KEYDB_HANDLE hd, kbnode_t kb);
gpg_error_t internal_keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb);
gpg_error_t internal_keydb_delete_keyblock (KEYDB_HANDLE hd);
gpg_error_t internal_keydb_search_reset (KEYDB_HANDLE hd);
gpg_error_t internal_keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                                   size_t ndesc, size_t *descindex);





#endif /*G10_KEYDB_PRIVATE_H*/
