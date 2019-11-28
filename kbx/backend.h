/* backend.h - Definitions for keyboxd backends
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
 */

#ifndef KBX_BACKEND_H
#define KBX_BACKEND_H

#include "keybox-search-desc.h"

/* Forward declaration of the keybox handle type.  */
struct keybox_handle;
typedef struct keybox_handle *KEYBOX_HANDLE;


/* The types of the backends.  */
enum database_types
  {
   DB_TYPE_NONE,   /* No database at all (unitialized etc.).  */
   DB_TYPE_CACHE,  /* The cache backend (backend-cache.c).    */
   DB_TYPE_KBX     /* Keybox type database (backend-kbx.c).   */
  };


/* Declaration of the backend handle.  Each backend uses its own
 * hidden handle structure with the only common thing being that the
 * first field is the database_type to help with debugging.  */
struct backend_handle_s;
typedef struct backend_handle_s *backend_handle_t;


/* Object to store backend specific database information per database
 * handle.  */
struct db_request_part_s
{
  struct db_request_part_s *next;

  /* Id of the backend instance this object pertains to.  */
  unsigned int backend_id;

  /* The handle used for a KBX backend or NULL.  */
  KEYBOX_HANDLE kbx_hd;

  /* For the CACHE backend the indices into the bloblist for each
   * index type.  */
  struct {
    unsigned int fpr;
    unsigned int kid;
    unsigned int grip;
    unsigned int ubid;
  } cache_seqno;
};
typedef struct db_request_part_s *db_request_part_t;


/* A database request handle.  This keeps per session search
 * information as well as a list of per-backend infos.  */
struct db_request_s
{
  unsigned int any_search:1;  /* Any search has been done.  */
  unsigned int any_found:1;   /* Any object has been found.  */
  unsigned int last_cached_valid:1; /* see below */
  unsigned int last_cached_final:1; /* see below */
  unsigned int last_cached_fprlen:8;/* see below */

  db_request_part_t part;

  /* Counter to track the next to be searched database index.  */
  unsigned int next_dbidx;

  /* The last UBID found in the cache and the corresponding keyid and,
   * if found via fpr, the fingerprint.  For the LAST_CACHED_FPRLEN see
   * above.  The entry here is only valid if LAST_CACHED_VALID is set;
   * if LAST_CACHED_FINAL is also set, this indicates that no further
   * database searches are required.  */
  unsigned char last_cached_ubid[UBID_LEN];
  u32 last_cached_kid_h;
  u32 last_cached_kid_l;
  unsigned char last_cached_fpr[32];
};



/*-- backend-support.c --*/
const char *strdbtype (enum database_types t);
unsigned int be_new_backend_id (void);
void be_generic_release_backend (ctrl_t ctrl, backend_handle_t hd);
void be_release_request (db_request_t req);
gpg_error_t be_find_request_part (backend_handle_t backend_hd,
                                  db_request_t request,
                                  db_request_part_t *r_part);
gpg_error_t be_return_pubkey (ctrl_t ctrl, const void *buffer, size_t buflen,
                              enum pubkey_types pubkey_type,
                              const unsigned char *ubid);
gpg_error_t be_ubid_from_blob (const void *blob, size_t bloblen,
                               enum pubkey_types *r_pktype, char *r_ubid);


/*-- backend-cache.c --*/
gpg_error_t be_cache_initialize (void);
gpg_error_t be_cache_add_resource (ctrl_t ctrl, backend_handle_t *r_hd);
void be_cache_release_resource (ctrl_t ctrl, backend_handle_t hd);
gpg_error_t be_cache_search (ctrl_t ctrl, backend_handle_t backend_hd,
                             db_request_t request,
                             KEYDB_SEARCH_DESC *desc, unsigned int ndesc);
void be_cache_mark_final (ctrl_t ctrl, db_request_t request);
void be_cache_pubkey (ctrl_t ctrl, const unsigned char *ubid,
                      const void *blob, unsigned int bloblen,
                      enum pubkey_types pubkey_type);
void be_cache_not_found (ctrl_t ctrl, enum pubkey_types pubkey_type,
                         KEYDB_SEARCH_DESC *desc, unsigned int ndesc);


/*-- backend-kbx.c --*/
gpg_error_t be_kbx_add_resource (ctrl_t ctrl, backend_handle_t *r_hd,
                                 const char *filename, int readonly);
void be_kbx_release_resource (ctrl_t ctrl, backend_handle_t hd);

void be_kbx_release_kbx_hd (KEYBOX_HANDLE kbx_hd);
gpg_error_t be_kbx_init_request_part (backend_handle_t backend_hd,
                                      db_request_part_t part);
gpg_error_t be_kbx_search (ctrl_t ctrl, backend_handle_t hd,
                           db_request_t request,
                           KEYDB_SEARCH_DESC *desc, unsigned int ndesc);
gpg_error_t be_kbx_seek (ctrl_t ctrl, backend_handle_t backend_hd,
                         db_request_t request, const unsigned char *ubid);
gpg_error_t be_kbx_insert (ctrl_t ctrl, backend_handle_t backend_hd,
                           db_request_t request, enum pubkey_types pktype,
                           const void *blob, size_t bloblen);
gpg_error_t be_kbx_update (ctrl_t ctrl, backend_handle_t backend_hd,
                           db_request_t request, enum pubkey_types pktype,
                           const void *blob, size_t bloblen);


#endif /*KBX_BACKEND_H*/
