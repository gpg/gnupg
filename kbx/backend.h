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

#include <ksba.h>
#include "keybox.h"

/* The types of the backends.  */
enum database_types
  {
   DB_TYPE_NONE,   /* No database at all (uninitialized etc.).  */
   DB_TYPE_CACHE,  /* The cache backend (backend-cache.c).    */
   DB_TYPE_KBX,    /* Keybox type database (backend-kbx.c).   */
   DB_TYPE_SQLITE  /* SQLite type database (backend-sqlite.c).*/
  };


/* Declaration of the backend handle.  Each backend uses its own
 * hidden handle structure with the only common thing being that the
 * first field is the database_type to help with debugging.  */
struct backend_handle_s;
typedef struct backend_handle_s *backend_handle_t;


/* Private data for sqlite requests.  */
struct be_sqlite_local_s;
typedef struct be_sqlite_local_s *be_sqlite_local_t;


/* Object to store backend specific database information per database
 * handle.  */
struct db_request_part_s
{
  struct db_request_part_s *next;

  /* Id of the backend instance this object pertains to.  */
  unsigned int backend_id;

  /* Local data for a KBX backend or NULL.  */
  KEYBOX_HANDLE kbx_hd;

  /* Local data for a sqlite backend.  */
  be_sqlite_local_t besqlite;

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
                              const unsigned char *ubid,
                              int is_ephemeral, int is_revoked,
                              int uidno, int pkno);
int be_is_x509_blob (const unsigned char *blob, size_t bloblen);
gpg_error_t be_ubid_from_blob (const void *blob, size_t bloblen,
                               enum pubkey_types *r_pktype, char *r_ubid);
char *be_get_x509_serial (ksba_cert_t cert);
gpg_error_t be_get_x509_keygrip (ksba_cert_t cert, unsigned char *keygrip);


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
gpg_error_t be_kbx_delete (ctrl_t ctrl, backend_handle_t backend_hd,
                           db_request_t request);


/*-- backend-sqlite.c --*/
gpg_error_t be_sqlite_add_resource (ctrl_t ctrl, backend_handle_t *r_hd,
                                    const char *filename, int readonly);
void be_sqlite_release_resource (ctrl_t ctrl, backend_handle_t hd);

gpg_error_t be_sqlite_init_local (backend_handle_t backend_hd,
                                  db_request_part_t part);
void be_sqlite_release_local (be_sqlite_local_t ctx);
gpg_error_t be_sqlite_rollback (void);
gpg_error_t be_sqlite_commit (void);
gpg_error_t be_sqlite_search (ctrl_t ctrl, backend_handle_t hd,
                              db_request_t request,
                              KEYDB_SEARCH_DESC *desc, unsigned int ndesc);
gpg_error_t be_sqlite_store (ctrl_t ctrl, backend_handle_t backend_hd,
                             db_request_t request, enum kbxd_store_modes mode,
                             enum pubkey_types pktype,
                             const unsigned char *ubid,
                             const void *blob, size_t bloblen);
gpg_error_t be_sqlite_delete (ctrl_t ctrl, backend_handle_t backend_hd,
                              db_request_t request, const unsigned char *ubid);


#endif /*KBX_BACKEND_H*/
