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
   DB_TYPE_KBX     /* Keybox type database (backend-kbx.c).   */
  };


/* Declaration of the backend handle.  Each backend uses its own
 * hidden handle structure with the only common thing being that the
 * first field is the database_type to help with debugging.  */
struct backend_handle_s;
typedef struct backend_handle_s *backend_handle_t;


/* Object to store backend specific databsde information per database
 * handle.  */
struct db_request_part_s
{
  struct db_request_part_s *next;

  /* Id of the backend instance this object pertains to.  */
  unsigned int backend_id;

  /* The handle used for a KBX backend or NULL.  */
  KEYBOX_HANDLE kbx_hd;
};
typedef struct db_request_part_s *db_request_part_t;


/* A database request handle.  This keeps per session search
 * information as well as a list of per-backend infos.  */
struct db_request_s
{
  unsigned int any_search:1;  /* Any search has been done.  */
  unsigned int any_found:1;   /* Any object has been found.  */

  db_request_part_t part;

  /* Counter to track the next to be searched database index.  */
  unsigned int next_dbidx;
};



/*-- backend-support.c --*/
const char *strdbtype (enum database_types t);
unsigned int be_new_backend_id (void);
void be_generic_release_backend (ctrl_t ctrl, backend_handle_t hd);
void be_release_request (db_request_t req);
gpg_error_t be_return_pubkey (ctrl_t ctrl, void *buffer, size_t buflen,
                              enum pubkey_types pubkey_type);


/*-- backend-kbx.c --*/
gpg_error_t be_kbx_add_resource (ctrl_t ctrl, backend_handle_t *r_hd,
                                 const char *filename, int readonly);
void be_kbx_release_resource (ctrl_t ctrl, backend_handle_t hd);

void be_kbx_release_kbx_hd (KEYBOX_HANDLE kbx_hd);
gpg_error_t be_kbx_search (ctrl_t ctrl, backend_handle_t hd,
                           db_request_t request,
                           KEYDB_SEARCH_DESC *desc, unsigned int ndesc);


#endif /*KBX_BACKEND_H*/
