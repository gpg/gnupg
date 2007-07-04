/* keydb.h - Key database
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

#ifndef GNUPG_KEYDB_H
#define GNUPG_KEYDB_H

#include <ksba.h>

#include "../kbx/keybox-search-desc.h"

typedef struct keydb_handle *KEYDB_HANDLE;

/* Flag value used with KEYBOX_FLAG_VALIDITY. */
#define VALIDITY_REVOKED (1<<5)


/*-- keydb.c --*/
int keydb_add_resource (const char *url, int force, int secret,
                        int *auto_created);
KEYDB_HANDLE keydb_new (int secret);
void keydb_release (KEYDB_HANDLE hd);
int keydb_set_ephemeral (KEYDB_HANDLE hd, int yes);
const char *keydb_get_resource_name (KEYDB_HANDLE hd);
gpg_error_t keydb_lock (KEYDB_HANDLE hd);

#if 0 /* pgp stuff */
int keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb);
int keydb_update_keyblock (KEYDB_HANDLE hd, KBNODE kb);
int keydb_insert_keyblock (KEYDB_HANDLE hd, KBNODE kb);
#endif

gpg_error_t keydb_get_flags (KEYDB_HANDLE hd, int which, int idx,
                             unsigned int *value);
gpg_error_t keydb_set_flags (KEYDB_HANDLE hd, int which, int idx,
                             unsigned int value);
int keydb_get_cert (KEYDB_HANDLE hd, ksba_cert_t *r_cert);
int keydb_insert_cert (KEYDB_HANDLE hd, ksba_cert_t cert);
int keydb_update_cert (KEYDB_HANDLE hd, ksba_cert_t cert);

int keydb_delete (KEYDB_HANDLE hd, int unlock);

int keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved);
void keydb_rebuild_caches (void);

int keydb_search_reset (KEYDB_HANDLE hd);
int keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc, size_t ndesc);
int keydb_search_first (KEYDB_HANDLE hd);
int keydb_search_next (KEYDB_HANDLE hd);
int keydb_search_kid (KEYDB_HANDLE hd, u32 *kid);
int keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr);
int keydb_search_issuer (KEYDB_HANDLE hd, const char *issuer);
int keydb_search_issuer_sn (KEYDB_HANDLE hd,
                            const char *issuer, const unsigned char *serial);
int keydb_search_subject (KEYDB_HANDLE hd, const char *issuer);

int keydb_classify_name (const char *name, KEYDB_SEARCH_DESC *desc);

int keydb_store_cert (ksba_cert_t cert, int ephemeral, int *existed);
gpg_error_t keydb_set_cert_flags (ksba_cert_t cert, int ephemeral,
                                  int which, int idx,
                                  unsigned int mask, unsigned int value);

void keydb_clear_some_cert_flags (ctrl_t ctrl, strlist_t names);


#endif /*GNUPG_KEYDB_H*/




