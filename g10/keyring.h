/* keyring.h - Keyring operations
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef GPG_KEYRING_H
#define GPG_KEYRING_H 1

#include "global.h"

typedef struct keyring_handle *KEYRING_HANDLE;

int keyring_register_filename (const char *fname, int secret, void **ptr);
int keyring_is_writable (void *token);

KEYRING_HANDLE keyring_new (void *token, int secret);
void keyring_release (KEYRING_HANDLE hd);
const char *keyring_get_resource_name (KEYRING_HANDLE hd);
int keyring_lock (KEYRING_HANDLE hd, int yes);
int keyring_get_keyblock (KEYRING_HANDLE hd, KBNODE *ret_kb);
int keyring_update_keyblock (KEYRING_HANDLE hd, KBNODE kb);
int keyring_insert_keyblock (KEYRING_HANDLE hd, KBNODE kb);
int keyring_locate_writable (KEYRING_HANDLE hd);
int keyring_delete_keyblock (KEYRING_HANDLE hd);
int keyring_search_reset (KEYRING_HANDLE hd);
int keyring_search (KEYRING_HANDLE hd, KEYDB_SEARCH_DESC *desc,
		    size_t ndesc, size_t *descindex);
int keyring_rebuild_cache (void *token,int noisy);

#endif /*GPG_KEYRING_H*/
