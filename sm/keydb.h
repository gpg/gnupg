/* keydb.h - Key database
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GNUPG_KEYDB_H
#define GNUPG_KEYDB_H

typedef struct keydb_handle *KEYDB_HANDLE;

typedef enum {
    KEYDB_SEARCH_MODE_NONE,
    KEYDB_SEARCH_MODE_EXACT,
    KEYDB_SEARCH_MODE_SUBSTR,
    KEYDB_SEARCH_MODE_MAIL,
    KEYDB_SEARCH_MODE_MAILSUB,
    KEYDB_SEARCH_MODE_MAILEND,
    KEYDB_SEARCH_MODE_WORDS,
    KEYDB_SEARCH_MODE_SHORT_KID,
    KEYDB_SEARCH_MODE_LONG_KID,
    KEYDB_SEARCH_MODE_FPR16,
    KEYDB_SEARCH_MODE_FPR20,
    KEYDB_SEARCH_MODE_FPR,
    KEYDB_SEARCH_MODE_FIRST,
    KEYDB_SEARCH_MODE_NEXT
} KeydbSearchMode;

struct keydb_search_desc {
    KeydbSearchMode mode;
    int (*skipfnc)(void *,u32*);
    void *skipfncvalue;
    union {
        const char *name;
        char fpr[MAX_FINGERPRINT_LEN];
        u32  kid[2];
    } u;
};

/*-- keydb.c --*/
int keydb_add_resource (const char *url, int force, int secret);
KEYDB_HANDLE keydb_new (int secret);
void keydb_release (KEYDB_HANDLE hd);
const char *keydb_get_resource_name (KEYDB_HANDLE hd);
int keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb);
int keydb_update_keyblock (KEYDB_HANDLE hd, KBNODE kb);
int keydb_insert_keyblock (KEYDB_HANDLE hd, KBNODE kb);
int keydb_delete_keyblock (KEYDB_HANDLE hd);
int keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved);
void keydb_rebuild_caches (void);
int keydb_search_reset (KEYDB_HANDLE hd);
int keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc, size_t ndesc);
int keydb_search_first (KEYDB_HANDLE hd);
int keydb_search_next (KEYDB_HANDLE hd);
int keydb_search_kid (KEYDB_HANDLE hd, u32 *kid);
int keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr);


#endif /*GNUPG_KEYDB_H*/




