/* keybox.h - Keybox operations
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef KEYBOX_H
#define KEYBOX_H 1
#ifdef __cplusplus
extern "C" { 
#if 0
 }
#endif
#endif

#include "keybox-search-desc.h"

#define KEYBOX_WITH_OPENPGP 1 
#define KEYBOX_WITH_X509 1


#ifdef KEYBOX_WITH_OPENPGP
#  undef KEYBOX_WITH_OPENPGP
/*#include <lib-to-handle-gpg-data-structs.h>*/
#endif

#ifdef KEYBOX_WITH_X509
# include <ksba.h>
#endif


typedef enum {
  KEYBOX_No_Error = 0,
  KEYBOX_General_Error = 1,
  KEYBOX_Out_Of_Core = 2,
  KEYBOX_Invalid_Value = 3,
  KEYBOX_Timeout = 4,  
  KEYBOX_Read_Error = 5,
  KEYBOX_Write_Error = 6,
  KEYBOX_File_Error = 7,
  KEYBOX_Blob_Too_Short = 8,
  KEYBOX_Blob_Too_Large = 9,
  KEYBOX_Invalid_Handle = 10,
  KEYBOX_File_Create_Error = 11,
  KEYBOX_File_Open_Error = 12,
  KEYBOX_File_Close_Error = 13,
  KEYBOX_Nothing_Found = 14,
  KEYBOX_Wrong_Blob_Type = 15,
} KeyboxError;



typedef struct keybox_handle *KEYBOX_HANDLE;


/*-- keybox-init.c --*/
void *keybox_register_file (const char *fname, int secret);
int keybox_is_writable (void *token);

KEYBOX_HANDLE keybox_new (void *token, int secret);
void keybox_release (KEYBOX_HANDLE hd);
const char *keybox_get_resource_name (KEYBOX_HANDLE hd);


/*-- keybox-search.c --*/
#ifdef KEYBOX_WITH_X509 
int keybox_get_cert (KEYBOX_HANDLE hd, KsbaCert *ret_cert);
#endif /*KEYBOX_WITH_X509*/

int keybox_search_reset (KEYBOX_HANDLE hd);
int keybox_search (KEYBOX_HANDLE hd, KEYBOX_SEARCH_DESC *desc, size_t ndesc);


/*-- keybox-update.c --*/
#ifdef KEYBOX_WITH_X509 
int keybox_insert_cert (KEYBOX_HANDLE hd, KsbaCert cert,
                        unsigned char *sha1_digest);
int keybox_update_cert (KEYBOX_HANDLE hd, KsbaCert cert,
                        unsigned char *sha1_digest);
#endif /*KEYBOX_WITH_X509*/

int keybox_delete (KEYBOX_HANDLE hd);


/*--  --*/

#if 0
int keybox_lock (KEYBOX_HANDLE hd, int yes);
int keybox_get_keyblock (KEYBOX_HANDLE hd, KBNODE *ret_kb);
int keybox_locate_writable (KEYBOX_HANDLE hd);
int keybox_search_reset (KEYBOX_HANDLE hd);
int keybox_search (KEYBOX_HANDLE hd, KEYDB_SEARCH_DESC *desc, size_t ndesc);
int keybox_rebuild_cache (void *);
#endif


/*-- keybox-util.c --*/
void keybox_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                               void *(*new_realloc_func)(void *p, size_t n),
                               void (*new_free_func)(void*) );

/*-- keybox-errors.c (built) --*/
const char *keybox_strerror (KeyboxError err);


#ifdef __cplusplus
}
#endif
#endif /*KEYBOX_H*/
