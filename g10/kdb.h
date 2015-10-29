#ifndef GNUPG_KDB_H
#define GNUPG_KDB_H

#include "keydb.h"

typedef struct keydb_handle *KDB_HANDLE;

gpg_error_t kdb_register_file (const char *fname, int read_only, void **ptr);
int kdb_is_writable (void *token);

KDB_HANDLE kdb_new (void *token);
void kdb_release (KDB_HANDLE hd);
void kdb_push_found_state (KDB_HANDLE hd);
void kdb_pop_found_state (KDB_HANDLE hd);
const char *kdb_get_resource_name (KDB_HANDLE hd);
int kdb_lock (KDB_HANDLE hd, int yes);
int kdb_get_keyblock (KDB_HANDLE hd, iobuf_t *iobuf,
                      int *pk_no, int *uid_no, u32 **sigstatus);
int kdb_update_keyblock (KDB_HANDLE hd, kbnode_t kb,
                         const void *image, size_t imagelen);
gpg_error_t kdb_insert_keyblock (KDB_HANDLE hd, kbnode_t kb,
                                 const void *image, size_t imagelen,
                                 u32 *sigstatus);
int kdb_delete (KDB_HANDLE hd);
int kdb_search_reset (KDB_HANDLE hd);
int kdb_search (KDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                size_t ndesc, size_t *descindex);

#endif
