/* backend-cache.c - Cache backend for keyboxd
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

/*
 * This cache backend is designed to be queried first and to deliver
 * cached items (which may also be not-found).  A set a maintenance
 * functions is used used by the frontend to fill the cache.
 * FIXME: Support x.509
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "keyboxd.h"
#include "../common/i18n.h"
#include "../common/host2net.h"
#include "backend.h"
#include "keybox-defs.h"


/* Standard values for the number of buckets and the threshold we use
 * to flush items.  */
#define NO_OF_KEY_ITEM_BUCKETS          383
#define KEY_ITEMS_PER_BUCKET_THRESHOLD  40
#define NO_OF_BLOB_BUCKETS              383
#define BLOBS_PER_BUCKET_THRESHOLD      20


/* Our definition of the backend handle.  */
struct backend_handle_s
{
  enum database_types db_type; /* Always DB_TYPE_CACHE.  */
  unsigned int backend_id;     /* Always the id the backend.  */
};


/* The object holding a blob.  */
typedef struct blob_s
{
  struct blob_s *next;
  enum pubkey_types pktype;
  unsigned int refcount;
  unsigned int usecount;
  unsigned int datalen;
  unsigned char *data;        /* The actual data of length DATALEN.  */
  unsigned char ubid[UBID_LEN];
} *blob_t;


static blob_t *blob_table;                /* Hash table with the blobs.   */
static size_t blob_table_size;            /* Number of allocated buckets. */
static unsigned int blob_table_threshold; /* Max. # of items per bucket.  */
static unsigned int blob_table_added;     /* Number of items added.       */
static unsigned int blob_table_dropped;   /* Number of items dropped.     */
static blob_t blob_attic;                 /* List of freed blobs.         */


/* A list item to blob data.  This is so that a next operation on a
 * cached key item can actually work.  Things are complicated because
 * we do not want to force caching all object before we get a next
 * request from the client.  To accomplish this we keep a flag
 * indicating that the search needs to continue instead of delivering
 * the previous item from the cache.  */
typedef struct bloblist_s
{
  struct bloblist_s *next;
  unsigned int final_kid:1;     /* The final blob for KID searches. */
  unsigned int final_fpr:1;     /* The final blob for FPR searches. */
  unsigned int ubid_valid:1;    /* The blobid below is valid.   */
  unsigned int subkey:1;        /* The entry is for a subkey.   */
  unsigned int fprlen:8;        /* The length of the fingerprint or 0.  */
  char fpr[32];                 /* The buffer for the fingerprint.  */
  unsigned char ubid[UBID_LEN]; /* The Unique-Blob-ID of the blob.  */
} *bloblist_t;

static bloblist_t bloblist_attic;  /* List of freed items.  */

/* The cache object.  For indexing we could use the fingerprint
 * directly as a hash value.  However, we use the keyid instead
 * because the keyid is used by OpenPGP in encrypted packets and older
 * signatures to identify a key.  Since v4 OpenPGP keys the keyid is
 * anyway a part of the fingerprint so it quickly extracted from a
 * fingerprint.  Note that v3 keys are not supported by gpg.
 * FIXME: Add support for X.509.
 */
typedef struct key_item_s
{
  struct key_item_s *next;
  bloblist_t  blist;       /* List of blobs or NULL for not-found.  */
  unsigned int usecount;
  unsigned int refcount;   /* Reference counter for this item.  */
  u32 kid_h;               /* Upper 4 bytes of the keyid.  */
  u32 kid_l;               /* Lower 4 bytes of the keyid.  */
} *key_item_t;

static key_item_t *key_table;            /* Hash table with the keys.    */
static size_t key_table_size;            /* Number of allocated buckets. */
static unsigned int key_table_threshold; /* Max. # of items per bucket.  */
static unsigned int key_table_added;     /* Number of items added.       */
static unsigned int key_table_dropped;   /* Number of items dropped.     */
static key_item_t key_item_attic;        /* List of freed items.         */




/* The hash function we use for the key_table.  Must not call a system
 * function.  */
static inline unsigned int
blob_table_hasher (const unsigned char *ubid)
{
  return (ubid[0] << 16 | ubid[1]) % blob_table_size;
}


/* Runtime allocation of the key table.  This allows us to eventually
 * add an option to control the size.  */
static gpg_error_t
blob_table_init (void)
{
  if (blob_table)
    return 0;
  blob_table_size = NO_OF_BLOB_BUCKETS;
  blob_table_threshold  = BLOBS_PER_BUCKET_THRESHOLD;
  blob_table = xtrycalloc (blob_table_size, sizeof *blob_table);
  if (!blob_table)
    return gpg_error_from_syserror ();
  return 0;
}

/* Free a blob.  This is done by moving it to the attic list.  */
static void
blob_unref (blob_t blob)
{
  void *p;

  if (!blob)
    return;
  log_assert (blob->refcount);
  if (!--blob->refcount)
    {
      p = blob->data;
      blob->data = NULL;
      blob->next = blob_attic;
      blob_attic = blob;
      xfree (p);
    }
}


/* Given the hash value and the ubid, find the blob in the bucket.
 * Returns NULL if not found or the blob item if found.  Always
 * returns the the number of items searched, which is in the case of a
 * not-found the length of the chain.  */
static blob_t
find_blob (unsigned int hash, const unsigned char *ubid,
           unsigned int *r_count)
{
  blob_t b;
  unsigned int count = 0;

  for (b = blob_table[hash]; b; b = b->next, count++)
    if (!memcmp (b->ubid, ubid, UBID_LEN))
      break;
  if (r_count)
    *r_count = count;
  return b;
}


/* Helper for the qsort in key_table_put.  */
static int
compare_blobs (const void *arg_a, const void *arg_b)
{
  const blob_t a = *(const blob_t *)arg_a;
  const blob_t b = *(const blob_t *)arg_b;

  /* Reverse sort on the usecount.  */
  if (a->usecount > b->usecount)
    return -1;
  else if (a->usecount == b->usecount)
    return 0;
  else
    return 1;
}


/* Put the blob (BLOBDATA, BLOBDATALEN) into the cache using UBID as
 * the index.  If it is already in the cache nothing happens.  */
static void
blob_table_put (const unsigned char *ubid, enum pubkey_types pktype,
                const void *blobdata, unsigned int blobdatalen)
{
  unsigned int hash;
  blob_t b;
  unsigned int count, n;
  void *blobdatacopy = NULL;

  hash = blob_table_hasher (ubid);
 find_again:
  b = find_blob (hash, ubid, &count);
  if (b)
    {
      xfree (blobdatacopy);
      return;  /* Already got this blob.  */
    }

  /* Create a copy of the blob if not yet done.  */
  if (!blobdatacopy)
    {
      blobdatacopy = xtrymalloc (blobdatalen);
      if (!blobdatacopy)
        {
          log_info ("Note: malloc failed while copying blob to the cache: %s\n",
                    gpg_strerror (gpg_error_from_syserror ()));
          return;  /* Out of core - ignore.  */
        }
      memcpy (blobdatacopy, blobdata, blobdatalen);
    }

  /* If the bucket is full remove a couple of items. */
  if (count >= blob_table_threshold)
    {
      blob_t list_head, *list_tailp, b_next;
      blob_t *array;
      int narray, idx;

      /* Unlink from the global list so that other threads don't
       * disturb us.  If another thread adds or removes something only
       * one will be the winner.  Bad luck for the dropped cache items
       * but after all it is just a cache.  */
      list_head = blob_table[hash];
      blob_table[hash] = NULL;

      /* Put all items into an array for sorting.  */
      array = xtrycalloc (count, sizeof *array);
      if (!array)
        {
          /* That's bad; give up all  items of the bucket.  */
          log_info ("Note: malloc failed while purging blobs from the "
                    "cache: %s\n", gpg_strerror (gpg_error_from_syserror ()));
          goto leave_drop;
        }
      narray = 0;
      for (b = list_head; b; b = b_next)
        {
          b_next = b->next;
          array[narray++] = b;
          b->next = NULL;
        }
      log_assert (narray == count);

      /* Sort the array and put half of it onto a new list.  */
      qsort (array, narray, sizeof *array, compare_blobs);
      list_head = NULL;
      list_tailp = &list_head;
      for (idx=0; idx < narray/2; idx++)
        {
          *list_tailp = array[idx];
          list_tailp = &array[idx]->next;
        }

      /* Put the new list into the bucket.  */
      b = blob_table[hash];
      blob_table[hash] = list_head;
      list_head = b;

      /* Free the remaining items and the array.  */
      for (; idx < narray; idx++)
        {
          blob_unref (array[idx]);
          blob_table_dropped++;
        }
      xfree (array);

    leave_drop:
      /* Free any items added in the meantime by other threads.  This
       * is also used in case of a malloc problem (which won't update
       * the counters, though). */
      for ( ; list_head; list_head = b_next)
        {
          b_next = list_head->next;
          blob_unref (list_head);
        }
    }

  /* Add an item to the bucket.  We allocate a whole block of items
   * for cache performance reasons.  */
  if (!blob_attic)
    {
      blob_t b_block;
      int b_blocksize = 256;

      b_block = xtrymalloc (b_blocksize * sizeof *b_block);
      if (!b_block)
        {
          log_info ("Note: malloc failed while adding blob to the cache: %s\n",
                    gpg_strerror (gpg_error_from_syserror ()));
          xfree (blobdatacopy);
          return;  /* Out of core - ignore.  */
        }
      for (n = 0; n < b_blocksize; n++)
        {
          b = b_block + n;
          b->next = blob_attic;
          blob_attic = b;
        }

      /* During the malloc another thread might have changed the
       * bucket.  Thus we need to start over.  */
      goto find_again;
    }

  /* We now know that there is an item in the attic.  Put it into the
   * chain.  Note that we may not use any system call here. */
  b = blob_attic;
  blob_attic = b->next;
  b->next = NULL;
  b->pktype = pktype;
  b->data = blobdatacopy;
  b->datalen = blobdatalen;
  memcpy (b->ubid, ubid, UBID_LEN);
  b->usecount = 1;
  b->refcount = 1;
  b->next = blob_table[hash];
  blob_table[hash] = b;
  blob_table_added++;
}


/* Given the UBID return a cached blob item.  The caller must
 * release that item using blob_unref.  */
static blob_t
blob_table_get (const unsigned char *ubid)
{
  unsigned int hash;
  blob_t b;

  hash = blob_table_hasher (ubid);
  b = find_blob (hash, ubid, NULL);
  if (b)
    {
      b->usecount++;
      b->refcount++;
      return b;  /* Found  */
    }

  return NULL;
}



/* The hash function we use for the key_table.  Must not call a system
 * function.  */
static inline unsigned int
key_table_hasher (u32 kid_l)
{
  return kid_l % key_table_size;
}


/* Runtime allocation of the key table.  This allows us to eventually
 * add an option to control the size.  */
static gpg_error_t
key_table_init (void)
{
  if (key_table)
    return 0;
  key_table_size = NO_OF_KEY_ITEM_BUCKETS;
  key_table_threshold  = KEY_ITEMS_PER_BUCKET_THRESHOLD;
  key_table = xtrycalloc (key_table_size, sizeof *key_table);
  if (!key_table)
    return gpg_error_from_syserror ();
  return 0;
}

/* Free a key_item.  This is done by moving it to the attic list.  */
static void
key_item_unref (key_item_t ki)
{
  bloblist_t bl, bl2;

  if (!ki)
    return;
  log_assert (ki->refcount);
  if (!--ki->refcount)
    {
      bl = ki->blist;
      ki->blist = NULL;
      ki->next = key_item_attic;
      key_item_attic = ki;

      if (bl)
        {
          for (bl2 = bl; bl2->next; bl2 = bl2->next)
            ;
          bl2->next = bloblist_attic;
          bloblist_attic = bl;
        }
    }
}


/* Given the hash value and the search info, find the key item in the
 * bucket.  Return NULL if not found or the key item if found.  Always
 * returns the the number of items searched, which is in the case of a
 * not-found the length of the chain.  Note that FPR may only be NULL
 * if FPRLEN is 0. */
static key_item_t
find_in_chain (unsigned int hash, u32 kid_h, u32 kid_l,
               unsigned int *r_count)
{
  key_item_t ki = key_table[hash];
  unsigned int count = 0;

  for (; ki; ki = ki->next, count++)
    if (ki->kid_h == kid_h && ki->kid_l == kid_l)
      break;
  if (r_count)
    *r_count = count;
  return ki;
}


/* Helper for the qsort in key_table_put.  */
static int
compare_key_items (const void *arg_a, const void *arg_b)
{
  const key_item_t a = *(const key_item_t *)arg_a;
  const key_item_t b = *(const key_item_t *)arg_b;

  /* Reverse sort on the usecount.  */
  if (a->usecount > b->usecount)
    return -1;
  else if (a->usecount == b->usecount)
    return 0;
  else
    return 1;
}


/* Allocate new key items.  They are put to the attic so that the
 * caller can take them from there.  On allocation failure a note
 * is printed and an error returned.  */
static gpg_error_t
alloc_more_key_items (void)
{
  gpg_error_t err;
  key_item_t kiblock, ki;
  int kiblocksize = 256;
  unsigned int n;

  kiblock = xtrymalloc (kiblocksize * sizeof *kiblock);
  if (!kiblock)
    {
      err = gpg_error_from_syserror ();
      log_info ("Note: malloc failed while adding to the cache: %s\n",
                gpg_strerror (err));
      return err;
    }
  for (n = 0; n < kiblocksize; n++)
    {
      ki = kiblock + n;
      ki->next = key_item_attic;
      key_item_attic = ki;
    }
  return 0;
}


/* Allocate new bloblist items.  They are put to the attic so that the
 * caller can take them from there.  On allocation failure a note is
 * printed and an error returned.  */
static gpg_error_t
alloc_more_bloblist_items (void)
{
  gpg_error_t err;
  bloblist_t bl;
  bloblist_t blistblock;
  int blistblocksize = 256;
  unsigned int n;

  blistblock = xtrymalloc (blistblocksize * sizeof *blistblock);
  if (!blistblock)
    {
      err = gpg_error_from_syserror ();
      log_info ("Note: malloc failed while adding to the cache: %s\n",
                gpg_strerror (err));
      return err;
    }
  for (n = 0; n < blistblocksize; n++)
    {
      bl = blistblock + n;
      bl->next = bloblist_attic;
      bloblist_attic = bl;
    }
  return 0;
}


/* Helper for key_table_put.  This function assumes that
 * bloblist_attaci is not NULL.  Returns a new bloblist item.  Be
 * aware that no system calls may be done - even not log
 * functions!  */
static bloblist_t
new_bloblist_item (const unsigned char *fpr, unsigned int fprlen,
                   const unsigned char *ubid, int subkey)
{
  bloblist_t bl;

  bl = bloblist_attic;
  bloblist_attic = bl->next;
  bl->next = NULL;

  if (ubid)
    memcpy (bl->ubid, ubid, UBID_LEN);
  else
    memset (bl->ubid, 0, UBID_LEN);
  bl->ubid_valid = 1;
  bl->final_kid = 0;
  bl->final_fpr = 0;
  bl->subkey = !!subkey;
  bl->fprlen = fprlen;
  memcpy (bl->fpr, fpr, fprlen);
  return bl;
}


/* If the list of key item in the bucken HASH is full remove a couple
 * of them.  On error a diagnostic is printed and an error code
 * return.  Note that the error code GPG_ERR_TRUE is returned if any
 * flush and thus system calls were done.
 */
static gpg_error_t
maybe_flush_some_key_buckets (unsigned int hash, unsigned int count)
{
  gpg_error_t err;
  key_item_t ki, list_head, *list_tailp, ki_next;
  key_item_t *array;
  int narray, idx;

  if (count < key_table_threshold)
    return 0;  /* Nothing to do.  */

  /* Unlink from the global list so that other threads don't disturb
   * us.  If another thread adds or removes something only one will be
   * the winner.  Bad luck for the dropped cache items but after all
   * it is just a cache.  */
  list_head = key_table[hash];
  key_table[hash] = NULL;

  /* Put all items into an array for sorting.  */
  array = xtrycalloc (count, sizeof *array);
  if (!array)
    {
      /* That's bad; give up all items of the bucket.  */
      err = gpg_error_from_syserror ();
      log_info ("Note: malloc failed while purging from the cache: %s\n",
                gpg_strerror (err));
      goto leave;
    }
  narray = 0;
  for (ki = list_head; ki; ki = ki_next)
    {
      ki_next = ki->next;
      array[narray++] = ki;
      ki->next = NULL;
    }
  log_assert (narray == count);

  /* Sort the array and put half of it onto a new list.  */
  qsort (array, narray, sizeof *array, compare_key_items);
  list_head = NULL;
  list_tailp = &list_head;
  for (idx=0; idx < narray/2; idx++)
    {
      *list_tailp = array[idx];
      list_tailp = &array[idx]->next;
    }

  /* Put the new list into the bucket.  */
  ki = key_table[hash];
  key_table[hash] = list_head;
  list_head = ki;

  /* Free the remaining items and the array.  */
  for (; idx < narray; idx++)
    {
      key_item_unref (array[idx]);
      key_table_dropped++;
    }
  xfree (array);
  err = gpg_error (GPG_ERR_TRUE);

 leave:
  /* Free any items added in the meantime by other threads.  This is
   * also used in case of a malloc problem (which won't update the
   * counters, though). */
  for ( ; list_head; list_head = ki_next)
    {
      ki_next = list_head->next;
      key_item_unref (list_head);
    }
  return err;
}


/* This is the core of
 *   key_table_put,
 *   key_table_put_no_fpr,
 *   key_table_put_no_kid.
 */
static void
do_key_table_put (u32 kid_h, u32 kid_l,
                  const unsigned char *fpr, unsigned int fprlen,
                  const unsigned char *ubid, int subkey)
{
  unsigned int hash;
  key_item_t ki;
  bloblist_t bl, bl_tail;
  unsigned int count;
  int do_find_again;
  int mark_not_found = !fpr;

  hash = key_table_hasher (kid_l);
 find_again:
  do_find_again = 0;
  ki = find_in_chain (hash, kid_h, kid_l, &count);
  if (ki)
    {
      if (mark_not_found)
        return; /* Can't put the mark because meanwhile a entry was
                 * added.  */

      for (bl = ki->blist; bl; bl = bl->next)
        if (bl->fprlen
            && bl->fprlen == fprlen
            && !memcmp (bl->fpr, fpr, fprlen))
          break;
      if (bl)
        return;  /* Already in the bloblist for the keyid  */

      /* Append to the list.  */
      if (!bloblist_attic)
        {
          if (alloc_more_bloblist_items ())
            return;  /* Out of core - ignore.  */
          goto find_again; /* Need to start over due to the malloc.  */
        }
      for (bl_tail = NULL, bl = ki->blist; bl; bl_tail = bl, bl = bl->next)
        ;
      bl = new_bloblist_item (fpr, fprlen, ubid, subkey);
      if (bl_tail)
        bl_tail->next = bl;
      else
        ki->blist = bl;

      return;
    }

  /* If the bucket is full remove a couple of items. */
  if (maybe_flush_some_key_buckets (hash, count))
    {
      /* During the function call another thread might have changed
       * the bucket.  Thus we need to start over.  */
      do_find_again = 1;
    }

  if (!key_item_attic)
    {
      if (alloc_more_key_items ())
        return;  /* Out of core - ignore.  */
      do_find_again = 1;
    }

  if (!bloblist_attic)
    {
      if (alloc_more_bloblist_items ())
        return;  /* Out of core - ignore.  */
      do_find_again = 1;
    }

  if (do_find_again)
    goto find_again;

  /* We now know that there are items in the attics.  Put them into
   * the chain.  Note that we may not use any system call here. */
  ki = key_item_attic;
  key_item_attic = ki->next;
  ki->next = NULL;

  if (mark_not_found)
    ki->blist = NULL;
  else
    ki->blist = new_bloblist_item (fpr, fprlen, ubid, subkey);

  ki->kid_h = kid_h;
  ki->kid_l = kid_l;
  ki->usecount = 1;
  ki->refcount = 1;

  ki->next = key_table[hash];
  key_table[hash] = ki;
  key_table_added++;
}


/* Given the fingerprint (FPR,FPRLEN) put the UBID into the cache.
 * SUBKEY indicates that the fingerprint is from a subkey.  */
static void
key_table_put (const unsigned char *fpr, unsigned int fprlen,
               const unsigned char *ubid, int subkey)
{
  u32 kid_h, kid_l;

  if (fprlen < 20 || fprlen > 32)
    return;  /* No support for v3 keys or unknown key versions.  */

  if (fprlen == 20)  /* v4 key */
    {
      kid_h = buf32_to_u32 (fpr+12);
      kid_l = buf32_to_u32 (fpr+16);
    }
  else  /* v5 or later key */
    {
      kid_h = buf32_to_u32 (fpr);
      kid_l = buf32_to_u32 (fpr+4);
    }
  do_key_table_put (kid_h, kid_l, fpr, fprlen, ubid, subkey);
}


/* Given the fingerprint (FPR,FPRLEN) put a flag into the cache that
 * this fingerprint was not found.  */
static void
key_table_put_no_fpr (const unsigned char *fpr, unsigned int fprlen)
{
  u32 kid_h, kid_l;

  if (fprlen < 20 || fprlen > 32)
    return;  /* No support for v3 keys or unknown key versions.  */

  if (fprlen == 20)  /* v4 key */
    {
      kid_h = buf32_to_u32 (fpr+12);
      kid_l = buf32_to_u32 (fpr+16);
    }
  else  /* v5 or later key */
    {
      kid_h = buf32_to_u32 (fpr);
      kid_l = buf32_to_u32 (fpr+4);
    }
  /* Note that our not-found chaching is only based on the keyid. */
  do_key_table_put (kid_h, kid_l, NULL, 0, NULL, 0);
}


/* Given the keyid (KID_H, KID_L) put a flag into the cache that this
 * keyid was not found. */
static void
key_table_put_no_kid (u32 kid_h, u32 kid_l)
{
  do_key_table_put (kid_h, kid_l, NULL, 0, NULL, 0);
}


/* Given the keyid or the fingerprint return the key item from the
 * cache.  The caller must release the result using key_item_unref.
 * NULL is returned if not found.  */
static key_item_t
key_table_get (u32 kid_h, u32 kid_l)
{
  unsigned int hash;
  key_item_t ki;

  hash = key_table_hasher (kid_l);
  ki = find_in_chain (hash, kid_h, kid_l, NULL);
  if (ki)
    {
      ki->usecount++;
      ki->refcount++;
      return ki;  /* Found  */
    }

  return NULL;
}


/* Return a key item by searching for the keyid.  The caller must use
 * key_item_unref on it.  */
static key_item_t
query_by_kid (u32 kid_h, u32 kid_l)
{
  return key_table_get (kid_h, kid_l);
}


/* Return a key item by searching for the fingerprint.  The caller
 * must use key_item_unref on it.  Note that the returned key item may
 * not actually carry the fingerprint; the caller needs to scan the
 * bloblist of the keyitem.  We can't do that here because the
 * reference counting is done on the keyitem s and thus this needs to
 * be returned. */
static key_item_t
query_by_fpr (const unsigned char *fpr, unsigned int fprlen)
{
  u32 kid_h, kid_l;

  if (fprlen < 20 || fprlen > 32 )
    return NULL;  /* No support for v3 keys or unknown key versions.  */

  if (fprlen == 20)  /* v4 key */
    {
      kid_h = buf32_to_u32 (fpr+12);
      kid_l = buf32_to_u32 (fpr+16);
    }
  else  /* v5 or later key */
    {
      kid_h = buf32_to_u32 (fpr);
      kid_l = buf32_to_u32 (fpr+4);
    }

  return key_table_get (kid_h, kid_l);
}





/* Make sure the tables are initialized.  */
gpg_error_t
be_cache_initialize (void)
{
  gpg_error_t err;

  err = blob_table_init ();
  if (!err)
    err = key_table_init ();
  return err;
}


/* Install a new resource and return a handle for that backend.  */
gpg_error_t
be_cache_add_resource (ctrl_t ctrl, backend_handle_t *r_hd)
{
  gpg_error_t err;
  backend_handle_t hd;

  (void)ctrl;

  *r_hd = NULL;
  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return gpg_error_from_syserror ();
  hd->db_type = DB_TYPE_CACHE;

  hd->backend_id = be_new_backend_id ();

  /* Just in case make sure we are initialized.  */
  err = be_cache_initialize ();
  if (err)
    goto leave;

  *r_hd = hd;
  hd = NULL;

 leave:
  xfree (hd);
  return err;
}


/* Release the backend handle HD and all its resources.  HD is not
 * valid after a call to this function.  */
void
be_cache_release_resource (ctrl_t ctrl, backend_handle_t hd)
{
  (void)ctrl;

  if (!hd)
    return;
  hd->db_type = DB_TYPE_NONE;

  /* Fixme: Free the key_table.  */

  xfree (hd);
}


/* Search for the keys described by (DESC,NDESC) and return them to
 * the caller.  BACKEND_HD is the handle for this backend and REQUEST
 * is the current database request object.  On a cache hit either 0 or
 * GPG_ERR_NOT_FOUND is returned.  The former returns the item; the
 * latter indicates that the cache has known that the item won't be
 * found in any databases.  On a cache miss GPG_ERR_EOF is
 * returned.  */
gpg_error_t
be_cache_search (ctrl_t ctrl, backend_handle_t backend_hd, db_request_t request,
                 KEYDB_SEARCH_DESC *desc, unsigned int ndesc)
{
  gpg_error_t err;
  db_request_part_t reqpart;
  unsigned int n;
  blob_t b;
  key_item_t ki;
  bloblist_t bl;
  int not_found = 0;
  int descidx = 0;
  int found_bykid = 0;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_CACHE);
  log_assert (request);

  err = be_find_request_part (backend_hd, request, &reqpart);
  if (err)
    goto leave;

  if (!desc)
    {
      /* Reset operation.  */
      request->last_cached_valid = 0;
      request->last_cached_final = 0;
      reqpart->cache_seqno.fpr = 0;
      reqpart->cache_seqno.kid = 0;
      reqpart->cache_seqno.grip = 0;
      reqpart->cache_seqno.ubid = 0;
      err = 0;
      goto leave;
    }

  for (ki = NULL, n=0; n < ndesc && !ki; n++)
    {
      descidx = n;
      switch (desc[n].mode)
        {
        case KEYDB_SEARCH_MODE_LONG_KID:
          ki = query_by_kid (desc[n].u.kid[0], desc[n].u.kid[1]);
          if (ki && ki->blist)
            {
              not_found = 0;
              /* Note that in a bloblist all keyids are the same.  */
              for (n=0, bl = ki->blist; bl; bl = bl->next)
                if (n++ == reqpart->cache_seqno.kid)
                  break;
              if (!bl)
                {
                  key_item_unref (ki);
                  ki = NULL;
                }
              else
                {
                  found_bykid = 1;
                  reqpart->cache_seqno.kid++;
                }
            }
          else if (ki)
            not_found = 1;
          break;

        case KEYDB_SEARCH_MODE_FPR:
          ki = query_by_fpr (desc[n].u.fpr, desc[n].fprlen);
          if (ki && ki->blist)
            {
              not_found = 0;
              for (n=0, bl = ki->blist; bl; bl = bl->next)
                if (bl->fprlen
                    && bl->fprlen == desc[n].fprlen
                    && !memcmp (bl->fpr, desc[n].u.fpr, desc[n].fprlen)
                    && n++ == reqpart->cache_seqno.fpr)
                  break;
              if (!bl)
                {
                  key_item_unref (ki);
                  ki = NULL;
                }
              else
                reqpart->cache_seqno.fpr++;
            }
          else if (ki)
            not_found = 1;
          break;

        /* case KEYDB_SEARCH_MODE_KEYGRIP: */
        /*   ki = query_by_grip (desc[n].u.fpr, desc[n].fprlen); */
        /*   break; */

        case KEYDB_SEARCH_MODE_UBID:
          /* This is the quite special UBID mode: If this is
           * encountered in the search list we will return just this
           * one and obviously look only into the blob cache.  */
          if (reqpart->cache_seqno.ubid)
            err = gpg_error (GPG_ERR_NOT_FOUND);
          else
            {
              b = blob_table_get (desc[n].u.ubid);
              if (b)
                {
                  err = be_return_pubkey (ctrl, b->data, b->datalen,
                                          b->pktype, desc[n].u.ubid,
                                          0, 0, 0, 0);
                  blob_unref (b);
                  reqpart->cache_seqno.ubid++;
                }
              else
                err = gpg_error (GPG_ERR_EOF);
            }
          goto leave;

        default:
          ki = NULL;
          break;
        }
    }

  if (not_found)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      key_item_unref (ki);
    }
  else if (ki)
    {
      if (bl && bl->ubid_valid)
        {
          memcpy (request->last_cached_ubid, bl->ubid, UBID_LEN);
          request->last_cached_valid = 1;
          request->last_cached_fprlen = desc[descidx].fprlen;
          memcpy (request->last_cached_fpr,
                  desc[descidx].u.fpr, desc[descidx].fprlen);
          request->last_cached_kid_h = ki->kid_h;
          request->last_cached_kid_l = ki->kid_l;
          request->last_cached_valid = 1;
          if ((bl->final_kid && found_bykid)
              || (bl->final_fpr && !found_bykid))
            request->last_cached_final = 1;
          else
            request->last_cached_final = 0;

          b = blob_table_get (bl->ubid);
          if (b)
            {
              err = be_return_pubkey (ctrl, b->data, b->datalen,
                                      PUBKEY_TYPE_OPGP, bl->ubid, 0, 0, 0, 0);
              blob_unref (b);
            }
          else
            {
              /* FIXME - return a different code so that the caller
               * can lookup using the UBID.  */
              err = gpg_error (GPG_ERR_MISSING_VALUE);
            }
        }
      else if (bl)
        err = gpg_error (GPG_ERR_MISSING_VALUE);
      else
        err = gpg_error (GPG_ERR_NOT_FOUND);
      key_item_unref (ki);
    }
  else
    err = gpg_error (GPG_ERR_EOF);

 leave:
  return err;
}


/* Mark the last cached item as the final item.  This is called when
 * the actual database returned EOF in respond to a restart from the
 * last cached UBID.  */
void
be_cache_mark_final (ctrl_t ctrl, db_request_t request)
{
  key_item_t ki;
  bloblist_t bl, blfound;

  (void)ctrl;

  log_assert (request);

  if (!request->last_cached_valid)
    return;

  if (!request->last_cached_fprlen) /* Was cached via keyid.  */
    {
      ki = query_by_kid (request->last_cached_kid_h,
                         request->last_cached_kid_l);
      if (ki && (bl = ki->blist))
        {
          for (blfound=NULL; bl; bl = bl->next)
            blfound = bl;
          if (blfound)
            blfound->final_kid = 1;
        }
      key_item_unref (ki);
    }
  else /* Was cached via fingerprint.  */
    {
      ki = query_by_fpr (request->last_cached_fpr,
                         request->last_cached_fprlen);
      if (ki && (bl = ki->blist))
        {
          for (blfound=NULL; bl; bl = bl->next)
            if (bl->fprlen
                && bl->fprlen == request->last_cached_fprlen
                && !memcmp (bl->fpr, request->last_cached_fpr,
                            request->last_cached_fprlen))
              blfound = bl;
          if (blfound)
            blfound->final_fpr = 1;
        }
      key_item_unref (ki);
    }

  request->last_cached_valid = 0;
}


/* Put the key (BLOB,BLOBLEN) of PUBKEY_TYPE into the cache.  */
void
be_cache_pubkey (ctrl_t ctrl, const unsigned char *ubid,
                 const void *blob, unsigned int bloblen,
                 enum pubkey_types pubkey_type)
{
  gpg_error_t err;

  (void)ctrl;

  if (pubkey_type == PUBKEY_TYPE_OPGP)
    {
      struct _keybox_openpgp_info info;
      struct _keybox_openpgp_key_info *kinfo;

      err = _keybox_parse_openpgp (blob, bloblen, NULL, &info);
      if (err)
        {
          log_info ("cache: error parsing OpenPGP blob: %s\n",
                    gpg_strerror (err));
          return;
        }

      blob_table_put (ubid, pubkey_type, blob, bloblen);

      kinfo = &info.primary;
      key_table_put (kinfo->fpr, kinfo->fprlen, ubid, 0);
      if (info.nsubkeys)
        for (kinfo = &info.subkeys; kinfo; kinfo = kinfo->next)
          key_table_put (kinfo->fpr, kinfo->fprlen, ubid, 1);

      _keybox_destroy_openpgp_info (&info);
    }

}


/* Put the a non-found mark for PUBKEY_TYPE into the cache.  The
 * indices are taken from the search descriptors (DESC,NDESC).  */
void
be_cache_not_found (ctrl_t ctrl, enum pubkey_types pubkey_type,
                    KEYDB_SEARCH_DESC *desc, unsigned int ndesc)
{
  unsigned int n;

  (void)ctrl;
  (void)pubkey_type;

  for (n=0; n < ndesc; n++)
    {
      switch (desc->mode)
        {
        case KEYDB_SEARCH_MODE_LONG_KID:
          key_table_put_no_kid (desc[n].u.kid[0], desc[n].u.kid[1]);
          break;

        case KEYDB_SEARCH_MODE_FPR:
          key_table_put_no_fpr (desc[n].u.fpr, desc[n].fprlen);
          break;

        default:
          break;
        }
    }
}
