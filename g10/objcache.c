/* objcache.c - Caching functions for keys and user ids.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "keydb.h"
#include "options.h"
#include "objcache.h"

/* Note that max value for uid_items is actually the threshold when
 * we start to look for items which can be removed.  */
#define NO_OF_UID_ITEM_BUCKETS    107
#define MAX_UID_ITEMS_PER_BUCKET  20

#define NO_OF_KEY_ITEM_BUCKETS    383
#define MAX_KEY_ITEMS_PER_BUCKET  20


/* An object to store a user id.  This describes an item in the linked
 * lists of a bucket in hash table.  The reference count will
 * eventually be used to remove items from the table.  */
typedef struct uid_item_s
{
  struct uid_item_s *next;
  unsigned int refcount;  /* The reference count for this item.   */
  unsigned int namelen;   /* The length of the UID sans the nul.  */
  char name[1];
} *uid_item_t;

static uid_item_t *uid_table; /* Hash table for with user ids.  */
static size_t uid_table_size; /* Number of allocated buckets.   */
static unsigned int uid_table_max;    /* Max. # of items in a bucket.  */
static unsigned int uid_table_added;  /* # of items added.   */
static unsigned int uid_table_dropped;/* # of items dropped.  */


/* An object to store properties of a key.  Note that this can be used
 * for a primary or a subkey.  The key is linked to a user if that
 * exists.  */
typedef struct key_item_s
{
  struct key_item_s *next;
  unsigned int usecount;
  byte fprlen;
  char fpr[MAX_FINGERPRINT_LEN];
  u32 keyid[2];
  uid_item_t ui;          /* NULL of a ref'ed user id item.      */
} *key_item_t;

static key_item_t *key_table; /* Hash table with the keys.      */
static size_t key_table_size; /* Number of allocated buckents.  */
static unsigned int key_table_max;    /* Max. # of items in a bucket.  */
static unsigned int key_table_added;  /* # of items added.   */
static unsigned int key_table_dropped;/* # of items dropped.  */
static key_item_t key_item_attic;     /* List of freed items.  */



/* Dump stats.  */
void
objcache_dump_stats (void)
{
  unsigned int idx;
  int len, minlen, maxlen;
  unsigned int count, attic, empty;
  key_item_t ki;
  uid_item_t ui;

  count = empty = 0;
  minlen = -1;
  maxlen = 0;
  for (idx = 0; idx < key_table_size; idx++)
    {
      len = 0;
      for (ki = key_table[idx]; ki; ki = ki->next)
        {
          count++;
          len++;
          /* log_debug ("key bucket %u: kid=%08lX used=%u ui=%p\n", */
          /*            idx, (ulong)ki->keyid[0], ki->usecount, ki->ui); */
        }
      if (len > maxlen)
        maxlen = len;

      if (!len)
        empty++;
      else if (minlen == -1 || len < minlen)
        minlen = len;
    }
  for (attic=0, ki = key_item_attic; ki; ki = ki->next)
    attic++;
  log_info ("objcache: keys=%u/%u/%u chains=%u,%d..%d buckets=%zu/%u"
            " attic=%u\n",
            count, key_table_added, key_table_dropped,
            empty, minlen > 0? minlen : 0, maxlen,
            key_table_size, key_table_max, attic);

  count = empty = 0;
  minlen = -1;
  maxlen = 0;
  for (idx = 0; idx < uid_table_size; idx++)
    {
      len = 0;
      for (ui = uid_table[idx]; ui; ui = ui->next)
        {
          count++;
          len++;
          /* log_debug ("uid bucket %u: %p ref=%u l=%u (%.20s)\n", */
          /*            idx, ui, ui->refcount, ui->namelen, ui->name); */
        }
      if (len > maxlen)
        maxlen = len;

      if (!len)
        empty++;
      else if (minlen == -1 || len < minlen)
        minlen = len;
    }
  log_info ("objcache: uids=%u/%u/%u chains=%u,%d..%d buckets=%zu/%u\n",
            count, uid_table_added, uid_table_dropped,
            empty, minlen > 0? minlen : 0, maxlen,
            uid_table_size, uid_table_max);
}



/* The hash function we use for the uid_table.  Must not call a system
 * function.  */
static inline unsigned int
uid_table_hasher (const char *name, unsigned namelen)
{
  const unsigned char *s = (const unsigned char*)name;
  unsigned int hashval = 0;
  unsigned int carry;

  for (; namelen; namelen--, s++)
    {
      hashval = (hashval << 4) + *s;
      if ((carry = (hashval & 0xf0000000)))
        {
          hashval ^= (carry >> 24);
          hashval ^= carry;
        }
    }

  return hashval % uid_table_size;
}


/* Run time allocation of the uid table.  This allows us to eventually
 * add an option to gpg to control the size.  */
static void
uid_table_init (void)
{
  if (uid_table)
    return;
  uid_table_size = NO_OF_UID_ITEM_BUCKETS;
  uid_table_max = MAX_UID_ITEMS_PER_BUCKET;
  uid_table = xcalloc (uid_table_size, sizeof *uid_table);
}


static uid_item_t
uid_item_ref (uid_item_t ui)
{
  if (ui)
    ui->refcount++;
  return ui;
}

static void
uid_item_unref (uid_item_t uid)
{
  if (!uid)
    return;
  if (!uid->refcount)
    log_fatal ("too many unrefs for uid_item\n");

  uid->refcount--;
  /* We do not release the item here because that would require that
   * we locate the head of the list which has this item.  This will
   * take too long and thus the item is removed when we need to purge
   * some items for the list during uid_item_put.  */
}


/* Put (NAME,NAMELEN) into the UID_TABLE and return the item.  The
 * reference count for that item is incremented.  NULL is return on an
 * allocation error.  The caller should release the returned item
 * using uid_item_unref.  */
static uid_item_t
uid_table_put (const char *name, unsigned int namelen)
{
  unsigned int hash;
  uid_item_t ui;
  unsigned int count;

  if (!uid_table)
    uid_table_init ();

  hash = uid_table_hasher (name, namelen);
  for (ui = uid_table[hash], count = 0; ui; ui = ui->next, count++)
    if (ui->namelen == namelen && !memcmp (ui->name, name, namelen))
      return uid_item_ref (ui);  /* Found.  */

  /* If the bucket is full remove all unrefed items.  */
  if (count >= uid_table_max)
    {
      uid_item_t ui_next, ui_prev, list_head, drop_head;

      /* No syscalls from here .. */
      list_head = uid_table[hash];
      drop_head = NULL;
      while (list_head && !list_head->refcount)
        {
          ui = list_head;
          list_head = ui->next;
          ui->next = drop_head;
          drop_head = ui;
        }
      if ((ui_prev = list_head))
        for (ui = ui_prev->next; ui; ui = ui_next)
          {
            ui_next = ui->next;
            if (!ui->refcount)
              {
                ui->next = drop_head;
                drop_head = ui;
                ui_prev->next = ui_next;
              }
            else
              ui_prev = ui;
          }
      uid_table[hash] = list_head;
      /* ... to here */

      for (ui = drop_head; ui; ui = ui_next)
        {
          ui_next = ui->next;
          xfree (ui);
          uid_table_dropped++;
        }
    }

  count = uid_table_added + uid_table_dropped;
  ui = xtrycalloc (1, sizeof *ui + namelen);
  if (!ui)
    return NULL;  /* Out of core.  */
  if (count != uid_table_added + uid_table_dropped)
    {
      /* During the malloc another thread added an item.  Thus we need
       * to check again.  */
      uid_item_t ui_new = ui;
      for (ui = uid_table[hash]; ui; ui = ui->next)
        if (ui->namelen == namelen && !memcmp (ui->name, name, namelen))
          {
            /* Found.  */
            xfree (ui_new);
            return uid_item_ref (ui);
          }
      ui = ui_new;
    }

  memcpy (ui->name, name, namelen);
  ui->name[namelen] = 0; /* Extra Nul so we can use it as a string.  */
  ui->namelen = namelen;
  ui->refcount = 1;
  ui->next = uid_table[hash];
  uid_table[hash] = ui;
  uid_table_added++;
  return ui;
}



/* The hash function we use for the key_table.  Must not call a system
 * function.  */
static inline unsigned int
key_table_hasher (u32 *keyid)
{
  /* A fingerprint could be used directly as a hash value.  However,
   * we use the keyid here because it is used in encrypted packets and
   * older signatures to identify a key.  Since v4 keys the keyid is
   * anyway a part of the fingerprint so it quickly extracted from a
   * fingerprint.  Note that v3 keys are not supported by gpg.  */
  return keyid[0] % key_table_size;
}


/* Run time allocation of the key table.  This allows us to eventually
 * add an option to gpg to control the size.  */
static void
key_table_init (void)
{
  if (key_table)
    return;
  key_table_size = NO_OF_KEY_ITEM_BUCKETS;
  key_table_max  = MAX_KEY_ITEMS_PER_BUCKET;
  key_table = xcalloc (key_table_size, sizeof *key_table);
}


static void
key_item_free (key_item_t ki)
{
  if (!ki)
    return;
  uid_item_unref (ki->ui);
  ki->ui = NULL;
  ki->next = key_item_attic;
  key_item_attic = ki;
}


/* Get a key item from PK or if that is NULL from KEYID.  The
 * reference count for that item is incremented.  NULL is return if it
 * was not found.  */
static key_item_t
key_table_get (PKT_public_key *pk, u32 *keyid)
{
  unsigned int hash;
  key_item_t ki, ki2;

  if (!key_table)
    key_table_init ();

  if (pk)
    {
      byte fpr[MAX_FINGERPRINT_LEN];
      size_t fprlen;
      u32 tmpkeyid[2];

      fingerprint_from_pk (pk, fpr, &fprlen);
      keyid_from_pk (pk, tmpkeyid);
      hash = key_table_hasher (tmpkeyid);
      for (ki = key_table[hash]; ki; ki = ki->next)
        if (ki->fprlen == fprlen && !memcmp (ki->fpr, fpr, fprlen))
          return ki; /* Found */
    }
  else if (keyid)
    {
      hash = key_table_hasher (keyid);
      for (ki = key_table[hash]; ki; ki = ki->next)
        if (ki->keyid[0] == keyid[0] && ki->keyid[1] == keyid[1])
          {
            /* Found.  We need to check for dups.  */
            for (ki2 = ki->next; ki2; ki2 = ki2->next)
              if (ki2->keyid[0] == keyid[0] && ki2->keyid[1] == keyid[1])
                return NULL;  /* Duplicated keyid - return NULL.  */

            /* This is the only one - return it.  */
            return ki;
          }
    }
  return NULL;
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


/* Put PK into the KEY_TABLE and return a key item.  The reference
 * count for that item is incremented.  If UI is given it is put into
 * the entry.  NULL is return on an allocation error.  */
static key_item_t
key_table_put (PKT_public_key *pk, uid_item_t ui)
{
  unsigned int hash;
  key_item_t ki;
  u32 keyid[2];
  byte fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  unsigned int count, n;

  if (!key_table)
    key_table_init ();

  fingerprint_from_pk (pk, fpr, &fprlen);
  keyid_from_pk (pk, keyid);
  hash = key_table_hasher (keyid);
  for (ki = key_table[hash], count=0; ki; ki = ki->next, count++)
    if (ki->fprlen == fprlen && !memcmp (ki->fpr, fpr, fprlen))
      return ki;  /* Found  */

  /* If the bucket is full remove a couple of items. */
  if (count >= key_table_max)
    {
      key_item_t list_head, *list_tailp, ki_next;
      key_item_t *array;
      int narray, idx;

      /* Unlink from the global list so that other threads don't
       * disturb us.  If another thread adds or removes something only
       * one will be the winner.  Bad luck for the drooped cache items
       * but after all it is just a cache.  */
      list_head = key_table[hash];
      key_table[hash] = NULL;

      /* Put all items into an array for sorting.  */
      array = xtrycalloc (count, sizeof *array);
      if (!array)
        {
          /* That's bad; give up all  items of the bucket.  */
          log_info ("Note: malloc failed while purging from the key_tabe: %s\n",
                    gpg_strerror (gpg_error_from_syserror ()));
          goto leave_drop;
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
          key_item_free (array[idx]);
          key_table_dropped++;
        }
      xfree (array);

    leave_drop:
      /* Free any items added in the meantime by other threads.  This
       * is also used in case of a malloc problem (which won't update
       * the counters, though). */
      for ( ; list_head; list_head = ki_next)
        {
          ki_next = list_head->next;
          key_item_free (list_head);
        }
    }

  /* Add an item to the bucket.  We allocate a whole block of items
   * for cache performance reasons.  */
  if (!key_item_attic)
    {
      key_item_t kiblock;
      int kiblocksize = 256;

      kiblock = xtrymalloc (kiblocksize * sizeof *kiblock);
      if (!kiblock)
        return NULL;  /* Out of core.  */
      for (n = 0; n < kiblocksize; n++)
        {
          ki = kiblock + n;
          ki->next = key_item_attic;
          key_item_attic = ki;
        }

      /* During the malloc another thread may have changed the bucket.
       * Thus we need to check again.  */
      for (ki = key_table[hash]; ki; ki = ki->next)
        if (ki->fprlen == fprlen && !memcmp (ki->fpr, fpr, fprlen))
          return ki;  /* Found  */
    }

  /* We now know that there is an item in the attic.  */
  ki = key_item_attic;
  key_item_attic = ki->next;
  ki->next = NULL;

  memcpy (ki->fpr, fpr, fprlen);
  ki->fprlen = fprlen;
  ki->keyid[0] = keyid[0];
  ki->keyid[1] = keyid[1];
  ki->ui = uid_item_ref (ui);
  ki->usecount = 0;
  ki->next = key_table[hash];
  key_table[hash] = ki;
  key_table_added++;
  return ki;
}



/* Return the user ID from the given keyblock.  We use the primary uid
 * flag which should have already been set.  The returned value is
 * only valid as long as the given keyblock is not changed. */
static const char *
primary_uid_from_keyblock (kbnode_t keyblock, size_t *uidlen)
{
  kbnode_t k;

  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID
	  && !k->pkt->pkt.user_id->attrib_data
	  && k->pkt->pkt.user_id->flags.primary)
	{
	  *uidlen = k->pkt->pkt.user_id->len;
	  return k->pkt->pkt.user_id->name;
	}
    }
  return NULL;
}


/* Store the associations of keyid/fingerprint and userid.  Only
 * public keys should be fed to this function.  */
void
cache_put_keyblock (kbnode_t keyblock)
{
  uid_item_t ui = NULL;
  kbnode_t k;

 restart:
  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_PUBLIC_KEY
	  || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
          if (!ui)
            {
              /* Initially we just test for an entry to avoid the need
               * to create a user id item for a put.  Only if we miss
               * key in the cache we create a user id and restart.  */
              if (!key_table_get (k->pkt->pkt.public_key, NULL))
                {
                  const char *uid;
                  size_t uidlen;

                  uid = primary_uid_from_keyblock (keyblock, &uidlen);
                  if (uid)
                    {
                      ui = uid_table_put (uid, uidlen);
                      if (!ui)
                        {
                          log_info ("Note: failed to cache a user id: %s\n",
                                    gpg_strerror (gpg_error_from_syserror ()));
                          goto leave;
                        }
                      goto restart;
                    }
                }
            }
          else /* With a UID we use the update cache mode.  */
            {
              if (!key_table_put (k->pkt->pkt.public_key, ui))
                {
                  log_info ("Note: failed to cache a key: %s\n",
                            gpg_strerror (gpg_error_from_syserror ()));
                  goto leave;
                }
            }
        }
    }

 leave:
  uid_item_unref (ui);
}


/* Return the user id string for KEYID.  If a user id is not found (or
 * on malloc error) NULL is returned.  If R_LENGTH is not NULL the
 * length of the user id is stored there; this does not included the
 * always appended nul.  Note that a user id may include an internal
 * nul which can be detected by the caller by comparing to the
 * returned length.  */
char *
cache_get_uid_bykid (u32 *keyid, unsigned int *r_length)
{
  key_item_t ki;
  char *p;

  if (r_length)
    *r_length = 0;

  ki = key_table_get (NULL, keyid);
  if (!ki)
    return NULL; /* Not found or duplicate keyid.  */

  if (!ki->ui)
    p = NULL;  /* No user id known for key.  */
  else
    {
      p = xtrymalloc (ki->ui->namelen + 1);
      if (p)
        {
          memcpy (p, ki->ui->name, ki->ui->namelen + 1);
          if (r_length)
            *r_length = ki->ui->namelen;
          ki->usecount++;
        }
    }

  return p;
}


/* Return the user id string for FPR with FPRLEN.  If a user id is not
 * found (or on malloc error) NULL is returned.  If R_LENGTH is not
 * NULL the length of the user id is stored there; this does not
 * included the always appended nul.  Note that a user id may include
 * an internal nul which can be detected by the caller by comparing to
 * the returned length.  */
char *
cache_get_uid_byfpr (const byte *fpr, size_t fprlen, size_t *r_length)
{
  char *p;
  unsigned int hash;
  u32 keyid[2];
  key_item_t ki;

  if (r_length)
    *r_length = 0;

  if (!key_table)
    return NULL;

  keyid_from_fingerprint (NULL, fpr, fprlen, keyid);
  hash = key_table_hasher (keyid);
  for (ki = key_table[hash]; ki; ki = ki->next)
    if (ki->fprlen == fprlen && !memcmp (ki->fpr, fpr, fprlen))
      break; /* Found */

  if (!ki)
    return NULL; /* Not found.  */

  if (!ki->ui)
    p = NULL;  /* No user id known for key.  */
  else
    {
      p = xtrymalloc (ki->ui->namelen + 1);
      if (p)
        {
          memcpy (p, ki->ui->name, ki->ui->namelen + 1);
          if (r_length)
            *r_length = ki->ui->namelen;
          ki->usecount++;
        }
    }

  return p;
}
