/* cache.c - keep a cache of passphrases
 * Copyright (C) 2002, 2010 Free Software Foundation, Inc.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <npth.h>

#include "agent.h"

/* The default TTL for DATA items.  This has no configure
 * option because it is expected that clients provide a TTL.  */
#define DEF_CACHE_TTL_DATA  (10 * 60)  /* 10 minutes.  */

/* The size of the encryption key in bytes.  */
#define ENCRYPTION_KEYSIZE (128/8)

/* A mutex used to serialize access to the cache.  */
static npth_mutex_t cache_lock;
/* The encryption context.  This is the only place where the
   encryption key for all cached entries is available.  It would be nice
   to keep this (or just the key) in some hardware device, for example
   a TPM.  Libgcrypt could be extended to provide such a service.
   With the current scheme it is easy to retrieve the cached entries
   if access to Libgcrypt's memory is available.  The encryption
   merely avoids grepping for clear texts in the memory.  Nevertheless
   the encryption provides the necessary infrastructure to make it
   more secure.  */
static gcry_cipher_hd_t encryption_handle;


struct secret_data_s {
  int  totallen; /* This includes the padding and space for AESWRAP. */
  char data[1];  /* A string.  */
};

/* The type of cache object.  */
typedef struct cache_item_s *ITEM;

/* The timer entry in a linked list.  */
struct timer_s {
  ITEM next;
  int tv_sec;
  int reason;
};
#define CACHE_EXPIRE_UNUSED      0
#define CACHE_EXPIRE_LAST_ACCESS 1
#define CACHE_EXPIRE_CREATION    2

/* The cache object.  */
struct cache_item_s {
  ITEM next;
  time_t created;
  time_t accessed;  /* Not updated for CACHE_MODE_DATA */
  int ttl;  /* max. lifetime given in seconds, -1 one means infinite */
  struct secret_data_s *pw;
  cache_mode_t cache_mode;
  int restricted;  /* The value of ctrl->restricted is part of the key.  */
  struct timer_s t;
  char key[1];
};

/* The cache himself.  */
static ITEM thecache;

/* The timer list of expiration, in active.  */
static ITEM the_timer_list;
/* Newly created entries, to be inserted into the timer list.  */
static ITEM the_timer_list_new;

/* NULL or the last cache key stored by agent_store_cache_hit.  */
static char *last_stored_cache_key;


/* This function must be called once to initialize this module. It
   has to be done before a second thread is spawned.  */
void
initialize_module_cache (void)
{
  int err;

  err = npth_mutex_init (&cache_lock, NULL);

  if (err)
    log_fatal ("error initializing cache module: %s\n", strerror (err));
}


void
deinitialize_module_cache (void)
{
  gcry_cipher_close (encryption_handle);
  encryption_handle = NULL;
}


/* We do the encryption init on the fly.  We can't do it in the module
   init code because that is run before we listen for connections and
   in case we are started on demand by gpg etc. it will only wait for
   a few seconds to decide whether the agent may now accept
   connections.  Thus we should get into listen state as soon as
   possible.  */
static gpg_error_t
init_encryption (void)
{
  gpg_error_t err;
  void *key;

  if (encryption_handle)
    return 0; /* Shortcut - Already initialized.  */

  err = gcry_cipher_open (&encryption_handle, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, GCRY_CIPHER_SECURE);
  if (!err)
    {
      key = gcry_random_bytes (ENCRYPTION_KEYSIZE, GCRY_STRONG_RANDOM);
      if (!key)
        err = gpg_error_from_syserror ();
      else
        {
          err = gcry_cipher_setkey (encryption_handle, key, ENCRYPTION_KEYSIZE);
          xfree (key);
        }
      if (err)
        {
          gcry_cipher_close (encryption_handle);
          encryption_handle = NULL;
        }
    }
  if (err)
    log_error ("error initializing cache encryption context: %s\n",
               gpg_strerror (err));

  return err? gpg_error (GPG_ERR_NOT_INITIALIZED) : 0;
}



static void
release_data (struct secret_data_s *data)
{
   xfree (data);
}

static gpg_error_t
new_data (const char *string, struct secret_data_s **r_data)
{
  gpg_error_t err;
  struct secret_data_s *d, *d_enc;
  size_t length;
  int total;

  *r_data = NULL;

  err = init_encryption ();
  if (err)
    return err;

  length = strlen (string) + 1;

  /* We pad the data to 32 bytes so that it get more complicated
     finding something out by watching allocation patterns.  This is
     usually not possible but we better assume nothing about our secure
     storage provider.  To support the AESWRAP mode we need to add 8
     extra bytes as well. */
  total = (length + 8) + 32 - ((length+8) % 32);

  d = xtrymalloc_secure (sizeof *d + total - 1);
  if (!d)
    return gpg_error_from_syserror ();
  memcpy (d->data, string, length);

  d_enc = xtrymalloc (sizeof *d_enc + total - 1);
  if (!d_enc)
    {
      err = gpg_error_from_syserror ();
      xfree (d);
      return err;
    }

  d_enc->totallen = total;
  err = gcry_cipher_encrypt (encryption_handle, d_enc->data, total,
                             d->data, total - 8);
  xfree (d);
  if (err)
    {
      xfree (d_enc);
      return err;
    }
  *r_data = d_enc;
  return 0;
}


static void
insert_to_timer_list_new (ITEM entry)
{
  entry->t.next = the_timer_list_new;
  the_timer_list_new = entry;
}

/* Insert to the active timer list.  */
static void
insert_to_timer_list (struct timespec *ts, ITEM entry)
{
  ITEM e, eprev;

  if (!the_timer_list || ts->tv_sec >= entry->t.tv_sec)
    {
      if (the_timer_list)
        {
          the_timer_list->t.tv_sec += ts->tv_sec - entry->t.tv_sec;
          if (ts->tv_nsec >= 500000000)
            the_timer_list->t.tv_sec++;
        }

      ts->tv_sec = entry->t.tv_sec;
      ts->tv_nsec = 0;

      entry->t.tv_sec = 0;
      entry->t.next = the_timer_list;
      the_timer_list = entry;
      return;
    }

  entry->t.tv_sec -= ts->tv_sec;
  eprev = NULL;
  for (e = the_timer_list; e; e = e->t.next)
    {
      if (e->t.tv_sec > entry->t.tv_sec)
        break;

      eprev = e;
      entry->t.tv_sec -= e->t.tv_sec;
    }

  entry->t.next = e;
  if (e)
    e->t.tv_sec -= entry->t.tv_sec;

  if (eprev)
    eprev->t.next = entry;
  else
    the_timer_list = entry;
}

static void
remove_from_timer_list (ITEM entry)
{
  ITEM e, eprev;

  eprev = NULL;
  for (e = the_timer_list; e; e = e->t.next)
    if (e != entry)
      eprev = e;
    else
      {
        if (e->t.next)
          e->t.next->t.tv_sec += e->t.tv_sec;

        if (eprev)
          eprev->t.next = e->t.next;
        else
          the_timer_list = e->t.next;

        break;
      }

  entry->t.next = NULL;
  entry->t.tv_sec = 0;
}

static void
remove_from_timer_list_new (ITEM entry)
{
  ITEM e, eprev;

  eprev = NULL;
  for (e = the_timer_list_new; e; e = e->t.next)
    if (e != entry)
      eprev = e;
    else
      {
        if (eprev)
          eprev->t.next = e->t.next;
        else
          the_timer_list_new = e->t.next;

        break;
      }

  entry->t.next = NULL;
  entry->t.tv_sec = 0;
}

static int
compute_expiration (ITEM r)
{
  unsigned long maxttl;
  time_t current = gnupg_get_time ();
  time_t next;

  if (r->cache_mode == CACHE_MODE_PIN)
    return 0; /* Don't let it expire - scdaemon explicitly flushes them.  */

  if (!r->pw)
    {
      /* Expire an old and unused entry after 30 minutes.  */
      r->t.tv_sec = 60*30;
      r->t.reason = CACHE_EXPIRE_UNUSED;
      return 1;
    }

  if (r->cache_mode == CACHE_MODE_DATA)
    {
      /* No MAX TTL here.  */
      if (r->ttl >= 0)
        {
          r->t.tv_sec = r->ttl;
          r->t.reason = CACHE_EXPIRE_CREATION;
          return 1;
        }
      else
        return 0;
    }
  else if (r->cache_mode == CACHE_MODE_SSH)
    maxttl = opt.max_cache_ttl_ssh;
  else
    maxttl = opt.max_cache_ttl;

  if (r->created + maxttl <= current)
    {
      r->t.tv_sec = 0;
      r->t.reason = CACHE_EXPIRE_CREATION;
      return 1;
    }

  next = r->created + maxttl - current;
  if (r->ttl >= 0 && r->ttl < next)
    {
      r->t.tv_sec = r->ttl;
      r->t.reason = CACHE_EXPIRE_LAST_ACCESS;
      return 1;
    }

  r->t.tv_sec = next;
  r->t.reason = CACHE_EXPIRE_CREATION;
  return 1;
}

static void
update_expiration (ITEM entry, int is_new_entry)
{
  if (!is_new_entry)
    {
      remove_from_timer_list (entry);
      remove_from_timer_list_new (entry);
    }

  if (compute_expiration (entry))
    {
      insert_to_timer_list_new (entry);
      agent_kick_the_loop ();
    }
}


/* Expire the cache entry.  Returns 1 when the entry should be removed
 * from the cache.  */
static int
do_expire (ITEM e)
{
  if (!e->pw)
    /* Unused entry after 30 minutes.  */
    return 1;

  if (e->t.reason == CACHE_EXPIRE_LAST_ACCESS)
    {
      if (DBG_CACHE)
        log_debug ("  expired '%s'.%d (%ds after last access)\n",
                   e->key, e->restricted, e->ttl);
    }
  else
    {
      if (DBG_CACHE)
        log_debug ("  expired '%s'.%d (%lus after creation)\n",
                   e->key, e->restricted, opt.max_cache_ttl);
    }

  release_data (e->pw);
  e->pw = NULL;
  e->accessed = 0;

  if (compute_expiration (e))
    insert_to_timer_list_new (e);

  return 0;
}


struct timespec *
agent_cache_expiration (void)
{
  static struct timespec abstime;
  static struct timespec timeout;
  struct timespec *tp;
  struct timespec curtime;
  int res;
  int expired = 0;
  ITEM e, enext;

  res = npth_mutex_lock (&cache_lock);
  if (res)
    log_fatal ("failed to acquire cache mutex: %s\n", strerror (res));

  npth_clock_gettime (&curtime);
  if (the_timer_list)
    {
      if (npth_timercmp (&abstime, &curtime, <))
        expired = 1;
      else
        npth_timersub (&abstime, &curtime, &timeout);
    }

  if (expired && (e = the_timer_list) && e->t.tv_sec == 0)
    {
      the_timer_list = e->t.next;
      e->t.next = NULL;

      if (do_expire (e))
        {
          ITEM r, rprev;

          if (DBG_CACHE)
            log_debug ("  removed '%s'.%d (mode %d) (slot not used for 30m)\n",
                       e->key, e->restricted, e->cache_mode);

          rprev = NULL;
          for (r = thecache; r; r = r->next)
            if (r == e)
              {
                if (!rprev)
                  thecache = r->next;
                else
                  rprev->next = r->next;
                break;
              }
            else
              rprev = r;

          remove_from_timer_list_new (e);

          xfree (e);
        }
    }

  if (expired || !the_timer_list)
    timeout.tv_sec = timeout.tv_nsec = 0;

  for (e = the_timer_list_new; e; e = enext)
    {
      enext = e->t.next;
      e->t.next = NULL;
      insert_to_timer_list (&timeout, e);
    }
  the_timer_list_new = NULL;

  if (!the_timer_list)
    tp = NULL;
  else
    {
      if (the_timer_list->t.tv_sec != 0)
        {
          timeout.tv_sec += the_timer_list->t.tv_sec;
          the_timer_list->t.tv_sec = 0;
        }

      npth_timeradd (&timeout, &curtime, &abstime);
      tp = &timeout;
    }

  res = npth_mutex_unlock (&cache_lock);
  if (res)
    log_fatal ("failed to release cache mutex: %s\n", strerror (res));

  return tp;
}


void
agent_flush_cache (int pincache_only)
{
  ITEM r;
  int res;

  if (DBG_CACHE)
    log_debug ("agent_flush_cache%s\n", pincache_only?" (pincache only)":"");

  res = npth_mutex_lock (&cache_lock);
  if (res)
    log_fatal ("failed to acquire cache mutex: %s\n", strerror (res));

  for (r=thecache; r; r = r->next)
    {
      if (pincache_only && r->cache_mode != CACHE_MODE_PIN)
        continue;
      if (r->pw)
        {
          if (DBG_CACHE)
            log_debug ("  flushing '%s'.%d\n", r->key, r->restricted);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = 0;
          update_expiration (r, 0);
        }
    }

  res = npth_mutex_unlock (&cache_lock);
  if (res)
    log_fatal ("failed to release cache mutex: %s\n", strerror (res));
}


/* Compare two cache modes.  */
static int
cache_mode_equal (cache_mode_t a, cache_mode_t b)
{
  /* CACHE_MODE_ANY matches any mode other than CACHE_MODE_IGNORE.  */
  return ((a == CACHE_MODE_ANY
           && !(b == CACHE_MODE_IGNORE || b == CACHE_MODE_DATA))
          || (b == CACHE_MODE_ANY
              && !(a == CACHE_MODE_IGNORE || a == CACHE_MODE_DATA))
          || a == b);
}


/* Store the string DATA in the cache under KEY and mark it with a
   maximum lifetime of TTL seconds.  If there is already data under
   this key, it will be replaced.  Using a DATA of NULL deletes the
   entry.  A TTL of 0 is replaced by the default TTL and a TTL of -1
   set infinite timeout.  CACHE_MODE is stored with the cache entry
   and used to select different timeouts.  */
int
agent_put_cache (ctrl_t ctrl, const char *key, cache_mode_t cache_mode,
                 const char *data, int ttl)
{
  gpg_error_t err = 0;
  ITEM r;
  int res;
  int restricted = ctrl? ctrl->restricted : -1;

  res = npth_mutex_lock (&cache_lock);
  if (res)
    log_fatal ("failed to acquire cache mutex: %s\n", strerror (res));

  if (DBG_CACHE)
    log_debug ("agent_put_cache '%s'.%d (mode %d) requested ttl=%d\n",
               key, restricted, cache_mode, ttl);

  if (!ttl)
    {
      switch(cache_mode)
        {
        case CACHE_MODE_SSH: ttl = opt.def_cache_ttl_ssh; break;
        case CACHE_MODE_DATA: ttl = DEF_CACHE_TTL_DATA; break;
        case CACHE_MODE_PIN: ttl = -1; break;
        default: ttl = opt.def_cache_ttl; break;
        }
    }
  if ((!ttl && data) || cache_mode == CACHE_MODE_IGNORE)
    goto out;

  for (r=thecache; r; r = r->next)
    {
      if (cache_mode == CACHE_MODE_PIN && data)
        {
          /* PIN mode is special because it is only used by scdaemon.  */
          if (!strcmp (r->key, key))
            break;
        }
      else if (cache_mode == CACHE_MODE_PIN)
        {
          /* FIXME: Parse the structure of the key and delete several
           * cached PINS.  */
          if (!strcmp (r->key, key))
            break;
        }
      else if (((cache_mode != CACHE_MODE_USER
                 && cache_mode != CACHE_MODE_NONCE)
                || cache_mode_equal (r->cache_mode, cache_mode))
               && r->restricted == restricted
               && !strcmp (r->key, key))
        break;
    }
  if (r) /* Replace.  */
    {
      if (r->pw)
        {
          release_data (r->pw);
          r->pw = NULL;
        }
      if (data)
        {
          r->created = r->accessed = gnupg_get_time ();
          r->ttl = ttl;
          r->cache_mode = cache_mode;
          err = new_data (data, &r->pw);
          if (err)
            log_error ("error replacing cache item: %s\n", gpg_strerror (err));
          update_expiration (r, 0);
        }
    }
  else if (data) /* Insert.  */
    {
      r = xtrycalloc (1, sizeof *r + strlen (key));
      if (!r)
        err = gpg_error_from_syserror ();
      else
        {
          strcpy (r->key, key);
          r->restricted = restricted;
          r->created = r->accessed = gnupg_get_time ();
          r->ttl = ttl;
          r->cache_mode = cache_mode;
          err = new_data (data, &r->pw);
          if (err)
            xfree (r);
          else
            {
              r->next = thecache;
              thecache = r;
              update_expiration (r, 1);
            }
        }
      if (err)
        log_error ("error inserting cache item: %s\n", gpg_strerror (err));
    }

 out:
  res = npth_mutex_unlock (&cache_lock);
  if (res)
    log_fatal ("failed to release cache mutex: %s\n", strerror (res));

  return err;
}


/* Try to find an item in the cache.  Returns NULL if not found or an
 * malloced string with the value.  */
char *
agent_get_cache (ctrl_t ctrl, const char *key, cache_mode_t cache_mode)
{
  gpg_error_t err;
  ITEM r;
  char *value = NULL;
  int res;
  int last_stored = 0;
  int restricted = ctrl? ctrl->restricted : -1;
  int yes;

  if (cache_mode == CACHE_MODE_IGNORE)
    return NULL;

  res = npth_mutex_lock (&cache_lock);
  if (res)
    log_fatal ("failed to acquire cache mutex: %s\n", strerror (res));

  if (!key)
    {
      key = last_stored_cache_key;
      if (!key)
        goto out;
      last_stored = 1;
    }

  if (DBG_CACHE)
    log_debug ("agent_get_cache '%s'.%d (mode %d)%s ...\n",
               key, restricted, cache_mode,
               last_stored? " (stored cache key)":"");

  for (r=thecache; r; r = r->next)
    {
      if (cache_mode == CACHE_MODE_PIN)
        yes = (r->pw && !strcmp (r->key, key));
      else if (r->pw
               && ((cache_mode != CACHE_MODE_USER
                    && cache_mode != CACHE_MODE_NONCE)
                   || cache_mode_equal (r->cache_mode, cache_mode))
               && r->restricted == restricted
               && !strcmp (r->key, key))
        yes = 1;
      else
        yes = 0;

      if (yes)
        {
          /* Note: To avoid races KEY may not be accessed anymore
           * below.  Note also that we don't update the accessed time
           * for data items.  */
          if (r->cache_mode != CACHE_MODE_DATA)
            {
              r->accessed = gnupg_get_time ();
              update_expiration (r, 0);
            }
          if (DBG_CACHE)
            log_debug ("... hit\n");
          if (r->pw->totallen < 32)
            err = gpg_error (GPG_ERR_INV_LENGTH);
          else if ((err = init_encryption ()))
            ;
          else if (!(value = xtrymalloc_secure (r->pw->totallen - 8)))
            err = gpg_error_from_syserror ();
          else
            {
              err = gcry_cipher_decrypt (encryption_handle,
                                         value, r->pw->totallen - 8,
                                         r->pw->data, r->pw->totallen);
            }
          if (err)
            {
              xfree (value);
              value = NULL;
              log_error ("retrieving cache entry '%s'.%d failed: %s\n",
                         key, restricted, gpg_strerror (err));
            }
          break;
        }
    }
  if (DBG_CACHE && value == NULL)
    log_debug ("... miss\n");

 out:
  res = npth_mutex_unlock (&cache_lock);
  if (res)
    log_fatal ("failed to release cache mutex: %s\n", strerror (res));

  return value;
}


/* Store the key for the last successful cache hit.  That value is
   used by agent_get_cache if the requested KEY is given as NULL.
   NULL may be used to remove that key. */
void
agent_store_cache_hit (const char *key)
{
  char *new;
  char *old;

  /* To make sure the update is atomic under the non-preemptive thread
   * model, we must make sure not to surrender control to a different
   * thread.  Therefore, we avoid calling the allocator during the
   * update.
   *
   * Background: xtrystrdup uses gcry_strdup which may use the secure
   * memory allocator of Libgcrypt.  That allocator takes locks and
   * since version 1.14 libgpg-error is nPth aware and thus taking a
   * lock may now lead to thread switch.  Note that this only happens
   * when secure memory is _allocated_ (the standard allocator uses
   * malloc which is not nPth aware) but not when calling _xfree_
   * because gcry_free needs to check whether the pointer is in secure
   * memory and thus needs to take a lock.
   */
  new = key ? xtrystrdup (key) : NULL;

  /* Atomic update.  */
  old = last_stored_cache_key;
  last_stored_cache_key = new;
  /* Done.  */

  xfree (old);
}
