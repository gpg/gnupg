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
#include <assert.h>
#include <npth.h>

#include "agent.h"

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

typedef struct cache_item_s *ITEM;
struct cache_item_s {
  ITEM next;
  time_t created;
  time_t accessed;
  int ttl;  /* max. lifetime given in seconds, -1 one means infinite */
  struct secret_data_s *pw;
  cache_mode_t cache_mode;
  int restricted;  /* The value of ctrl->restricted is part of the key.  */
  char key[1];
};

/* The cache himself.  */
static ITEM thecache;

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



/* Check whether there are items to expire.  */
static void
housekeeping (void)
{
  ITEM r, rprev;
  time_t current = gnupg_get_time ();

  /* First expire the actual data */
  for (r=thecache; r; r = r->next)
    {
      if (r->pw && r->ttl >= 0 && r->accessed + r->ttl < current)
        {
          if (DBG_CACHE)
            log_debug ("  expired '%s'.%d (%ds after last access)\n",
                       r->key, r->restricted, r->ttl);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = current;
        }
    }

  /* Second, make sure that we also remove them based on the created stamp so
     that the user has to enter it from time to time. */
  for (r=thecache; r; r = r->next)
    {
      unsigned long maxttl;

      switch (r->cache_mode)
        {
        case CACHE_MODE_SSH: maxttl = opt.max_cache_ttl_ssh; break;
        default: maxttl = opt.max_cache_ttl; break;
        }
      if (r->pw && r->created + maxttl < current)
        {
          if (DBG_CACHE)
            log_debug ("  expired '%s'.%d (%lus after creation)\n",
                       r->key, r->restricted, opt.max_cache_ttl);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = current;
        }
    }

  /* Third, make sure that we don't have too many items in the list.
   * Expire old and unused entries after 30 minutes.  */
  for (rprev=NULL, r=thecache; r; )
    {
      if (!r->pw && r->ttl >= 0 && r->accessed + 60*30 < current)
        {
          ITEM r2 = r->next;
          if (DBG_CACHE)
            log_debug ("  removed '%s'.%d (mode %d) (slot not used for 30m)\n",
                       r->key, r->restricted, r->cache_mode);
          xfree (r);
          if (!rprev)
            thecache = r2;
          else
            rprev->next = r2;
          r = r2;
        }
      else
        {
          rprev = r;
          r = r->next;
        }
    }
}


void
agent_cache_housekeeping (void)
{
  int res;

  if (DBG_CACHE)
    log_debug ("agent_cache_housekeeping\n");

  res = npth_mutex_lock (&cache_lock);
  if (res)
    log_fatal ("failed to acquire cache mutex: %s\n", strerror (res));

  housekeeping ();

  res = npth_mutex_unlock (&cache_lock);
  if (res)
    log_fatal ("failed to release cache mutex: %s\n", strerror (res));
}


void
agent_flush_cache (void)
{
  ITEM r;
  int res;

  if (DBG_CACHE)
    log_debug ("agent_flush_cache\n");

  res = npth_mutex_lock (&cache_lock);
  if (res)
    log_fatal ("failed to acquire cache mutex: %s\n", strerror (res));

  for (r=thecache; r; r = r->next)
    {
      if (r->pw)
        {
          if (DBG_CACHE)
            log_debug ("  flushing '%s'.%d\n", r->key, r->restricted);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = 0;
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
  return ((a == CACHE_MODE_ANY && b != CACHE_MODE_IGNORE)
          || (b == CACHE_MODE_ANY && a != CACHE_MODE_IGNORE) || a == b);
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
  housekeeping ();

  if (!ttl)
    {
      switch(cache_mode)
        {
        case CACHE_MODE_SSH: ttl = opt.def_cache_ttl_ssh; break;
        default: ttl = opt.def_cache_ttl; break;
        }
    }
  if ((!ttl && data) || cache_mode == CACHE_MODE_IGNORE)
    goto out;

  for (r=thecache; r; r = r->next)
    {
      if (((cache_mode != CACHE_MODE_USER
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


/* Try to find an item in the cache.  Note that we currently don't
   make use of CACHE_MODE except for CACHE_MODE_NONCE and
   CACHE_MODE_USER.  */
char *
agent_get_cache (ctrl_t ctrl, const char *key, cache_mode_t cache_mode)
{
  gpg_error_t err;
  ITEM r;
  char *value = NULL;
  int res;
  int last_stored = 0;
  int restricted = ctrl? ctrl->restricted : -1;

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
               key, ctrl->restricted, cache_mode,
               last_stored? " (stored cache key)":"");
  housekeeping ();

  for (r=thecache; r; r = r->next)
    {
      if (r->pw
          && ((cache_mode != CACHE_MODE_USER
               && cache_mode != CACHE_MODE_NONCE)
              || cache_mode_equal (r->cache_mode, cache_mode))
          && r->restricted == restricted
          && !strcmp (r->key, key))
        {
          /* Note: To avoid races KEY may not be accessed anymore below.  */
          r->accessed = gnupg_get_time ();
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
