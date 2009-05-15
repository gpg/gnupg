/* cache.c - keep a cache of passphrases
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "agent.h"

struct secret_data_s {
  int  totallen; /* this includes the padding */
  int  datalen;  /* actual data length */
  char data[1];
};

typedef struct cache_item_s *ITEM;
struct cache_item_s {
  ITEM next;
  time_t created;
  time_t accessed;
  int ttl;  /* max. lifetime given in seconds, -1 one means infinite */
  int lockcount;
  struct secret_data_s *pw;
  cache_mode_t cache_mode;
  char key[1];
};


static ITEM thecache;


static void
release_data (struct secret_data_s *data)
{
   xfree (data);
}

static struct secret_data_s *
new_data (const void *data, size_t length)
{
  struct secret_data_s *d;
  int total;

  /* we pad the data to 32 bytes so that it get more complicated
     finding something out by watching allocation patterns.  This is
     usally not possible but we better assume nothing about our
     secure storage provider*/
  total = length + 32 - (length % 32);

  d = gcry_malloc_secure (sizeof *d + total - 1);
  if (d)
    {
      d->totallen = total;
      d->datalen  = length;
      memcpy (d->data, data, length);
    }
  return d;
}



/* check whether there are items to expire */
static void
housekeeping (void)
{
  ITEM r, rprev;
  time_t current = gnupg_get_time ();

  /* First expire the actual data */
  for (r=thecache; r; r = r->next)
    {
      if (!r->lockcount && r->pw
	  && r->ttl >= 0 && r->accessed + r->ttl < current)
        {
          if (DBG_CACHE)
            log_debug ("  expired `%s' (%ds after last access)\n",
                       r->key, r->ttl);
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
      if (!r->lockcount && r->pw && r->created + maxttl < current)
        {
          if (DBG_CACHE)
            log_debug ("  expired `%s' (%lus after creation)\n",
                       r->key, opt.max_cache_ttl);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = current;
        }
    }

  /* Third, make sure that we don't have too many items in the list.
     Expire old and unused entries after 30 minutes */
  for (rprev=NULL, r=thecache; r; )
    {
      if (!r->pw && r->ttl >= 0 && r->accessed + 60*30 < current)
        {
          if (r->lockcount)
            {
              log_error ("can't remove unused cache entry `%s' due to"
                         " lockcount=%d\n",
                         r->key, r->lockcount);
              r->accessed += 60*10; /* next error message in 10 minutes */
              rprev = r;
              r = r->next;
            }
          else
            {
              ITEM r2 = r->next;
              if (DBG_CACHE)
                log_debug ("  removed `%s' (slot not used for 30m)\n", r->key);
              xfree (r);
              if (!rprev)
                thecache = r2;
              else
                rprev->next = r2;
              r = r2;
            }
        }
      else
        {
          rprev = r;
          r = r->next;
        }
    }
}


void
agent_flush_cache (void)
{
  ITEM r;

  if (DBG_CACHE)
    log_debug ("agent_flush_cache\n");

  for (r=thecache; r; r = r->next)
    {
      if (!r->lockcount && r->pw)
        {
          if (DBG_CACHE)
            log_debug ("  flushing `%s'\n", r->key);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = 0;
        }
      else if (r->lockcount && r->pw)
        {
          if (DBG_CACHE)
            log_debug ("    marked `%s' for flushing\n", r->key);
          r->accessed = 0;
          r->ttl = 0;
        }
    }
}



/* Store DATA of length DATALEN in the cache under KEY and mark it
   with a maximum lifetime of TTL seconds.  If there is already data
   under this key, it will be replaced.  Using a DATA of NULL deletes
   the entry.  A TTL of 0 is replaced by the default TTL and a TTL of
   -1 set infinite timeout.  CACHE_MODE is stored with the cache entry
   and used to select different timeouts.  */
int
agent_put_cache (const char *key, cache_mode_t cache_mode,
                 const char *data, int ttl)
{
  ITEM r;

  if (DBG_CACHE)
    log_debug ("agent_put_cache `%s' requested ttl=%d mode=%d\n",
               key, ttl, cache_mode);
  housekeeping ();

  if (!ttl)
    {
      switch(cache_mode)
        {
        case CACHE_MODE_SSH: ttl = opt.def_cache_ttl_ssh; break;
        default: ttl = opt.def_cache_ttl; break;
        }
    }
  if (!ttl || cache_mode == CACHE_MODE_IGNORE)
    return 0;

  for (r=thecache; r; r = r->next)
    {
      if (!r->lockcount && !strcmp (r->key, key))
        break;
    }
  if (r)
    { /* replace */
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
          r->pw = new_data (data, strlen (data)+1);
          if (!r->pw)
            log_error ("out of core while allocating new cache item\n");
        }
    }
  else if (data)
    { /* simply insert */
      r = xtrycalloc (1, sizeof *r + strlen (key));
      if (!r)
        log_error ("out of core while allocating new cache control\n");
      else
        {
          strcpy (r->key, key);
          r->created = r->accessed = gnupg_get_time (); 
          r->ttl = ttl;
          r->cache_mode = cache_mode;
          r->pw = new_data (data, strlen (data)+1);
          if (!r->pw)
            {
              log_error ("out of core while allocating new cache item\n");
              xfree (r);
            }
          else
            {
              r->next = thecache;
              thecache = r;
            }
        }
    }
  return 0;
}


/* Try to find an item in the cache.  Note that we currently don't
   make use of CACHE_MODE.  */
const char *
agent_get_cache (const char *key, cache_mode_t cache_mode, void **cache_id)
{
  ITEM r;

  if (cache_mode == CACHE_MODE_IGNORE)
    return NULL;

  if (DBG_CACHE)
    log_debug ("agent_get_cache `%s'...\n", key);
  housekeeping ();

  /* first try to find one with no locks - this is an updated cache
     entry: We might have entries with a lockcount and without a
     lockcount. */
  for (r=thecache; r; r = r->next)
    {
      if (!r->lockcount && r->pw && !strcmp (r->key, key))
        {
          /* put_cache does only put strings into the cache, so we
             don't need the lengths */
          r->accessed = gnupg_get_time ();
          if (DBG_CACHE)
            log_debug ("... hit\n");
          r->lockcount++;
          *cache_id = r;
          return r->pw->data;
        }
    }
  /* again, but this time get even one with a lockcount set */
  for (r=thecache; r; r = r->next)
    {
      if (r->pw && !strcmp (r->key, key))
        {
          r->accessed = gnupg_get_time ();
          if (DBG_CACHE)
            log_debug ("... hit (locked)\n");
          r->lockcount++;
          *cache_id = r;
          return r->pw->data;
        }
    }
  if (DBG_CACHE)
    log_debug ("... miss\n");

  *cache_id = NULL;
  return NULL;
}


void
agent_unlock_cache_entry (void **cache_id)
{
  ITEM r;

  for (r=thecache; r; r = r->next)
    {
      if (r == *cache_id)
        {
          if (!r->lockcount)
            log_error ("trying to unlock non-locked cache entry `%s'\n",
                       r->key);
          else
            r->lockcount--;
          return;
        }
    }
}
