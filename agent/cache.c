/* cache.c - keep a cache of passphrases
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
  int  ttl;  /* max. lifetime given in seonds */
  struct secret_data_s *pw;
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

  d = gcry_malloc_secure (sizeof d + total - 1);
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
  time_t current = time (NULL);

  /* first expire the actual data */
  for (r=thecache; r; r = r->next)
    {
      if (r->pw && r->accessed + r->ttl < current)
        {
          if (DBG_CACHE)
            log_debug ("  expired `%s' (%ds after last access)\n",
                       r->key, r->ttl);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = current;
        }
    }

  /* second, make sure that we also remove them based on the created stamp so
     that the used has to enter it from time to time.  We do this every hour */
  for (r=thecache; r; r = r->next)
    {
      if (r->pw && r->created + 60*60 < current)
        {
          if (DBG_CACHE)
            log_debug ("  expired `%s' (1h after creation)\n", r->key);
          release_data (r->pw);
          r->pw = NULL;
          r->accessed = current;
        }
    }

  /* third, make sure that we don't have too many items in the list.
     Expire old and unused entries after 30 minutes */
  for (rprev=NULL, r=thecache; r; )
    {
      if (!r->pw && r->accessed + 60*30 < current)
        {
          ITEM r2 = r->next;
          if (DBG_CACHE)
            log_debug ("  removed `%s' (slot not used for 30m)\n", r->key);
          xfree (r);
          if (!rprev)
            thecache = r2;
          else
            rprev = r2;
          r = r2;
        }
      else
        {
          rprev = r;
          r = r->next;
        }
    }
}



/* Store DATA of length DATALEN in the cache under KEY and mark it
   with a maximum lifetime of TTL seconds.  If tehre is already data
   under this key, it will be replaced.  Using a DATA of NULL deletes
   the entry */
int
agent_put_cache (const char *key, const char *data, int ttl)
{
  ITEM r;

  if (DBG_CACHE)
    log_debug ("agent_put_cache `%s'\n", key);
  housekeeping ();

  if (ttl < 1)
    ttl = 60*5; /* default is 5 minutes */

  for (r=thecache; r; r = r->next)
    {
      if ( !strcmp (r->key, key))
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
          r->created = r->accessed = time (NULL); 
          r->ttl = ttl;
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


/* Try to find an item in the cache */
const char *
agent_get_cache (const char *key)
{
  ITEM r;
  int count = 0;

  if (DBG_CACHE)
    log_debug ("agent_get_cache `%s'...\n", key);
  housekeeping ();

  /* FIXME: Returning pointers is not thread safe - add a referencense
     counter */
  for (r=thecache; r; r = r->next, count++)
    {
      if (r->pw && !strcmp (r->key, key))
        {
          /* put_cache does only put strings into the cache, so we
             don't need the lengths */
          r->accessed = time (NULL);
          if (DBG_CACHE)
            log_debug ("... hit\n");
          return r->pw->data;
        }
    }
  if (DBG_CACHE)
    log_debug ("... miss\n");

  return NULL;
}



