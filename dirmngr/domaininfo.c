/* domaininfo.c - Gather statistics about accessed domains
 * Copyright (C) 2017 Werner Koch
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
 *
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "dirmngr.h"


/* Number of bucket for the hash array and limit for the length of a
 * bucket chain.  For debugging values of 13 and 10 are more suitable
 * and a command like
 *   for j   in a b c d e f g h i j k l m n o p q r s t u v w z y z; do \
 *     for i in a b c d e f g h i j k l m n o p q r s t u v w z y z; do \
 *       gpg-connect-agent --dirmngr "wkd_get foo@$i.$j.gnupg.net" /bye \
 *       >/dev/null ; done; done
 * will quickly add a couple of domains.
 */
#define NO_OF_DOMAINBUCKETS  103
#define MAX_DOMAINBUCKET_LEN  20


/* Object to keep track of a domain name.  */
struct domaininfo_s
{
  struct domaininfo_s *next;
  unsigned int no_name:1;            /* Domain name not found.            */
  unsigned int wkd_not_found:1;      /* A WKD query failed.               */
  unsigned int wkd_supported:1;      /* One WKD entry was found.          */
  unsigned int wkd_not_supported:1;  /* Definitely does not support WKD.  */
  char name[1];
};
typedef struct domaininfo_s *domaininfo_t;

/* And the hashed array.  */
static domaininfo_t domainbuckets[NO_OF_DOMAINBUCKETS];


/* The hash function we use.  Must not call a system function.  */
static inline u32
hash_domain (const char *domain)
{
  const unsigned char *s = (const unsigned char*)domain;
  u32 hashval = 0;
  u32 carry;

  for (; *s; s++)
    {
      if (*s == '.')
        continue;
      hashval = (hashval << 4) + *s;
      if ((carry = (hashval & 0xf0000000)))
        {
          hashval ^= (carry >> 24);
          hashval ^= carry;
        }
    }

  return hashval % NO_OF_DOMAINBUCKETS;
}


void
domaininfo_print_stats (void)
{
  int bidx;
  domaininfo_t di;
  int count, no_name, wkd_not_found, wkd_supported, wkd_not_supported;
  int len, minlen, maxlen;

  count = no_name = wkd_not_found = wkd_supported = wkd_not_supported = 0;
  maxlen = 0;
  minlen = -1;
  for (bidx = 0; bidx < NO_OF_DOMAINBUCKETS; bidx++)
    {
      len = 0;
      for (di = domainbuckets[bidx]; di; di = di->next)
        {
          count++;
          len++;
          if (di->no_name)
            no_name++;
          if (di->wkd_not_found)
            wkd_not_found++;
          if (di->wkd_supported)
            wkd_supported++;
          if (di->wkd_not_supported)
            wkd_not_supported++;
        }
      if (len > maxlen)
        maxlen = len;
      if (minlen == -1 || len < minlen)
        minlen = len;
    }
  log_info ("domaininfo: items=%d chainlen=%d..%d nn=%d nf=%d ns=%d s=%d\n",
            count,
            minlen > 0? minlen : 0,
            maxlen,
            no_name, wkd_not_found, wkd_not_supported, wkd_supported);
}


/* Return true if DOMAIN definitely does not support WKD.  Noet that
 * DOMAIN is expected to be lowercase.  */
int
domaininfo_is_wkd_not_supported (const char *domain)
{
  domaininfo_t di;

  for (di = domainbuckets[hash_domain (domain)]; di; di = di->next)
    if (!strcmp (di->name, domain))
      return !!di->wkd_not_supported;

  return 0;  /* We don't know.  */
}


/* Core update function.  DOMAIN is expected to be lowercase.
 * CALLBACK is called to update the existing or the newly inserted
 * item.  */
static void
insert_or_update (const char *domain,
                  void (*callback)(domaininfo_t di, int insert_mode))
{
  domaininfo_t di;
  domaininfo_t di_new;
  domaininfo_t di_cut;
  u32 hash;
  int count;

  hash = hash_domain (domain);
  for (di = domainbuckets[hash]; di; di = di->next)
    if (!strcmp (di->name, domain))
      {
        callback (di, 0);  /* Update */
        return;
      }

  di_new = xtrycalloc (1, sizeof *di + strlen (domain));
  if (!di_new)
    return;  /* Out of core - we ignore this.  */
  strcpy (di_new->name, domain);

  /* Need to do another lookup because the malloc is a system call and
   * thus the hash array may have been changed by another thread.  */
  di_cut = NULL;
  for (count=0, di = domainbuckets[hash]; di; di = di->next, count++)
    if (!strcmp (di->name, domain))
      {
        callback (di, 0);  /* Update */
        xfree (di_new);
        return;
      }

  /* Before we insert we need to check whether the chain gets too long.  */
  di_cut = NULL;
  if (count >= MAX_DOMAINBUCKET_LEN)
    {
      for (count=0, di = domainbuckets[hash]; di; di = di->next, count++)
        if (count >= MAX_DOMAINBUCKET_LEN/2)
          {
            di_cut = di->next;
            di->next = NULL;
            break;
          }
    }

  /* Insert */
  callback (di_new, 1);
  di = di_new;
  di->next = domainbuckets[hash];
  domainbuckets[hash] = di;

  /* Remove the rest of the cutted chain.  */
  while (di_cut)
    {
      di = di_cut->next;
      xfree (di_cut);
      di_cut = di;
    }
}


/* Helper for domaininfo_set_no_name.  */
static void
set_no_name_cb (domaininfo_t di, int insert_mode)
{
  (void)insert_mode;

  di->no_name = 1;
  /* Obviously the domain is in this case also not supported.  */
  di->wkd_not_supported = 1;

  /* The next should already be 0 but we clear it anyway in the case
   * of a temporary DNS failure.  */
  di->wkd_supported = 0;
}


/* Mark DOMAIN as not existent.  */
void
domaininfo_set_no_name (const char *domain)
{
  insert_or_update (domain, set_no_name_cb);
}


/* Helper for domaininfo_set_wkd_supported.  */
static void
set_wkd_supported_cb (domaininfo_t di, int insert_mode)
{
  (void)insert_mode;

  di->wkd_supported = 1;
  /* The next will already be set unless the domain enabled WKD in the
   * meantime.  Thus we need to clear it.  */
  di->wkd_not_supported = 0;
}


/* Mark DOMAIN as supporting WKD.  */
void
domaininfo_set_wkd_supported (const char *domain)
{
  insert_or_update (domain, set_wkd_supported_cb);
}


/* Helper for domaininfo_set_wkd_not_supported.  */
static void
set_wkd_not_supported_cb (domaininfo_t di, int insert_mode)
{
  (void)insert_mode;

  di->wkd_not_supported = 1;
  di->wkd_supported = 0;
}


/* Mark DOMAIN as not supporting WKD queries (e.g. no policy file).  */
void
domaininfo_set_wkd_not_supported (const char *domain)
{
  insert_or_update (domain, set_wkd_not_supported_cb);
}



/* Helper for domaininfo_set_wkd_not_found.  */
static void
set_wkd_not_found_cb (domaininfo_t di, int insert_mode)
{
  /* Set the not found flag but there is no need to do this if we
   * already know that the domain either does not support WKD or we
   * know that it supports WKD.  */
  if (insert_mode)
    di->wkd_not_found = 1;
  else if (!di->wkd_not_supported && !di->wkd_supported)
    di->wkd_not_found = 1;

  /* Better clear this flag in case we had a DNS failure in the
   * past.  */
  di->no_name = 0;
}


/* Update a counter for DOMAIN to keep track of failed WKD queries.  */
void
domaininfo_set_wkd_not_found (const char *domain)
{
  insert_or_update (domain, set_wkd_not_found_cb);
}
