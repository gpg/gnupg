/* i18n.c - gettext initialization
 * Copyright (C) 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "util.h"
#include "i18n.h"


#undef USE_MSGCACHE
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES) \
   && !defined(USE_SIMPLE_GETTEXT) && defined(ENABLE_NLS)
# define USE_MSGCACHE 1
#endif


#ifdef USE_MSGCACHE
/* An object to store pointers to static strings and their static
   translations.  A linked list is not optimal but given that we only
   have a few dozen messages it should be acceptable. */
struct msg_cache_s
{
  struct msg_cache_s *next;
  const char *key;
  const char *value;
};

/* A object to store an lc_messages string and a link to the cache
   object.  */
struct msg_cache_heads_s
{
  struct msg_cache_heads_s *next;
  struct msg_cache_s *cache;
  char lc_messages[1];
};

/* Out static cache of translated messages.  We need this because
   there is no gettext API to return a translation depending on the
   locale.  Switching the locale for each access to a translatable
   string seems to be too expensive.  Note that this is used only for
   strings in gpg-agent which are passed to Pinentry.  All other
   strings are using the regular gettext interface.  Note that we can
   never release this memory because consumers take the result as
   static strings.  */
static struct msg_cache_heads_s *msgcache;

#endif /*USE_MSGCACHE*/


void
i18n_init (void)
{
#ifdef USE_SIMPLE_GETTEXT
  bindtextdomain (PACKAGE_GT, gnupg_localedir ());
  textdomain (PACKAGE_GT);
#else
# ifdef ENABLE_NLS
  setlocale (LC_ALL, "" );
  bindtextdomain (PACKAGE_GT, LOCALEDIR);
  textdomain (PACKAGE_GT);
# endif
#endif
}


/* The Assuan agent protocol requires us to transmit utf-8 strings
   thus we need a way to temporary switch gettext from native to
   utf8.  */
char *
i18n_switchto_utf8 (void)
{
#ifdef USE_SIMPLE_GETTEXT
  /* Return an arbitrary pointer as true value.  */
  return gettext_use_utf8 (1) ? (char*)(-1) : NULL;
#elif defined(ENABLE_NLS)
  char *orig_codeset = bind_textdomain_codeset (PACKAGE_GT, NULL);
# ifdef HAVE_LANGINFO_CODESET
  if (!orig_codeset)
    orig_codeset = nl_langinfo (CODESET);
# endif
  if (orig_codeset)
    { /* We only switch when we are able to restore the codeset later.
         Note that bind_textdomain_codeset does only return on memory
         errors but not if a codeset is not available.  Thus we don't
         bother printing a diagnostic here. */
      orig_codeset = xstrdup (orig_codeset);
      if (!bind_textdomain_codeset (PACKAGE_GT, "utf-8"))
        {
	  xfree (orig_codeset);
	  orig_codeset = NULL;
	}
    }
  return orig_codeset;
#else
  return NULL;
#endif
}

/* Switch back to the saved codeset.  */
void
i18n_switchback (char *saved_codeset)
{
#ifdef USE_SIMPLE_GETTEXT
  gettext_use_utf8 (!!saved_codeset);
#elif defined(ENABLE_NLS)
  if (saved_codeset)
    {
      bind_textdomain_codeset (PACKAGE_GT, saved_codeset);
      xfree (saved_codeset);
    }
#else
  (void)saved_codeset;
#endif
}


/* Gettext variant which temporary switches to utf-8 for string. */
const char *
i18n_utf8 (const char *string)
{
  char *saved = i18n_switchto_utf8 ();
  const char *result = _(string);
  i18n_switchback (saved);
  return result;
}


/* A variant of gettext which allows the programmer to specify the
   locale to use for translating the message.  The function assumes
   that utf-8 is used for the encoding.  */
const char *
i18n_localegettext (const char *lc_messages, const char *string)
{
#if USE_MSGCACHE
  const char *result = NULL;
  char *saved = NULL;
  struct msg_cache_heads_s *mh;
  struct msg_cache_s *mc;

  if (!lc_messages)
    goto leave;

  /* Lookup in the cache.  */
  for (mh = msgcache; mh; mh = mh->next)
    if (!strcmp (mh->lc_messages, lc_messages))
      break;
  if (mh)
    {
      /* A cache entry for this local exists - find the string.
         Because the system is designed for static strings it is
         sufficient to compare the pointers.  */
      for (mc = mh->cache; mc; mc = mc->next)
        if (mc->key == string)
          {
            /* Cache hit.  */
            result = mc->value;
            goto leave;
          }
    }

  /* Cached miss.  Change the locale, translate, reset locale.  */
  saved = setlocale (LC_MESSAGES, NULL);
  if (!saved)
    goto leave;
  saved = xtrystrdup (saved);
  if (!saved)
    goto leave;
  if (!setlocale (LC_MESSAGES, lc_messages))
    goto leave;

  bindtextdomain (PACKAGE_GT, LOCALEDIR);
  result = gettext (string);
  setlocale (LC_MESSAGES, saved);
  bindtextdomain (PACKAGE_GT, LOCALEDIR);

  /* Cache the result.  */
  if (!mh)
    {
      /* First use of this locale - create an entry.  */
      mh = xtrymalloc (sizeof *mh + strlen (lc_messages));
      if (!mh)
        goto leave;
      strcpy (mh->lc_messages, lc_messages);
      mh->cache = NULL;
      mh->next = msgcache;
      msgcache = mh;
    }
  mc = xtrymalloc (sizeof *mc);
  if (!mc)
    goto leave;
  mc->key = string;
  mc->value = result;
  mc->next = mh->cache;
  mh->cache = mc;

 leave:
  xfree (saved);
  return result? result : _(string);

#else /*!USE_MSGCACHE*/

  (void)lc_messages;
  return _(string);

#endif /*!USE_MSGCACHE*/
}
