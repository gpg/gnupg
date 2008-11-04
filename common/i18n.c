/* i18n.c - gettext initialization
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "util.h"
#include "i18n.h"


void
i18n_init (void)
{
#ifdef USE_SIMPLE_GETTEXT
  bindtextdomain (PACKAGE_GT, gnupg_localedir ());
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
  gettext_select_utf8 (1);
  return NULL;
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
  (void)saved_codeset;
  gettext_select_utf8 (0);
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
