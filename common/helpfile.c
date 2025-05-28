/* helpfile.c - GnuPG's helpfile feature
 *	Copyright (C) 2007 Free Software Foundation, Inc.
 *	Copyright (C) 2011,2012, 2025 g10 Code GmbH
 *
 * This file is part of GnuPG.
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
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#include <config.h>
#include <stdlib.h>


#include "util.h"
#include "i18n.h"
#include "membuf.h"


/* Try to find KEY in the file FNAME.  */
static char *
findkey_fname (const char *key, const char *fname, unsigned int flags)
{
  gpg_error_t err = 0;
  estream_t fp;
  int lnr = 0;
  int c;
  char *p, line[256];
  int in_item = 0;
  membuf_t mb = MEMBUF_ZERO;

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      if (errno != ENOENT)
        {
          err = gpg_error_from_syserror ();
          log_error (_("can't open '%s': %s\n"), fname, gpg_strerror (err));
        }
      return NULL;
    }

  while (es_fgets (line, DIM(line)-1, fp))
    {
      lnr++;

      if (!*line || line[strlen(line)-1] != '\n')
        {
          /* Eat until end of line. */
          while ((c = es_getc (fp)) != EOF && c != '\n')
            ;
          err = gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                           : GPG_ERR_INCOMPLETE_LINE);
          log_error (_("file '%s', line %d: %s\n"),
                     fname, lnr, gpg_strerror (err));
        }
      else
        line[strlen(line)-1] = 0; /* Chop the LF. */

    again:
      if (!in_item)
        {
          /* Allow for empty lines and spaces while not in an item. */
          for (p=line; spacep (p); p++)
            ;
          if (!*p || *p == '#')
            continue;
          if (*line != '.' || spacep(line+1))
            {
              log_info (_("file '%s', line %d: %s\n"),
                        fname, lnr, _("ignoring garbage line"));
              continue;
            }
          trim_trailing_spaces (line);
          in_item = 1;
          if (!strcmp (line+1, key))
            {
              /* Found.  Start collecting.  */
              init_membuf (&mb, 1024);
            }
          continue;
        }

      /* If in an item only allow for comments in the first column
         and provide ". " as an escape sequence to allow for
         leading dots and hash marks in the actual text.  */
      if (*line == '#')
        continue;
      if (*line == '.')
        {
          if (spacep(line+1))
            p = line + 2;
          else
            {
              trim_trailing_spaces (line);
              in_item = 0;
              if (is_membuf_ready (&mb))
                break;        /* Yep, found and collected the item.  */
              if (!line[1])
                continue;     /* Just an end of text dot. */
              goto again;     /* A new key line.  */
            }
        }
      else
        p = line;

      if (is_membuf_ready (&mb))
        {
          put_membuf_str (&mb, p);
          if ((flags & GET_TEMPLATE_CRLF))
            put_membuf (&mb, "\r\n", 2);
          else
            put_membuf (&mb, "\n", 1);
        }

    }
  if ( !err && es_ferror (fp) )
    {
      err = gpg_error_from_syserror ();
      log_error (_("error reading '%s', line %d: %s\n"),
                 fname, lnr, gpg_strerror (err));
    }

  es_fclose (fp);
  if (is_membuf_ready (&mb))
    {
      /* We have collected something.  */
      if (err)
        {
          xfree (get_membuf (&mb, NULL));
          return NULL;
        }
      else
        {
          put_membuf (&mb, "", 1);  /* Terminate string.  */
          return get_membuf (&mb, NULL);
        }
    }
  else
    return NULL;
}


/* Try the help files depending on the locale.  */
static char *
findkey_locale (const char *domain, const char *key, const char *locname,
                const char *dirname, unsigned int flags)
{
  const char *s;
  char *fname, *ext, *p;
  char *result;

  fname = xtrymalloc (strlen (dirname) + 2
                      + strlen (domain) + strlen (locname) + 4 + 1);
  if (!fname)
    return NULL;
  ext = stpcpy (stpcpy (stpcpy (stpcpy (fname, dirname), "/"), domain), ".");
  /* Search with locale name and territory.  ("help.LL_TT.txt") */
  if (strchr (locname, '_'))
    {
      strcpy (stpcpy (ext, locname), ".txt");
      result = findkey_fname (key, fname, flags);
    }
  else
    result = NULL;  /* No territory.  */

  if (!result)
    {
      /* Search with just the locale name - if any. ("help.LL.txt") */
      if (*locname)
        {
          for (p=ext, s=locname; *s && *s != '_';)
            *p++ = *s++;
          strcpy (p, ".txt");
          result = findkey_fname (key, fname, flags);
        }
      else
        result = NULL;
    }

  if (!result && (!(flags & GET_TEMPLATE_CURRENT_LOCALE) || !*locname))
    {
      /* Last try: Search in file without any locale info.  ("help.txt") */
      strcpy (ext, "txt");
      result = findkey_fname (key, fname, flags);
    }

  xfree (fname);
  return result;
}


/* Return a malloced text as identified by KEY.  The system takes
   the string from an UTF-8 encoded file to be created by an
   administrator or as distributed with GnuPG.  On a GNU or Unix
   system the entry is searched in these files:

     /etc/gnupg/<domain>.<LL>.txt
     /etc/gnupg/<domain>.txt
     /usr/share/gnupg/<domain>.<LL>.txt
     /usr/share/gnupg/<domain>.txt

   The <domain> is either "help" or any other domain like "mail-tube".
   Here <LL> denotes the two digit language code of the current
   locale.  If the flag bit GET_TEMPLATE_CURRENT_LOCALE is set, the
   function won't fallback to the english valiant ("<domain>.txt")
   unless that locale has been requested.

   The template file needs to be encoded in UTF-8, lines with a '#' in the
   first column are comment lines and entirely ignored.  Help keys are
   identified by a key consisting of a single word with a single dot
   as the first character.  All key lines listed without any
   intervening lines (except for comment lines) lead to the same help
   text.  Lines following the key lines make up the actual template texts.
*/

char *
gnupg_get_template (const char *domain, const char *key, unsigned int flags)
{
  static const char *locname;
  char *result;

  if (!locname)
    {
      char *buffer, *p;
      int count = 0;
      const char *s = gnupg_messages_locale_name ();
      buffer = xtrystrdup (s);
      if (!buffer)
        locname = "";
      else
        {
          for (p = buffer; *p; p++)
            if (*p == '.' || *p == '@' || *p == '/' /*(safeguard)*/)
              *p = 0;
            else if (*p == '_')
              {
                if (count++)
                  *p = 0;  /* Also cut at an underscore in the territory.  */
              }
          locname = buffer;
        }
    }

  if (!key || !*key)
    return NULL;

  result = findkey_locale (domain, key, locname,
                           gnupg_sysconfdir (), flags);
  if (!result)
    result = findkey_locale (domain, key, locname,
                             gnupg_datadir (), flags);

  if (result && (flags & GET_TEMPLATE_SUBST_ENVVARS))
    {
      char *tmp = substitute_envvars (result);
      if (tmp)
        {
          xfree (result);
          result = tmp;
        }
    }

  if (result && !(flags & GET_TEMPLATE_CRLF))
    trim_trailing_spaces (result);

  return result;
}


char *
gnupg_get_help_string (const char *key, int only_current)
{
  return gnupg_get_template ("help", key,
                             only_current? GET_TEMPLATE_CURRENT_LOCALE : 0);
}
