/* server-help.h - Helper functions for writing Assuan servers.
 *	Copyright (C) 2003, 2009, 2010 g10 Code GmbH
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
 */

#include <config.h>
#include <string.h>

#include "util.h"
#include "server-help.h"


static GPGRT_INLINE gpg_error_t
my_error (int e)
{
  return gpg_err_make (default_errsource, (e));
}

static GPGRT_INLINE gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}


/* Skip over options in LINE.

   Blanks after the options are also removed.  Options are indicated
   by two leading dashes followed by a string consisting of non-space
   characters.  The special option "--" indicates an explicit end of
   options; all what follows will not be considered an option.  The
   first no-option string also indicates the end of option parsing. */
char *
skip_options (const char *line)
{
  while (spacep (line))
    line++;
  while (*line == '-' && line[1] == '-')
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  return (char*) line;
}


/* Check whether the option NAME appears in LINE.  */
int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  if (s && s >= skip_options (line))
    return 0;
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}


/* Same as has_option but only considers options at the begin of the
   line.  This is useful for commands which allow arbitrary strings on
   the line.  */
int
has_leading_option (const char *line, const char *name)
{
  const char *s;
  int n;

  if (name[0] != '-' || name[1] != '-' || !name[2] || spacep (name+2))
    return 0;
  n = strlen (name);
  while ( *line == '-' && line[1] == '-' )
    {
      s = line;
      while (*line && !spacep (line))
        line++;
      if (n == (line - s) && !strncmp (s, name, n))
        return 1;
      while (spacep (line))
        line++;
    }
  return 0;
}


/* Same as has_option but does only test for the name of the option
   and ignores an argument, i.e. with NAME being "--hash" it would
   return a pointer for "--hash" as well as for "--hash=foo".  If
   there is no such option NULL is returned.  The pointer returned
   points right behind the option name, this may be an equal sign, Nul
   or a space.  */
const char *
has_option_name (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1))
          && (!s[n] || spacep (s+n) || s[n] == '=')) ? (s+n) : NULL;
}


/* Parse an option with the format "--NAME=VALUE" which must occur in
 * LINE before a double-dash.  LINE is written to but not modified by
 * this function.  If the option is found and has a value the value is
 * stored as a malloced string at R_VALUE.  If the option was not
 * found or an error occurred NULL is stored there.  Note that
 * currently the value must be a string without any space; we may
 * eventually update this function to allow for a quoted value.  */
gpg_error_t
get_option_value (char *line, const char *name, char **r_value)
{
  char *p, *pend;
  int c;

  *r_value = NULL;

  p = (char*)has_option_name (line, name);
  if (!p || p >= skip_options (line))
    return 0;

  if (*p != '=' || !p[1] || spacep (p+1))
    return my_error (GPG_ERR_INV_ARG);
  p++;
  for (pend = p; *pend && !spacep (pend); pend++)
    ;
  c = *pend;
  *pend = 0;
  *r_value = xtrystrdup (p);
  *pend = c;
  if (!p)
    return my_error_from_syserror ();
  return 0;
}


/* Return a pointer to the argument of the option with NAME.  If such
   an option is not given, NULL is returned. */
char *
option_value (const char *line, const char *name)
{
  char *s;
  int n = strlen (name);

  s = strstr (line, name);
  if (s && s >= skip_options (line))
    return NULL;
  if (s && (s == line || spacep (s-1))
      && s[n] && (spacep (s+n) || s[n] == '='))
    {
      s += n + 1;
      s += strspn (s, " ");
      if (*s && !spacep(s))
        return s;
    }
  return NULL;
}
