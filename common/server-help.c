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

#include "server-help.h"
#include "util.h"

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
