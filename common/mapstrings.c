/* mapstrings.c - Static string mapping
 * Copyright (C) 2014 Werner Koch
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
#include <stdlib.h>
#include <errno.h>

#include "util.h"
#include "stringhelp.h"
#include "membuf.h"


static struct {
  const char *name;
  const char *value;
} macros[] = {
#ifdef PACKAGE_BUGREPORT
  { "EMAIL", PACKAGE_BUGREPORT },
#else
  { "EMAIL", "bug@example.org" },
#endif
  { "GNUPG",     GNUPG_NAME },
  { "GPG",       GPG_NAME },
  { "GPGSM",     GPGSM_NAME },
  { "GPG_AGENT", GPG_AGENT_NAME },
  { "SCDAEMON",  SCDAEMON_NAME },
  { "DIRMNGR",   DIRMNGR_NAME },
  { "G13",       G13_NAME },
  { "GPGCONF",   GPGCONF_NAME },
  { "GPGTAR",    GPGTAR_NAME }
};



/* A list to remember already done mappings.  */
struct mapping_s
{
  struct mapping_s *next;
  const char *key;
  const char *value;
};
static struct mapping_s *mappings;


/* If STRING has already been mapped, return the mapped string.  If
   not return NULL.  */
static const char *
already_mapped (const char *string)
{
  struct mapping_s *m;

  for (m=mappings; m; m = m->next)
    if (m->key == string && !strcmp (m->key, string))
      return m->value;
  return NULL;
}


/* Store NEWSTRING under key STRING and return NEWSTRING.  */
static const char *
store_mapping (const char *string, char *newstring)
{
  struct mapping_s *m;

  m = xmalloc (sizeof *m);
  m->key = string;
  m->value = newstring;
  m->next = mappings;
  mappings = m;
  return newstring;
}


/* Find the first macro in STRING.  Return a pointer to the
   replacement value, set BEGPTR to the leading '@', and set ENDPTR to
   the terminating '@'.  If no macro is found return NULL.  */
const char *
find_macro (const char *string,  const char **begptr,
            const char **endptr)
{
  const char *s, *s2, *s3;
  int idx;

  s = string;
  if (!s)
    return NULL;

  for (; (s2 = strchr (s, '@')); s = s2)
    {
      s2++;
      if (*s2 >= 'A' && *s2 <= 'Z' && (s3 = (strchr (s2, '@'))))
        {
          for (idx=0; idx < DIM (macros); idx++)
            if (strlen (macros[idx].name) == (s3 - s2)
                && !memcmp (macros[idx].name, s2, (s3 - s2)))
              {
                *begptr = s2 - 1;
                *endptr = s3;
                return macros[idx].value;
              }
        }
    }
  return NULL;
}


/* If STRING includes known @FOO@ macros, replace these macros and
   return a new static string.  Warning: STRING must have been
   allocated statically.  Note that this function allocates memory
   which will not be released (similar to gettext).  */
const char *
map_static_macro_string (const char *string)
{
  const char *s, *s2, *s3, *value;
  membuf_t mb;
  char *p;

  if ((s = already_mapped (string)))
    return s;
  s = string;
  value = find_macro (s, &s2, &s3);
  if (!value)
    return string; /* No macros at all.  */

  init_membuf (&mb, strlen (string) + 100);
  do
    {
      put_membuf (&mb, s, s2 - s);
      put_membuf_str (&mb, value);
      s = s3 + 1;
    }
  while ((value = find_macro (s, &s2, &s3)));
  put_membuf_str (&mb, s);
  put_membuf (&mb, "", 1);

  p = get_membuf_shrink (&mb, NULL);
  if (!p)
    log_fatal ("map_static_macro_string failed: %s\n", strerror (errno));

  return store_mapping (string, p);
}
