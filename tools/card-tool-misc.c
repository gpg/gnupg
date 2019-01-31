/* card-tool-misc.c - Helper functions for gpg-card-tool
 * Copyright (C) 2019 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/openpgpdefs.h"
#include "card-tool.h"

/* Return the key info object for the key KEYREF.  If it is not found
 * NULL is returned.  */
key_info_t
find_kinfo (card_info_t info, const char *keyref)
{
  key_info_t kinfo;

  for (kinfo = info->kinfo; kinfo; kinfo = kinfo->next)
    if (!strcmp (kinfo->keyref, keyref))
      return kinfo;
  return NULL;
}


/* Convert STRING into a newly allocated buffer while translating the
 * hex numbers.  Blanks and colons are allowed to separate pairs of
 * hex digits.  Returns NULL on error or a newly malloced buffer and
 * its length in LENGTH.  */
void *
hex_to_buffer (const char *string, size_t *r_length)
{
  unsigned char *buffer;
  const char *s;
  size_t n;

  buffer = xtrymalloc (strlen (string)+1);
  if (!buffer)
    return NULL;
  for (s=string, n=0; *s; s++)
    {
      if (ascii_isspace (*s) || *s == ':')
        continue;
      if (hexdigitp (s) && hexdigitp (s+1))
        {
          buffer[n++] = xtoi_2 (s);
          s++;
        }
      else
        {
          xfree (buffer);
          gpg_err_set_errno (EINVAL);
          return NULL;
        }
    }
  *r_length = n;
  return buffer;
}
