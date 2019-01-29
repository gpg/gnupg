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
