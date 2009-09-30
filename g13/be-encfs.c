/* be-encfs.c - The EncFS based backend
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "g13.h"
#include "i18n.h"
#include "keyblob.h"
#include "be-encfs.h"

/* See be_get_detached_name for a description.  Note that the
   dispatcher code makes sure that NULL is stored at R_NAME before
   calling us. */
gpg_error_t
be_encfs_get_detached_name (const char *fname, char **r_name, int *r_isdir)
{
  char *result;

  if (!fname || !*fname)
    return gpg_error (GPG_ERR_INV_ARG);

  result = strconcat (fname, ".d", NULL);
  if (!result)
    return gpg_error_from_syserror ();
  *r_name = result;
  *r_isdir = 1;
  return 0;
}


gpg_error_t
be_encfs_create_new_keys (membuf_t *mb)
{
  return 0;
}


