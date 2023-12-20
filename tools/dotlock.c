/* dotlock.c - A utility to handle dotlock by command line.
 *	Copyright (C) 2023 g10 Code GmbH
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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <gpg-error.h>
#include "../common/util.h"
#include "../common/stringhelp.h"
#include "../common/dotlock.h"

static void
lock (const char *filename)
{
  dotlock_t h;
  unsigned int flags = DOTLOCK_LOCK_BY_PARENT;

  h = dotlock_create (filename, flags);
  if (!h)
    {
      perror ("error creating lock file");
      exit (1);
    }

  if (dotlock_take (h, 0))
    {
      perror ("error taking lock");
      dotlock_destroy (h);
      exit (1);
    }

  dotlock_destroy (h);
}

static void
unlock (const char *filename)
{
  dotlock_t h;
  unsigned int flags = (DOTLOCK_LOCK_BY_PARENT | DOTLOCK_LOCKED);

  h = dotlock_create (filename, flags);
  if (!h)
    {
      perror ("no lock file");
      exit (1);
    }

  dotlock_release (h);
  dotlock_destroy (h);
}


int
main (int argc, const char *argv[])
{
  const char *name;
  const char *fname;
  char *filename;
  int op_unlock = 0;

  if (argc >= 2 && !strcmp (argv[1], "-u"))
    {
      op_unlock = 1;
      argc--;
      argv++;
    }

  if (argc != 2)
    {
      printf ("Usage: %s [-u] NAME\n", argv[0]);
      exit (1);
    }

  name = argv[1];

  if (!strcmp (name, "pubring.db"))
    /* Keybox pubring.db lock */
    fname = "public-keys.d/pubring.db";
  else
    /* Other locks.  */
    fname = name;

  filename = make_absfilename (gnupg_homedir (), fname, NULL);

  if (op_unlock)
    unlock (filename);
  else
    lock (filename);

  xfree (filename);
  return 0;
}
