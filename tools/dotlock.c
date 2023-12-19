/* dotlock.c - Command to handle dotlock.
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
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_W32_SYSTEM
# include "windows.h"
#else
#include <sys/random.h>
#endif

#include "dotlock.h"

static void
lock (const char *fname)
{
  dotlock_t h;
  unsigned int flags = DOTLOCK_FLAG_LOCK_BY_PARENT;

  h = dotlock_create (fname, flags);
  if (!h)
    die ("error creating lock file for '%s': %s", fname, strerror (errno));

  if (dotlock_take (h, 0))
    die ("error taking lock");
}

static void
unlock (const char *fname, long timeout)
{
  dotlock_t h;
  unsigned int flags = (DOTLOCK_FLAG_LOCK_BY_PARENT
                        | DOTLOCK_FLAG_READONLY);

  h = dotlock_create (fname, flags);
  if (!h)
    die ("error creating lock file for '%s': %s", fname, strerror (errno));

  dotlock_destroy (h);
}


int
main (int argc, char **argv)
{
  const char *fname;

  fname = argv[argc-1];

  if ()
    lock (fname);
  else
    unlock (fname);

  return 0;
}


/*
Local Variables:
compile-command: "cc -Wall -O2 -D_FILE_OFFSET_BITS=64 -o t-dotlock t-dotlock.c"
End:
*/
