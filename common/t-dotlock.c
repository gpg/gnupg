/* t-dotlock.c - Module test for dotlock.c
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
 */

/* Note: This is a standalone test program which does not rely on any
   GnuPG helper files.  However, it may also be build as part of the
   GnuPG build system.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Some quick replacements for stuff we usually expect to be defined
   in config.h.  Define HAVE_POSIX_SYSTEM for better readability. */
#if !defined (HAVE_DOSISH_SYSTEM) && defined(_WIN32)
# define HAVE_DOSISH_SYSTEM 1
#endif
#if !defined (HAVE_DOSISH_SYSTEM) && !defined (HAVE_POSIX_SYSTEM)
# define HAVE_POSIX_SYSTEM 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "dotlock.h"

#define PGM "t-dotlock"


static volatile int ctrl_c_pending;

static void
control_c_handler (int signo)
{
  (void)signo;
  ctrl_c_pending = 1;
}



static void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  fprintf (stderr, PGM "[%lu]: ", (unsigned long)getpid ());
  vfprintf (stderr, format, arg_ptr);
  putc ('\n', stderr);
  va_end (arg_ptr);
  exit (1);
}


static void
inf (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  fprintf (stderr, PGM "[%lu]: ", (unsigned long)getpid ());
  vfprintf (stderr, format, arg_ptr);
  putc ('\n', stderr);
  va_end (arg_ptr);
}


static void
lock_and_unlock (const char *fname)
{
  dotlock_t h;

  h = dotlock_create (fname, 0);
  if (!h)
    die ("error creating lock file for '%s': %s", fname, strerror (errno));
  inf ("lock created");

  while (!ctrl_c_pending)
    {
      if (dotlock_take (h, -1))
        die ("error taking lock");
      inf ("lock taken");
      sleep (1);
      if (dotlock_release (h))
        die ("error releasing lock");
      inf ("lock released");
      sleep (1);
    }
  dotlock_destroy (h);
  inf ("lock destroyed");
}


int
main (int argc, char **argv)
{
  const char *fname;

  if (argc > 1)
    fname = argv[1];
  else
    fname = "t-dotlock.tmp";

  {
    struct sigaction nact;

    nact.sa_handler = control_c_handler;
    nact.sa_flags = 0;
    sigaction (SIGINT, &nact, NULL);
  }

  dotlock_create (NULL, 0);  /* Initialize (optional).  */

  lock_and_unlock (fname);


  return 0;
}


/*
Local Variables:
compile-command: "cc -Wall -O2 -D_FILE_OFFSET_BITS=64 -o t-dotlock t-dotlock.c dotlock.c"
End:
*/
