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
#ifdef HAVE_W32_SYSTEM
# include "windows.h"
#else
#include <sys/random.h>
#endif

#include "dotlock.h"

#ifdef HAVE_W32_SYSTEM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))

const char *
w32_strerror (int ec)
{
  static char strerr[256];

  if (ec == -1)
    ec = (int)GetLastError ();
  FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, ec,
                 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                 strerr, DIM (strerr)-1, NULL);
  {
    /* Strip the CR,LF - we want just the string.  */
    size_t n = strlen (strerr);
    if (n > 2 && strerr[n-2] == '\r' && strerr[n-1] == '\n' )
      strerr[n-2] = 0;
  }
  return strerr;
}

static wchar_t *
cp_to_wchar (const char *string, unsigned int codepage)
{
  int n;
  size_t nbytes;
  wchar_t *result;

  n = MultiByteToWideChar (codepage, 0, string, -1, NULL, 0);
  if (n < 0)
    {
      return NULL;
    }

  nbytes = (size_t)(n+1) * sizeof(*result);
  if (nbytes / sizeof(*result) != (n+1))
    {
      return NULL;
    }
  result = malloc (nbytes);
  if (!result)
    return NULL;

  n = MultiByteToWideChar (codepage, 0, string, -1, result, n);
  if (n < 0)
    {
      free (result);
      result = NULL;
    }
  return result;
}

wchar_t *
utf8_to_wchar (const char *string)
{
  return cp_to_wchar (string, CP_UTF8);
}

char *
stpcpy(char *a,const char *b)
{
    while( *b )
	*a++ = *b++;
    *a = 0;

    return (char*)a;
}

static char *
do_strconcat (const char *s1, va_list arg_ptr)
{
  const char *argv[48];
  size_t argc;
  size_t needed;
  char *buffer, *p;

  argc = 0;
  argv[argc++] = s1;
  needed = strlen (s1);
  while (((argv[argc] = va_arg (arg_ptr, const char *))))
    {
      needed += strlen (argv[argc]);
      if (argc >= DIM (argv)-1)
        {
          return NULL;
        }
      argc++;
    }
  needed++;
  buffer = malloc (needed);
  if (buffer)
    {
      for (p = buffer, argc=0; argv[argc]; argc++)
        p = stpcpy (p, argv[argc]);
    }
  return buffer;
}

/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *
strconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    result = calloc (1, 1);
  else
    {
      va_start (arg_ptr, s1);
      result = do_strconcat (s1, arg_ptr);
      va_end (arg_ptr);
    }
  return result;
}
#endif /*HAVE_W32_SYSTEM*/


#include "dotlock.c"

#define PGM "t-dotlock"

#ifndef HAVE_W32_SYSTEM
static volatile int ctrl_c_pending_flag;
static void
control_c_handler (int signo)
{
  (void)signo;
  ctrl_c_pending_flag = 1;
}
#endif


static int
ctrl_c_pending (void)
{
#if HAVE_W32_SYSTEM
  static int count;

  return (++count > 9);
#else
  return ctrl_c_pending_flag;
#endif
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
  unsigned long usec;

  h = dotlock_create (fname, 0);
  if (!h)
    die ("error creating lock file for '%s': %s", fname, strerror (errno));
  inf ("lock created");

  do
    {
#ifdef HAVE_W32_SYSTEM
      usec = 10000;
#else
      getrandom (&usec, sizeof (usec), 0);
      usec &= 0xffff;
      usec |= 0x0f00;
#endif
      if (dotlock_take (h, -1))
        die ("error taking lock");
      inf ("lock taken");
      usleep (usec);
      if (dotlock_release (h))
        die ("error releasing lock");
      inf ("lock released");
      usleep (usec);
    }
  while (!ctrl_c_pending ());
  dotlock_destroy (h);
  inf ("lock destroyed");
}


int
main (int argc, char **argv)
{
  const char *fname;

  if (argc > 1 && !strcmp (argv[1], "--one-shot"))
    {
      ctrl_c_pending_flag = 1;
      argc--;
    }

  if (argc > 1)
    fname = argv[argc-1];
  else
    {
#ifdef HAVE_W32_SYSTEM
      fname = "t-dotⒶlock.tmp";
#else
      fname = "t-dotlock.tmp";
#endif
    }

#ifndef HAVE_W32_SYSTEM
  {
    struct sigaction nact;

    nact.sa_handler = control_c_handler;
    nact.sa_flags = 0;
    sigaction (SIGINT, &nact, NULL);
  }
#endif

  dotlock_create (NULL, 0);  /* Initialize (optional).  */

  lock_and_unlock (fname);


  return 0;
}


/*
Local Variables:
compile-command: "cc -Wall -O2 -D_FILE_OFFSET_BITS=64 -o t-dotlock t-dotlock.c"
End:
*/
