/* t-b64.c - Module tests for b64enc.c and b64dec.c
 *	Copyright (C) 2008 Free Software Foundation, Inc.
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

/* 

   As of now this is only a test program for manual tests.

 */



#include <config.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     errcount++;                                 \
                   } while(0)

static int verbose;
static int errcount;

static void
test_b64enc_pgp (const char *string)
{
  gpg_error_t err;
  struct b64state state;

  if (!string)
    string = "a";

  err = b64enc_start (&state, stdout, "PGP MESSAGE");
  if (err)
    fail (1);

  err = b64enc_write (&state, string, strlen (string));
  if (err)
    fail (2);

  err = b64enc_finish (&state);
  if (err)
    fail (3);

  pass ();
}






int
main (int argc, char **argv)
{
  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  test_b64enc_pgp (argc? *argv: NULL);

  return !!errcount;
}

