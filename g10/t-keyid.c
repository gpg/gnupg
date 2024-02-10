/* t-keyid.c - Tests for keyid.c.
 * Copyright (C) 2024 g10 Code GmbH
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
#define LEAN_T_SUPPORT 1

#define PGM "t-keyid"

#include "gpg.h"
#include "keydb.h"
#include "../common/t-support.h"



static int verbose;


static void
test_compare_pubkey_string (void)
{
  static struct { const char *astr; const char *bstr; int expected; } t[] =
  {
    { "rsa2048"  , "rsa2048"             ,  1 },
    { "rsa2048"  , ">=rsa2048"           ,  1 },
    { "rsa2048"  , ">rsa2048"            ,  0 },
    { "ed25519"  , ">rsa1024"            ,  0 },
    { "ed25519"  , "ed25519"             ,  1 },
    { "ed25519"  , ",,,=ed25519"         ,  1 },
    { "nistp384" , ">nistp256"           ,  1 },
    { "nistp521" , ">=rsa3072, >nistp384",  1 },
    { " nistp521" , ">=rsa3072, >nistp384   ",  1 },
    { "  nistp521  " , "  >=rsa3072, >nistp384   ",  1 },
    { "  =nistp521  " , "  >=rsa3072, >nistp384,,",  1 },
    { "nistp384" , ">nistp384"           ,  0 },
    { "nistp384" , ">=nistp384"          ,  1 },
    { "brainpoolP384" , ">=brainpoolp256", 1 },
    { "brainpoolP384" , ">brainpoolp384" , 0 },
    { "brainpoolP384" , ">=brainpoolp384", 1 },
    { "brainpoolP256r1", ">brainpoolp256r1", 0 },
    { "brainpoolP384r1", ">brainpoolp384r1" , 0 },
    { "brainpoolP384r1", ">=brainpoolp384r1", 1 },
    { "brainpoolP384r1", ">=brainpoolp384"  , 1 },
    { "",  "", 0}
  };
  int idx;
  int result;

  for (idx=0; idx < DIM(t); idx++)
    {
      result = compare_pubkey_string (t[idx].astr, t[idx].bstr);
      if (result != t[idx].expected)
        {
          fail (idx);
          if (verbose)
            log_debug ("\"%s\", \"%s\" want %d got %d\n",
                       t[idx].astr, t[idx].bstr, t[idx].expected, result);
        }
    }

}


int
main (int argc, char **argv)
{
  int last_argc = -1;

  no_exit_on_fail = 1;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [FILE]\n"
                 "Options:\n"
                 "  --verbose         Print timings etc.\n"
                 "  --debug           Flyswatter\n"
                 , stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  test_compare_pubkey_string ();

  return !!errcount;
}
