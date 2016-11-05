/* t-mapstrings.c - Regression tests for mapstrings.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "t-support.h"
#include "stringhelp.h"

static void
test_map_static_macro_string (void)
{
  static struct {
    const char *string;
    const char *expected;
    const char *lastresult;
  } tests[] = {
    { "@GPG@ (@GNUPG@)",
      GPG_NAME " (" GNUPG_NAME ")" },
    { "@GPG@(@GNUPG@)",
      GPG_NAME "(" GNUPG_NAME ")" },
    { "@GPG@@GNUPG@",
      GPG_NAME  GNUPG_NAME },
    { " @GPG@@GNUPG@",
      " " GPG_NAME  GNUPG_NAME },
    { " @GPG@@GNUPG@ ",
      " " GPG_NAME  GNUPG_NAME " " },
    { " @GPG@GNUPG@ ",
      " " GPG_NAME "GNUPG@ " },
    { " @ GPG@GNUPG@ ",
      " @ GPG" GNUPG_NAME " " },
    { "--@GPGTAR@",
      "--" GPGTAR_NAME }
  };
  int testno;
  const char *result;

  for (testno=0; testno < DIM(tests); testno++)
    {
      result = map_static_macro_string (tests[testno].string);
      if (!result)
        fail (testno);
      else if (strcmp (result, tests[testno].expected))
        fail (testno);
      if (!tests[testno].lastresult)
        tests[testno].lastresult = result;
    }

  /* A second time to check that the same string is been returned.  */
  for (testno=0; testno < DIM(tests); testno++)
    {
      result = map_static_macro_string (tests[testno].string);
      if (!result)
        fail (testno);
      else if (strcmp (result, tests[testno].expected))
        fail (testno);
      if (result != tests[testno].lastresult)
        fail (testno);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_map_static_macro_string ();

  return 0;
}
