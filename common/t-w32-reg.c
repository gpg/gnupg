/* t-w32-reg.c - Regression tests for W32 registry functions
 * Copyright (C) 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "mischelp.h"

#include "t-support.h"
#include "w32help.h"


static void
test_read_registry (void)
{
  char *string1, *string2;

  string1 = read_w32_registry_string
    ("HKEY_CURRENT_USER",
     "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
     "User Agent");
  if (!string1)
    fail (0);
  fprintf (stderr, "User agent: %s\n", string1);

  string2 = read_w32_reg_string
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion"
     "\\Internet Settings:User Agent", NULL);
  if (!string2)
    fail (1);
  fprintf (stderr, "User agent: %s\n", string2);
  if (strcmp (string1, string2))
    fail (2);


  xfree (string1);
  xfree (string2);
}




int
main (int argc, char **argv)
{
  if (argc > 1)
    {
      char *string = read_w32_reg_string (argv[1], NULL);
      printf ("%s -> %s\n", argv[1], string? string : "(null)");
      xfree (string);
    }
  else
    test_read_registry ();

  return 0;
}
