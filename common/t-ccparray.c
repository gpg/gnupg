/* t-ccparray.c - Module test for ccparray.c
 * Copyright (C) 2016 g10 Code GmbH
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "ccparray.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                       exit (1);                                 \
                    } while(0)


static void
run_test_1 (void)
{
  ccparray_t ccp;
  const char **argv;
  size_t nelem;

  ccparray_init (&ccp, 0);
  ccparray_put (&ccp, "First arg");
  ccparray_put (&ccp, "Second arg");
  ccparray_put (&ccp, NULL);
  ccparray_put (&ccp, "Fourth arg");
  argv = ccparray_get (&ccp, &nelem);
  if (!argv)
    {
      fprintf (stderr, "error building array: %s\n", strerror (errno));
      exit (1);
    }

  if (nelem != 4)
    fail (1);

  /* for (i=0; argv[i]; i++) */
  /*   printf ("[%d] = '%s'\n", i, argv[i]); */
  xfree (argv);
}


static void
run_test_var (int count)
{
  ccparray_t ccp;
  size_t nelem;
  int i;

  ccparray_init (&ccp, 0);
  for (i=0; i < count; i++)
    ccparray_put (&ccp, "An arg");
  xfree (ccparray_get (&ccp, &nelem));
  if (nelem != i)
    fail (2);
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  run_test_1 ();
  run_test_var (0);
  run_test_var (7);
  run_test_var (8);
  run_test_var (9);
  run_test_var (4096);

  return 0;
}
