/* t-helpfile.c - Module test for helpfile.c
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

#include "util.h"
#include "i18n.h"

/* #define pass()  do { ; } while(0) */
/* #define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\ */
/*                                __FILE__,__LINE__, (a));          \ */
/*                      errcount++;                                 \ */
/*                    } while(0) */

static int verbose;
static int errcount;



int
main (int argc, char **argv)
{
  char *result;

  if (argc)
    { argc--; argv++; }
  i18n_init ();
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  result = gnupg_get_help_string (argc? argv[0]:NULL, 0);
  if (!result)
    {
      fprintf (stderr, 
               "Error: nothing found for `%s'\n", argc?argv[0]:"(null)");
      errcount++;
    }
  else
    {
      printf ("key `%s' result=`%s'\n", argc?argv[0]:"(null)", result);
      xfree (result);
    }

  return !!errcount;
}

