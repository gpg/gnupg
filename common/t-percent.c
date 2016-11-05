/* t-percent.c - Module test for percent.c
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     exit (1);                                   \
                   } while(0)

static void
test_percent_plus_escape (void)
{
  static struct {
    const char *string;
    const char *expect;
  } tbl[] = {
    {
      "",
      ""
    }, {
      "a",
      "a",
    }, {
      " ",
      "+",
    }, {
      "  ",
      "++"
    }, {
      "+ +",
      "%2B+%2B"
    }, {
      "\" \"",
      "%22+%22"
    }, {
      "%22",
      "%2522"
    }, {
      "%% ",
      "%25%25+"
    }, {
      "\n ABC\t",
      "%0A+ABC%09"
    }, { NULL, NULL }
  };
  char *buf, *buf2;
  int i;
  size_t len;

  for (i=0; tbl[i].string; i++)
    {
      buf = percent_plus_escape (tbl[i].string);
      if (!buf)
        {
          fprintf (stderr, "out of core: %s\n", strerror (errno));
          exit (2);
        }
      if (strcmp (buf, tbl[i].expect))
        fail (i);
      buf2 = percent_plus_unescape (buf, 0);
      if (!buf2)
        {
          fprintf (stderr, "out of core: %s\n", strerror (errno));
          exit (2);
        }
      if (strcmp (buf2, tbl[i].string))
        fail (i);
      xfree (buf2);
      /* Now test the inplace conversion.  */
      len = percent_plus_unescape_inplace (buf, 0);
      buf[len] = 0;
      if (strcmp (buf, tbl[i].string))
        fail (i);
      xfree (buf);
    }
}



int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  /* FIXME: We escape_unescape is not tested - only
     percent_plus_unescape.  */
  test_percent_plus_escape ();

  return 0;
}
