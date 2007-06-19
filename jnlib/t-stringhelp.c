/* t-stringhelp.c - Regression tests for stringhelp.c
 * Copyright (C) 2007 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stringhelp.h"

#include "t-support.h"



static void
test_percent_escape (void)
{
  char *result;
  static struct {
    const char *extra; 
    const char *value; 
    const char *expected;
  } tests[] = 
    {
      { NULL, "", "" },
      { NULL, "%", "%25" },
      { NULL, "%%", "%25%25" },
      { NULL, " %", " %25" },
      { NULL, ":", "%3a" },
      { NULL, " :", " %3a" },
      { NULL, ": ", "%3a " },
      { NULL, " : ", " %3a " },
      { NULL, "::", "%3a%3a" },
      { NULL, ": :", "%3a %3a" },
      { NULL, "%:", "%25%3a" },
      { NULL, ":%", "%3a%25" },
      { "\\\n:", ":%", "%3a%25" },
      { "\\\n:", "\\:%", "%5c%3a%25" },
      { "\\\n:", "\n:%", "%0a%3a%25" },
      { "\\\n:", "\xff:%", "\xff%3a%25" },
      { "\\\n:", "\xfe:%", "\xfe%3a%25" },
      { "\\\n:", "\x01:%", "\x01%3a%25" },
      { "\x01",  "\x01:%", "%01%3a%25" },
      { "\xfe",  "\xfe:%", "%fe%3a%25" },
      { "\xfe",  "\xff:%", "\xff%3a%25" },

      { NULL, NULL, NULL }
    };
  int testno;

  result = percent_escape (NULL, NULL);
  if (result)
    fail (0);
  for (testno=0; tests[testno].value; testno++)
    {
      result = percent_escape (tests[testno].value, tests[testno].extra);
      if (!result)
        fail (testno);
      if (strcmp (result, tests[testno].expected))
        fail (testno);
      xfree (result);
    }

}




int
main (int argc, char **argv)
{
  test_percent_escape ();

  return 0;
}

