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


static void
test_percent_data_escape (void)
{
  static struct {
    const char *prefix;
    const char *data;
    size_t datalen;
    const char *expect;
  } tbl[] = {
    {
      NULL,
      "", 0,
      ""
    }, {
      NULL,
      "a", 1,
      "a",
    }, {
      NULL,
      "%22", 3,
      "%2522"
    }, {
      NULL,
      "%%", 3,
      "%25%25%00"
    }, {
      NULL,
      "\n \0BC\t", 6,
      "\n %00BC\t"
    }, {
      "",
      "", 0,
      ""
    }, {
      "",
      "a", 1,
      "a",
    }, {
      "",
      "%22", 3,
      "%2522"
    }, {
      "",
      "%%", 3,
      "%25%25%00"
    }, {
      "",
      "\n \0BC\t", 6,
      "\n %00BC\t"
    }, {
      "a",
      "", 0,
      "a"
    }, {
      "a",
      "a", 1,
      "aa",
    }, {
      "a",
      "%22", 3,
      "a%2522"
    }, {
      "a",
      "%%", 3,
      "a%25%25%00"
    }, {
      "a",
      "\n \0BC\t", 6,
      "a\n %00BC\t"
    }, {
      " ",
      "%%", 3,
      " %25%25%00"
    }, {
      "+",
      "%%", 3,
      "+%25%25%00"
    }, {
      "%",
      "%%", 3,
      "%25%25%25%00"
    }, {
      "a b",
      "%%", 3,
      "a b%25%25%00"
    }, {
      "a%2Bb",
      "%%", 3,
      "a%252Bb%25%25%00"
    }, {
      "\n",
      "%%", 3,
      "%0A%25%25%00"
    }, {
      NULL,
      NULL, 0,
      NULL }
  };
  char *buf;
  int i;
  size_t len, prefixlen;

  for (i=0; tbl[i].data; i++)
    {
      buf = percent_data_escape (0, tbl[i].prefix, tbl[i].data, tbl[i].datalen);
      if (!buf)
        {
          fprintf (stderr, "out of core: %s\n", strerror (errno));
          exit (2);
        }
      if (strcmp (buf, tbl[i].expect))
        {
          fail (i);
        }
      len = percent_plus_unescape_inplace (buf, 0);
      prefixlen = tbl[i].prefix? strlen (tbl[i].prefix) : 0;
      if (len != tbl[i].datalen + prefixlen)
        fail (i);
      else if (tbl[i].prefix && memcmp (buf, tbl[i].prefix, prefixlen)
               && !(prefixlen == 1 && *tbl[i].prefix == '+' && *buf == ' '))
        {
          /* Note extra condition above handles the one test case
           * which reverts a plus to a space due to the use of the
           * plus-unescape function also for the prefix part.  */
          fail (i);
        }
      else if (memcmp (buf+prefixlen, tbl[i].data, tbl[i].datalen))
        {
          fail (i);
        }
      xfree (buf);
    }
}



static void
test_percent_data_escape_plus (void)
{
  static struct {
    const char *data;
    size_t datalen;
    const char *expect;
  } tbl[] = {
    {
      "", 0,
      ""
    }, {
      "a", 1,
      "a",
    }, {
      "%22", 3,
      "%2522"
    }, {
      "%%", 3,
      "%25%25%00"
    }, {
      "\n \0BC\t", 6,
      "%0A+%00BC%09"
    }, {
      " ", 1,
      "+"
    }, {
      "  ", 2,
      "++"
    }, {
      "+ +", 3,
      "%2B+%2B"
    }, {
      "\" \"", 3,  /* Note: This function does not escape quotes.  */
      "\"+\""
    }, {
      "%22", 3,
      "%2522"
    }, {
      "%% ", 3,
      "%25%25+"
    }, {
      "\n ABC\t", 6,
      "%0A+ABC%09"
    }, { NULL, 0, NULL }
  };
  char *buf;
  int i;
  size_t len;

  for (i=0; tbl[i].data; i++)
    {
      buf = percent_data_escape (1, NULL, tbl[i].data, tbl[i].datalen);
      if (!buf)
        {
          fprintf (stderr, "out of core: %s\n", strerror (errno));
          exit (2);
        }
      if (strcmp (buf, tbl[i].expect))
        {
          fail (i);
        }
      len = percent_plus_unescape_inplace (buf, 0);
      if (len != tbl[i].datalen)
        fail (i);
      else if (memcmp (buf, tbl[i].data, tbl[i].datalen))
        fail (i);
      xfree (buf);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  /* FIXME: escape_unescape is not tested - only percent_plus_unescape.  */
  test_percent_plus_escape ();
  test_percent_data_escape ();
  test_percent_data_escape_plus ();
  return 0;
}
