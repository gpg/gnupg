/* t-gettime.c - Module test for gettime.c
 *	Copyright (C) 2007, 2011 Free Software Foundation, Inc.
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

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     errcount++;                                 \
                   } while(0)

static int verbose;
static int errcount;
#define INVALID ((time_t)(-1))


static void
test_isotime2epoch (void)
{
  struct { const char *string; time_t expected; } array [] = {
    { "19700101T000001",  1 },
    { "19700101T235959",  86399 },
    { "19980815T143712",  903191832 },
    { "19700101T000000",  0 },
    { "19691231T235959",  INVALID },
    { "19000101T000000",  INVALID },
    { "",                 INVALID },
    { "19000101T00000",   INVALID },
    { "20010101t123456",  INVALID },
    { "20010101T123456",  978352496 },
    { "20070629T160000",  1183132800 },
    { "20070629T160000:",  1183132800 },
    { "20070629T160000,",  1183132800 },
    { "20070629T160000 ",  1183132800 },
    { "20070629T160000\n", 1183132800 },
    { "20070629T160000.",  INVALID },
    { NULL, 0 }
  };
  int idx;
  time_t val;
  gnupg_isotime_t tbuf;

  for (idx=0; array[idx].string; idx++)
    {
      val = isotime2epoch (array[idx].string);
      if (val != array[idx].expected )
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string `%s' exp: %ld got: %ld\n",
                     array[idx].string, (long)array[idx].expected,
                     (long)val);
        }
      if (array[idx].expected != INVALID)
        {
          epoch2isotime (tbuf, val);
          if (strlen (tbuf) != 15)
            {
              if (verbose)
                fprintf (stderr, "string `%s', time-t %ld, revert: `%s'\n",
                         array[idx].string, (long)val, tbuf);
              fail (idx);
            }
          if (strncmp (array[idx].string, tbuf, 15))
            fail (idx);
        }
    }
}



static void
test_string2isotime (void)
{
  struct {
    const char *string;
    size_t result;
    const char *expected;
  } array [] = {
    { "19700101T000001",      15, "19700101T000001" },
    { "19700101T235959",      15, "19700101T235959" },
    { "19980815T143712",      15, "19980815T143712" },
    { "19700101T000000",      15, "19700101T000000" },
    { "19691231T235959",      15, "19691231T235959" },
    { "19000101T000000",      15, "19000101T000000" },
    { "",                      0, ""                },
    { "19000101T00000",        0, ""                },
    { "20010101t123456",       0, ""                },
    { "20010101T123456",      15, "20010101T123456" },
    { "20070629T160000",      15, "20070629T160000" },
    { "20070629T160000:",     15, "20070629T160000" },
    { "20070629T160000,",     15, "20070629T160000" },
    { "20070629T160000 ",     15, "20070629T160000" },
    { "20070629T160000\n",    15,"20070629T160000"  },
    { "20070629T160000.",      0, ""                },
    { "1066-03-20",           10, "10660320T000000" },
    { "1066-03-20,",          10, "10660320T000000" },
    { "1066-03-20:",           0, ""                },
    { "1066-03-20 00",        13, "10660320T000000" },
    { "1066-03-20 01",        13, "10660320T010000" },
    { "1066-03-20 23",        13, "10660320T230000" },
    { "1066-03-20 24",         0, ""                },
    { "1066-03-20 00:",        0, ""                },
    { "1066-03-20 00:3",       0, ""                },
    { "1066-03-20 00:31",     16, "10660320T003100" },
    { "1066-03-20 00:31:47",  19, "10660320T003147" },
    { "1066-03-20 00:31:47 ", 19, "10660320T003147" },
    { "1066-03-20 00:31:47,", 19, "10660320T003147" },
    { "1066-03-20 00:31:47:",  0, ""                },
    { "1-03-20 00:31:47:",     0, ""                },
    { "10-03-20 00:31:47:",    0, ""                },
    { "106-03-20 00:31:47:",   0, ""                },
    { "1066-23-20 00:31:47:",  0, ""                },
    { "1066-00-20 00:31:47:",  0, ""                },
    { "1066-0-20 00:31:47:",   0, ""                },
    { "1066-01-2 00:31:47:",   0, ""                },
    { "1066-01-2  00:31:47:",  0, ""                },
    { "1066-01-32 00:31:47:",  0, ""                },
    { "1066-01-00 00:31:47:",  0, ""                },
    { "1066-03-20  00:31:47:",11, "10660320T000000" },
    { "1066-03-2000:31:47:",   0, ""                },
    { "10666-03-20 00:31:47:", 0, ""                },
    { NULL, 0 }
  };
  int idx;
  size_t result;
  gnupg_isotime_t tbuf;

  for (idx=0; array[idx].string; idx++)
    {
      result = string2isotime (tbuf, array[idx].string);
      if (result != array[idx].result)
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string `%s' expected: %d, got: %d\n",
                     array[idx].string, (int)array[idx].result, (int)result);
        }
      else if (result && strlen (tbuf) != 15)
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string `%s' invalid isotime returned\n",
                     array[idx].string);
        }
      else if (result && strcmp (array[idx].expected, tbuf))
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string `%s' bad isotime '%s' returned\n",
                     array[idx].string, tbuf);
        }
    }
}


int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  test_isotime2epoch ();
  test_string2isotime ();

  return !!errcount;
}
