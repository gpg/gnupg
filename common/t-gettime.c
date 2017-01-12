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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#include "util.h"

/* In case we do not have stdint.h and no other version of that
 * conversion macro provide shortcut it.  */
#ifndef UINTMAX_C
#define UINTMAX_C (c)  (c)
#endif

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
#if SIZEOF_TIME_T > 4
    { "21060207T062815", (time_t)UINTMAX_C(0x0ffffffff) },
    { "21060207T062816", (time_t)UINTMAX_C(0x100000000) },
    { "21060207T062817", (time_t)UINTMAX_C(0x100000001) },
    { "21060711T120001", (time_t)UINTMAX_C(4308292801)  },
#endif /*SIZEOF_TIME_T > 4*/
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
            fprintf (stderr, "string '%s' exp: %ld got: %ld\n",
                     array[idx].string, (long)array[idx].expected,
                     (long)val);
        }
      if (array[idx].expected != INVALID)
        {
          epoch2isotime (tbuf, val);
          if (strlen (tbuf) != 15)
            {
              if (verbose)
                fprintf (stderr, "string '%s', time-t %ld, revert: '%s'\n",
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
            fprintf (stderr, "string '%s' expected: %d, got: %d\n",
                     array[idx].string, (int)array[idx].result, (int)result);
        }
      else if (result && strlen (tbuf) != 15)
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string '%s' invalid isotime returned\n",
                     array[idx].string);
        }
      else if (result && strcmp (array[idx].expected, tbuf))
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string '%s' bad isotime '%s' returned\n",
                     array[idx].string, tbuf);
        }
    }
}


static void
test_isodate_human_to_tm (void)
{
  struct {
    const char *string;
    int okay;
    int year, mon, mday;
  } array [] = {
    { "1970-01-01",      1, 1970,  1,  1 },
    { "1970-02-01",      1, 1970,  2,  1 },
    { "1970-12-31",      1, 1970, 12, 31 },
    { "1971-01-01",      1, 1971,  1,  1 },
    { "1998-08-15",      1, 1998,  8, 15 },
    { "2015-04-10",      1, 2015,  4, 10 },
    { "2015-04-10 11:30",1, 2015,  4, 10 },
    { "1969-12-31",      0,    0,  0,  0 },
    { "1900-01-01",      0,    0,  0,  0 },
    { "",                0,    0,  0,  0 },
    { "1970-12-32",      0,    0,  0,  0 },
    { "1970-13-01",      0,    0,  0,  0 },
    { "1970-01-00",      0,    0,  0,  0 },
    { "1970-00-01",      0,    0,  0,  0 },
    { "1970-00-01",      0,    0,  0,  0 },
    { "1970",            0,    0,  0,  0 },
    { "1970-01",         0,    0,  0,  0 },
    { "1970-01-1",       0,    0,  0,  0 },
    { "1970-1--01",      0,    0,  0,  0 },
    { "1970-01-01,",     1, 1970,  1,  1 },
    { "1970-01-01 ",     1, 1970,  1,  1 },
    { "1970-01-01\t",    1, 1970,  1,  1 },
    { "1970-01-01;",     0,    0,  0,  0 },
    { "1970-01-01:",     0,    0,  0,  0 },
    { "1970_01-01",      0,    0,  0,  0 },
    { "1970-01_01",      0,    0,  0,  0 },
    { NULL, 0 }
  };
  int idx;
  int okay;
  struct tm tmbuf;

  for (idx=0; array[idx].string; idx++)
    {
      okay = !isodate_human_to_tm (array[idx].string, &tmbuf);
      if (okay != array[idx].okay)
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string '%s' expected: %d, got: %d\n",
                     array[idx].string, (int)array[idx].okay, okay);
        }
      else if (!okay)
        ;
      else if (tmbuf.tm_year + 1900 != array[idx].year
               || tmbuf.tm_mon +1   != array[idx].mon
               || tmbuf.tm_mday     != array[idx].mday)
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string '%s' returned %04d-%02d-%02d\n",
                     array[idx].string,
                     tmbuf.tm_year + 1900, tmbuf.tm_mon + 1, tmbuf.tm_mday);
        }
      else if (tmbuf.tm_sec || tmbuf.tm_min || tmbuf.tm_hour
               || tmbuf.tm_isdst != -1)
        {
          fail (idx);
          if (verbose)
            fprintf (stderr, "string '%s' returned bad time part\n",
                     array[idx].string);
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
  test_isodate_human_to_tm ();

  return !!errcount;
}
