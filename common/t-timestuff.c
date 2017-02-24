/* t-timestuff.c - Regression tests for time functions
 * Copyright (C) 2007 Free Software Foundation, Inc.
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


static int
cmp_time_s (struct tm *a, struct tm *b)
{
  if (a->tm_year != b->tm_year
      || a->tm_mon  != b->tm_mon
      || a->tm_mday != b->tm_mday
      || a->tm_hour != b->tm_hour
      || a->tm_min  != b->tm_min
      || a->tm_sec  != b->tm_sec
      || a->tm_wday != b->tm_wday
      || a->tm_yday != b->tm_yday
      || !a->tm_isdst != !b->tm_isdst)
    return -1;
  return 0;
}



static void
test_timegm (void)
{
  static struct {
    int year, mon, mday, hour, min, sec;
  } tvalues[] = {
    { -1 },
    { -2,  1 },
    { -2,  2 },
    { -2,  86399 },
    { -2,  86400 },
    { -2,  0x7ffffffe },
    { -2,  0x7fffffff },
    /* Note: Because we use mktime below we can only start with the
       day after Epoch.  */
    { 1970, 0, 2, 0, 0 , 1},
    { 1970, 0, 2, 0, 0 , 2},
    { 1970, 0, 2, 12, 0 , 0},
    { 1970, 0, 2, 23, 59 , 59},
    { 1999, 11, 31, 23, 59 , 59},
    { 2000, 0, 1, 0, 0, 0},
    { 2000, 0, 1, 0, 0, 1},
    { 2010, 11, 31, 23, 59 , 59},
    { 2010, 0, 1, 0, 0, 0},
    { 2010, 0, 1, 0, 0, 1},
    /* On GNU based 32 bit systems the end of all ticks will be on
       20380119T031408 (unless Uli takes compassion on us and changes
       time_t to a u64).  We check that the previous day is okay.  */
    { 2038, 0, 18, 23, 59, 59}

  };
  int tidx;
  time_t now, atime;
  struct tm tbuf, tbuf2, *tp;

  for (tidx=0; tidx < DIM (tvalues); tidx++)
    {
      if (tvalues[tidx].year == -1)
        {
          now = time (NULL);
        }
      else if (tvalues[tidx].year == -2)
        {
          now = tvalues[tidx].mon;
        }
      else
        {
          memset (&tbuf, 0, sizeof tbuf);
          tbuf.tm_year = tvalues[tidx].year - 1900;
          tbuf.tm_mon  = tvalues[tidx].mon;
          tbuf.tm_mday = tvalues[tidx].mday;
          tbuf.tm_hour = tvalues[tidx].hour;
          tbuf.tm_min  = tvalues[tidx].min;
          tbuf.tm_sec  = tvalues[tidx].sec;
#ifdef HAVE_TIMEGM
          now = timegm (&tbuf);
#else
          now = mktime (&tbuf);
#endif
        }
      if (now == (time_t)(-1))
        fail (tidx);

      tp = gmtime (&now);
      if (!tp)
        fail (tidx);
      else
        {
          tbuf = *tp;
          tbuf2 = tbuf;
#ifdef HAVE_TIMEGM
          atime = timegm (&tbuf);
#else
          atime = mktime (&tbuf);
#endif
          if (atime == (time_t)(-1))
            fail (tidx);
          else if (atime != now)
            fail (tidx);

          tp = gmtime (&atime);
          if (!tp)
            fail (tidx);
          else if (cmp_time_s (tp, &tbuf))
            fail (tidx);
          else if (cmp_time_s (tp, &tbuf2))
            fail (tidx);
        }
    }
}



int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  /* If we do not have timegm, we use mktime.  However, we need to use
     UTC in this case so that the 20380118T235959 test does not fail
     for other timezones.  */
#ifndef HAVE_TIMEGM
# ifdef HAVE_SETENV
  setenv ("TZ", "UTC", 1);
#else
  putenv (xstrdup ("TZ=UTC"));
#endif
  tzset ();
#endif

  test_timegm ();

  return 0;
}
