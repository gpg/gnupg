/* gettime.c - Wrapper for time functions
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdlib.h>
#include <time.h>

#include "util.h"

static unsigned long timewarp;
static enum { NORMAL = 0, FROZEN, FUTURE, PAST } timemode;

/* Wrapper for the time(3).  We use this here so we can fake the time
   for tests */
time_t 
gnupg_get_time () 
{
  time_t current = time (NULL);
  if (timemode == NORMAL)
    return current;
  else if (timemode == FROZEN)
    return timewarp;
  else if (timemode == FUTURE)
    return current + timewarp;
  else
    return current - timewarp;
}

/* set the time to NEWTIME so that gnupg_get_time returns a time
   starting with this one.  With FREEZE set to 1 the returned time
   will never change.  Just for completeness, a value of (time_t)-1
   for NEWTIME gets you back to rality. Note that this is obviously
   not thread-safe but this is not required. */
void
gnupg_set_time (time_t newtime, int freeze)
{
  time_t current = time (NULL);

  if ( newtime == (time_t)-1 || current == newtime)
    {
      timemode = NORMAL;
      timewarp = 0;
    }
  else if (freeze)
    {
      timemode = FROZEN;
      timewarp = current;
    }
  else if (newtime > current)
    {
      timemode = FUTURE;
      timewarp = newtime - current;
    }
  else
    {
      timemode = PAST;
      timewarp = current - newtime;
    }
}

/* Returns true when we are in timewarp mode */
int
gnupg_faked_time_p (void)
{
  return timemode;
}




