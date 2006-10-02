/* mischelp.c - Miscellaneous helper functions
 * Copyright (C) 1998, 2000, 2001, 2006 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libjnlib-config.h"
#include "mischelp.h"

/* A dummy function to prevent an empty compilation unit.  Some
   compilers bail out in this case. */
time_t
libjnlib_dummy_mischelp_func (void)
{
  return time (NULL);
}


/*
  timegm() is a GNU function that might not be available everywhere.
  It's basically the inverse of gmtime() - you give it a struct tm,
  and get back a time_t.  It differs from mktime() in that it handles
  the case where the struct tm is UTC and the local environment isn't.

  Note, that this replacement implementaion is not thread-safe!

  Some BSDs don't handle the putenv("foo") case properly, so we use
  unsetenv if the platform has it to remove environment variables.
*/
#ifndef HAVE_TIMEGM
time_t
timegm (struct tm *tm)
{
  time_t answer;
  char *zone;

  zone=getenv("TZ");
  putenv("TZ=UTC");
  tzset();
  answer=mktime(tm);
  if(zone)
    {
      static char *old_zone;

      if (!old_zone)
        {
          old_zone = malloc(3+strlen(zone)+1);
          if (old_zone)
            {
              strcpy(old_zone,"TZ=");
              strcat(old_zone,zone);
            }
	}
      if (old_zone)
        putenv (old_zone);	
    }
  else
#ifdef HAVE_UNSETENV
    unsetenv("TZ");
#else
    putenv("TZ");
#endif

  tzset();
  return answer;
}
#endif /*!HAVE_TIMEGM*/

