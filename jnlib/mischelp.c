/* mischelp.c - Miscellaneous helper functions
 * Copyright (C) 1998, 2000, 2001, 2006, 2007 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/stat.h>
# include <unistd.h>
#endif /*!HAVE_W32_SYSTEM*/

#include "libjnlib-config.h"
#include "stringhelp.h"
#include "mischelp.h"


/* Check whether the files NAME1 and NAME2 are identical.  This is for
   example achieved by comparing the inode numbers of the files.  */
int
same_file_p (const char *name1, const char *name2)
{
  int yes;
      
  /* First try a shortcut.  */
  if (!compare_filenames (name1, name2))
    yes = 1;
  else
    {
#ifdef HAVE_W32_SYSTEM  
      HANDLE file1, file2;
      BY_HANDLE_FILE_INFORMATION info1, info2;
      
      file1 = CreateFile (name1, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
      if (file1 == INVALID_HANDLE_VALUE)
        yes = 0; /* If we can't open the file, it is not the same.  */
      else
        {
          file2 = CreateFile (name2, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
          if (file1 == INVALID_HANDLE_VALUE)
            yes = 0; /* If we can't open the file, it is not the same.  */
          else
            {
              yes = (GetFileInformationByHandle (file1, &info1)
                     && GetFileInformationByHandle (file2, &info2)
                     && info1.dwVolumeSerialNumber==info2.dwVolumeSerialNumber
                     && info1.nFileIndexHigh == info2.nFileIndexHigh
                     && info1.nFileIndexLow == info2.nFileIndexLow);
              CloseHandle (file2);
            }
          CloseHandle (file1);
        }
#else /*!HAVE_W32_SYSTEM*/
      struct stat info1, info2;
      
      yes = (!stat (name1, &info1) && !stat (name2, &info2)
             && info1.st_dev == info2.st_dev && info1.st_ino == info2.st_ino);
#endif /*!HAVE_W32_SYSTEM*/
    }
  return yes;
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

