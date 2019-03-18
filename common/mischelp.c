/* mischelp.c - Miscellaneous helper functions
 * Copyright (C) 1998, 2000, 2001, 2006, 2007 Free Software Foundation, Inc.
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
#include <errno.h>

#include "util.h"
#include "common-defs.h"
#include "stringhelp.h"
#include "utf8conv.h"
#include "mischelp.h"


void
wipememory (void *ptr, size_t len)
{
#if defined(HAVE_W32_SYSTEM) && defined(SecureZeroMemory)
  SecureZeroMemory (ptr, len);
#elif defined(HAVE_EXPLICIT_BZERO)
  explicit_bzero (ptr, len);
#else
  /* Prevent compiler from optimizing away the call to memset by accessing
     memset through volatile pointer. */
  static void *(*volatile memset_ptr)(void *, int, size_t) = (void *)memset;
  memset_ptr (ptr, 0, len);
#endif
}


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

#ifdef HAVE_W32CE_SYSTEM
      {
        wchar_t *wname = utf8_to_wchar (name1);
        if (wname)
          file1 = CreateFile (wname, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        else
          file1 = INVALID_HANDLE_VALUE;
        xfree (wname);
      }
#else
      file1 = CreateFile (name1, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif
      if (file1 == INVALID_HANDLE_VALUE)
        yes = 0; /* If we can't open the file, it is not the same.  */
      else
        {
#ifdef HAVE_W32CE_SYSTEM
          {
            wchar_t *wname = utf8_to_wchar (name2);
            if (wname)
              file2 = CreateFile (wname, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
            else
              file2 = INVALID_HANDLE_VALUE;
            xfree (wname);
          }
#else
          file2 = CreateFile (name2, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif
          if (file2 == INVALID_HANDLE_VALUE)
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

  Note, that this replacement implementation might not be thread-safe!

  Some BSDs don't handle the putenv("foo") case properly, so we use
  unsetenv if the platform has it to remove environment variables.
*/
#ifndef HAVE_TIMEGM
time_t
timegm (struct tm *tm)
{
#ifdef HAVE_W32_SYSTEM
  /* This one is thread safe.  */
  SYSTEMTIME st;
  FILETIME ft;
  unsigned long long cnsecs;

  st.wYear   = tm->tm_year + 1900;
  st.wMonth  = tm->tm_mon  + 1;
  st.wDay    = tm->tm_mday;
  st.wHour   = tm->tm_hour;
  st.wMinute = tm->tm_min;
  st.wSecond = tm->tm_sec;
  st.wMilliseconds = 0; /* Not available.  */
  st.wDayOfWeek = 0;    /* Ignored.  */

  /* System time is UTC thus the conversion is pretty easy.  */
  if (!SystemTimeToFileTime (&st, &ft))
    {
      gpg_err_set_errno (EINVAL);
      return (time_t)(-1);
    }

  cnsecs = (((unsigned long long)ft.dwHighDateTime << 32)
            | ft.dwLowDateTime);
  cnsecs -= 116444736000000000ULL; /* The filetime epoch is 1601-01-01.  */
  return (time_t)(cnsecs / 10000000ULL);

#else /* (Non thread safe implementation!) */

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
    gnupg_unsetenv("TZ");

  tzset();
  return answer;
#endif
}
#endif /*!HAVE_TIMEGM*/
