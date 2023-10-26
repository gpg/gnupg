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
      wchar_t *wname;

      wname = gpgrt_fname_to_wchar (name1);
      if (wname)
        {
          file1 = CreateFileW (wname, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
          xfree (wname);
        }
      else
        file1 = INVALID_HANDLE_VALUE;

      if (file1 == INVALID_HANDLE_VALUE)
        yes = 0; /* If we can't open the file, it is not the same.  */
      else
        {
          wname = gpgrt_fname_to_wchar (name2);
          if (wname)
            {
              file2 = CreateFileW (wname, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
              xfree (wname);
            }
          else
            file2 = INVALID_HANDLE_VALUE;

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
