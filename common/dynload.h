/* dynload.h - Wrapper functions for run-time dynamic loading
 *      Copyright (C) 2003, 2010 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_DYNLOAD_H
#define GNUPG_COMMON_DYNLOAD_H

#ifndef __MINGW32__
# include <dlfcn.h>
#else
# include <errhandlingapi.h>
# include <handleapi.h>
# include <libloaderapi.h>
# include "utf8conv.h"
# include "mischelp.h"
# define RTLD_LAZY 0

static inline void *
dlopen (const char *name, int flag)
{
  void *hd;
  (void)flag;

  hd = LoadLibraryEx (name, NULL, 0);
  return hd;
}

static inline void *
dlsym (void *hd, const char *sym)
{
  if (hd && sym)
    {
      void *fnc = GetProcAddress (hd, sym);
      if (!fnc)
        return NULL;
      return fnc;
    }
  return NULL;
}


static inline const char *
dlerror (void)
{
  static char buf[32];
  snprintf (buf, sizeof buf, "ec=%lu", GetLastError ());
  return buf;
}


static inline int
dlclose (void * hd)
{
  if (hd)
    {
      CloseHandle (hd);
      return 0;
    }
  return -1;
}
# endif /*__MINGW32__*/
#endif /*GNUPG_COMMON_DYNLOAD_H*/
