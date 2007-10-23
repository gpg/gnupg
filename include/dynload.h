/* dlfcn.h - W32 functions for run-time dynamic loading
 *      Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef GNUPG_DYNLOAD_H
#define GNUPG_DYNLOAD_H
#if defined (ENABLE_CARD_SUPPORT) || defined(_WIN32)
#ifndef _WIN32
#include <dlfcn.h>
#else
#include <windows.h>

#define RTLD_LAZY 0

static __inline__ void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);
  return hd;
}

static __inline__ void *
dlsym (void * hd, const char * sym)
{
  if (hd && sym)
    {
      void * fnc = GetProcAddress (hd, sym);
      if (!fnc)
        return NULL;
      return fnc;
    }
  return NULL;
}


static __inline__ const char *
dlerror (void)
{
  return w32_strerror (0);
}


static __inline__ int
dlclose (void * hd)
{
  if (hd)
    {
      FreeLibrary (hd);
      return 0;
    }
  return -1;
}  
#endif /*_WIN32*/
#endif /*ENABLE_CARD_SUPPORT||_WIN32*/
#endif /*GNUPG_DYNLOAD_H*/
