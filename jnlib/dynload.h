/* dynload.h - Wrapper functions for run-time dynamic loading
 *      Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_DYNLOAD_H
#define LIBJNLIB_DYNLOAD_H

#ifndef __MINGW32__
# include <dlfcn.h>
#else
# include <windows.h>

# define RTLD_LAZY 0

static inline void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);
  (void)flag;
  return hd;
}

static inline void *
dlsym (void *hd, const char *sym)
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


static inline const char *
dlerror (void)
{
  static char buf[32];
  sprintf (buf, "ec=%lu", GetLastError ());
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
#endif /*LIBJNLIB_DYNLOAD_H*/
