/* idea-stub.c - Dummy module for the deprecated IDEA cipher.
 * Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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

/* IDEA is a patented algorithm and therefore the use of IDEA in
   countries where this patent is valid can not be allowed due to the
   terms of the GNU General Public License.  Those restrictions are
   there to help protecting the freedom of software.  For more
   information on the nonsense of software patents and the general
   problem with this, please see http://www.noepatents.org.

   However for research purposes and in certain situations it might be
   useful to use this algorithm anyway.  

   We provide this stub which will dynload a idea module and is only 
   used if the configure run did't found statically linked file.
   See http://www.gnupg.org/why-not-dea.html for details.
*/

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_DL_DLOPEN
#include <dlfcn.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif
#include "util.h"
#include "algorithms.h"

#ifndef RTLD_NOW
#define RTLD_NOW  1
#endif

#ifdef _WIN32
#define HAVE_DL_DLOPEN 1
#define USE_DYNAMIC_LINKING 1

static int last_error = 0;
    
void*
dlopen (const char *pathname, int mode)
{
  void *h = LoadLibrary (pathname);
  if (!h) 
    {
      log_error ("LoadLibrary failed: %s\n", w32_strerror (errno));
      last_error = 1;
      return NULL;
    }
  return h;
}

int
dlclose ( void *handle )
{
  last_error = 0;
  return FreeLibrary (handle);
}


const char*
dlerror (void)
{
  if (last_error)
    return w32_strerror (0);
  return NULL;
}

void*
dlsym (void *handle, const char *name)
{
  void *h = GetProcAddress (handle, name);
  if (!h)
    {
      log_error ("GetProcAddress failed: %s\n", w32_strerror (errno));
      last_error = 1;
    }
  return h;
}
#endif /*_WIN32*/

/* We do only support dlopen and the Windows emulation of it. */
#ifndef HAVE_DL_DLOPEN
#undef USE_DYNAMIC_LINKING
#endif

typedef
const char *(*INFO_FNC)(int, size_t*, size_t*, size_t*,
                        int  (**)( void *, const byte *, unsigned),
                        void (**)( void *, byte *, const byte *),
                        void (**)( void *, byte *, const byte *));

static INFO_FNC
load_module (const char *name)
{
#ifdef USE_DYNAMIC_LINKING
  const char *err;
  void *handle;
  void *sym;

#ifndef _WIN32
  /* Make sure we are not setuid. */
  if (getuid() != geteuid())
    log_bug("trying to load an extension while still setuid\n");
#endif

  handle = dlopen (name, RTLD_NOW);
  if (!handle)
    {
      err=dlerror();
      goto failure;
    }

  sym = dlsym (handle, "idea_get_info");
  if (dlerror ())
    sym = dlsym (handle, "_idea_get_info");
  if ((err=dlerror())) 
    goto failure;

  return (INFO_FNC)sym;
  
 failure:
  log_info ("invalid module `%s': %s\n", name?name:"???", err?err:"???");
  if (handle)
      dlclose (handle);
#endif /*USE_DYNAMIC_LINKING*/
  return NULL;
}

const char *
idea_get_info( int algo, size_t *keylen,
	       size_t *blocksize, size_t *contextsize,
	       int (**r_setkey)( void *c, const byte *key, unsigned keylen ),
	       void (**r_encrypt)( void *c, byte *outbuf, const byte *inbuf ),
	       void (**r_decrypt)( void *c, byte *outbuf, const byte *inbuf )
	       )
{
  static int initialized;
  static INFO_FNC info_fnc;
  const char *rstr;
  int i;

  if (!initialized)
    {
      initialized = 1;
      for (i=0; (rstr = dynload_enum_module_names (i)); i++)
        {
          info_fnc = load_module (rstr);
          if (info_fnc)
            break;
        }
    }
  if (!info_fnc)
    return NULL; /* dynloadable module not found. */
  rstr = info_fnc (algo, keylen, blocksize, contextsize,
                   r_setkey, r_encrypt, r_decrypt);
  if (rstr && *keylen == 128 && *blocksize == 8
      && *r_setkey && *r_encrypt && r_decrypt)
    return rstr;
  return NULL;
}
