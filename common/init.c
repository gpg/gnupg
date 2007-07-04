/* init.c - Various initializations
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

#include <config.h>

#ifdef WITHOUT_GNU_PTH /* Give the Makefile a chance to build without Pth.  */
#undef HAVE_PTH
#undef USE_GNU_PTH
#endif

#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif
#ifdef HAVE_PTH      
#include <pth.h>
#endif

#include "estream.h"
#include "util.h"


/* This function is to be used early at program startup to make sure
   that some subsystems are initialized.  This is in particular
   important for W32 to initialize the sockets so that our socket
   emulation code used directly as well as in libassuan may be used.
   It should best be called before any I/O is done so that setup
   required for logging is ready.  CAUTION: This might be called while
   running suid(root). */
void
init_common_subsystems (void)
{
  /* Try to auto set the character set.  */
  set_native_charset (NULL); 

#ifdef HAVE_W32_SYSTEM
  /* For W32 we need to initialize the socket layer.  This is because
     we use recv and send in libassuan as well as at some other
     places.  If we are building with PTH we let pth_init do it.  We
     can't do much on error so we ignore them.  An error would anyway
     later pop up if one of the socket functions is used. */
# ifdef HAVE_PTH
  pth_init ();
# else
 {
   WSADATA wsadat;

   WSAStartup (0x202, &wsadat);
 }
# endif /*!HAVE_PTH*/
#endif

  /* Initialize the Estream library. */
  es_init ();
}

