/* w32-pth.c - GNU Pth emulation for W32 (MS Windows).
 * Copyright (C) 2004 g10 Code GmbH
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
#ifdef HAVE_W32_SYSTEM
#include <stdio.h>
#include <windows.h>
#include <io.h>

#include "w32-pth.h"

ssize_t
pth_read (int fd, void *buffer, size_t size)
{
  return read (fd, buffer, size);
}

ssize_t
pth_write (int fd, const void *buffer, size_t size)
{
  return write (fd, buffer, size);
}


#endif /*HAVE_W32_SYSTEM*/
