/* no-pth.c - stubs to avoid linking against PTH
 * Copyright (C) 2002 Free Software Foundation, Inc.
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
#ifdef USE_GNU_PTH /*we need the stubs only in this case */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pth.h>

#if PTH_SYSCALL_SOFT
# error this file cannot be used with PTH syscall divertion 
#endif


ssize_t  
pth_read (int a, void *b , size_t c)
{
  return read (a, b, c);
}

ssize_t
pth_write (int a, const void *b, size_t c)
{
  return write (a, b, c);
}

int
pth_accept (int a, struct sockaddr *b, socklen_t *c) 
{
  return accept (a, b, c);
}



#endif /*USE_GNU_PTH*/
