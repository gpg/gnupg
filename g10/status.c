/* status.c
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "status.h"

static int fd = -1;

void
set_status_fd( int newfd )
{
    fd = newfd;
}


void
write_status( int no )
{
    const char *s;

    if( fd == -1 )
	return;  /* not enabled */

    switch( no ) {
      case STATUS_ENTER  : s = "ENTER\n"; break;
      case STATUS_LEAVE  : s = "LEAVE\n"; break;
      case STATUS_ABORT  : s = "ABORT\n"; break;
      case STATUS_GOODSIG: s = "GOODSIG\n"; break;
      case STATUS_BADSIG : s = "BADSIG\n"; break;
      case STATUS_ERRSIG : s = "ERRSIG\n"; break;
      default: s = "?\n"; break;
    }

    write( fd, s, strlen(s) );

}

