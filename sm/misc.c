/* misc.c - Miscellaneous fucntions
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <ksba.h>

#include "util.h"
#include "gpgsm.h"


/* Note: we might want to wrap this in a macro to get our hands on
   the line and file where the error occired */
int
map_ksba_err (int err)
{
  switch (err)
    {
    case -1:
    case 0:
      break;
      
    default:
      err = GPGSM_General_Error;
      break;
    }
  return err;
}


int 
map_gcry_err (int err)
{
  switch (err)
    {
    case -1:
    case 0:
      break;
      
    default:
      err = GPGSM_General_Error;
      break;
    }
  return err;
}

int 
map_kbx_err (int err)
{
  switch (err)
    {
    case -1:
    case 0:
      break;
      
    default:
      err = GPGSM_General_Error;
      break;
    }
  return err;
}







