/* kbxfile.c - KBX file handling
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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

/****************
 * We will change the whole system to use only KBX.  This file here
 * will implement the methods needed to operate on plain KBXfiles.
 * Most stuff from getkey and ringedit will be replaced by stuff here.
 * To make things even mor easier we will only allow one updateable kbxfile
 * and optionally some read-only files.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <gcrypt.h>

#include "kbx.h"


int
kbxfile_search_by_fpr( void )
{
    return -1;
}

