/* import.c
 *	Copyright (c) 1998 by Werner Koch (dd9jn)
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
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"


/****************
 * Import the public keys from the given filename.
 * Import is a somewhat misleading name, as we (only) add informations
 * about the public keys into aout trustdb.
 *
 * NOTE: this function is not really needed and will be changed to
 *	a function which reads a plain textfile, describing a public
 *	key and its associated ownertrust.  This can be used (together
 *	with the export function) to make a backup of the assigned
 *	ownertrusts.
 */
int
import_pubkeys( const char *filename )
{
    log_fatal("Not yet implemented");
    return 0;
}


