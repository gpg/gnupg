/* kbxio.c - KBX I/O handling
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


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <gcrypt.h>

#include "iobuf.h"
#include "util.h"
#include "kbx.h"


int
kbx_read_blob ( KBXBLOB *r_blob, FILE *a )
{
    char *image;
    size_t imagelen = 0;
    int c1, c2, c3, c4;
    int rc;

    *r_blob = NULL;
    if (    (c1 = getc ( a )) == EOF
	 || (c2 = getc ( a )) == EOF
	 || (c3 = getc ( a )) == EOF
	 || (c4 = getc ( a )) == EOF ) {
	if ( c1 == EOF && !ferror ( a ) )
	    return -1;
	return GPGERR_GENERAL;
    }
    imagelen = (c1 << 24) | (c2 << 16) | (c3 << 8 ) | c4;
    if ( imagelen > 500000 ) { /* sanity check:blob too large */
	return GPGERR_GENERAL;
    }
    else if ( imagelen < 4 ) { /* blobtoo short */
	return GPGERR_GENERAL;
    }
    image = gcry_malloc ( imagelen );
    if ( !image ) {
	return GPGERR_GENERAL;
    }

    image[0] = c1; image[1] = c2; image[2] = c3; image[3] = c4;
    if ( fread ( image+4, imagelen-4, 1, a ) != 1 )  {
	gcry_free ( image );
	return GPGERR_GENERAL;
    }

    rc = kbx_new_blob ( r_blob, image, imagelen );
    return rc;
}



