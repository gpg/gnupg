/* keybox-file.c - file oeprations
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "keybox-defs.h"


int
_keybox_read_blob (KEYBOXBLOB *r_blob, FILE *fp)
{
  char *image;
  size_t imagelen = 0;
  int c1, c2, c3, c4;
  int rc;

  *r_blob = NULL;
  if ((c1 = getc (fp)) == EOF
      || (c2 = getc (fp)) == EOF
      || (c3 = getc (fp)) == EOF
      || (c4 = getc (fp)) == EOF ) {
    if ( c1 == EOF && !ferror (fp) )
      return -1; /* eof */
    return KEYBOX_Read_Error;
  }

  imagelen = (c1 << 24) | (c2 << 16) | (c3 << 8 ) | c4;
  if (imagelen > 500000) /* sanity check */
    return KEYBOX_Blob_Too_Large;
  
  if (imagelen < 4) 
    return KEYBOX_Blob_Too_Short;
    
  image = xtrymalloc (imagelen);
  if (!image) 
    return KEYBOX_Out_Of_Core;

  image[0] = c1; image[1] = c2; image[2] = c3; image[3] = c4;
  if (fread (image+4, imagelen-4, 1, fp) != 1)
    {
      return KEYBOX_Read_Error;
    }
  
  rc = _keybox_new_blob (r_blob, image, imagelen);
  if (rc)
      xfree (image);
  return rc;
}





void
export_as_kbxfile(void)
{
#if 0
    KBPOS kbpos;
    KBNODE keyblock = NULL;
    int rc=0;

    rc = enum_keyblocks_begin( &kbpos, 0 );
    if( rc ) {
	if( rc != -1 )
	    log_error("enum_keyblocks(open) failed: %s\n", gpg_errstr(rc) );
	goto leave;
    }

    while( !(rc = enum_keyblocks_next( kbpos, 1, &keyblock )) ) {
	KBXBLOB blob;
	const char *p;
	size_t n;

	merge_keys_and_selfsig( keyblock );
	rc = kbx_create_blob ( &blob, keyblock );
	if( rc ) {
	    log_error("kbx_create_blob failed: %s\n", gpg_errstr(rc) );
	    goto leave;
	}
	p = kbx_get_blob_image ( blob, &n );
	fwrite( p, n, 1, stdout );
	kbx_release_blob ( blob );
    }

    if( rc && rc != -1 )
	log_error("enum_keyblocks(read) failed: %s\n", gpg_errstr(rc));

  leave:
    enum_keyblocks_end( kbpos );
    release_kbnode( keyblock );
#endif
}

