/* keybox-file.c - file oeprations
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
#include <errno.h>

#include "keybox-defs.h"

/* Read a block at the current postion and return it in r_blob.
   r_blob may be NULL to simply skip the current block */
int
_keybox_read_blob (KEYBOXBLOB *r_blob, FILE *fp)
{
  char *image;
  size_t imagelen = 0;
  int c1, c2, c3, c4, type;
  int rc;
  off_t off;

 again:
  *r_blob = NULL;
  off = ftello (fp);
  if (off == (off_t)-1)
    return gpg_error (gpg_err_code_from_errno (errno));

  if ((c1 = getc (fp)) == EOF
      || (c2 = getc (fp)) == EOF
      || (c3 = getc (fp)) == EOF
      || (c4 = getc (fp)) == EOF
      || (type = getc (fp)) == EOF)
    {
      if ( c1 == EOF && !ferror (fp) )
        return -1; /* eof */
      return gpg_error (gpg_err_code_from_errno (errno));
    }

  imagelen = (c1 << 24) | (c2 << 16) | (c3 << 8 ) | c4;
  if (imagelen > 500000) /* sanity check */
    return gpg_error (GPG_ERR_TOO_LARGE);
  
  if (imagelen < 5) 
    return gpg_error (GPG_ERR_TOO_SHORT);

  if (!type)
    {
      /* special treatment for empty blobs. */
      if (fseek (fp, imagelen-5, SEEK_CUR))
        return gpg_error (gpg_err_code_from_errno (errno));
      goto again;
    }

  image = xtrymalloc (imagelen);
  if (!image) 
    return gpg_error (gpg_err_code_from_errno (errno));

  image[0] = c1; image[1] = c2; image[2] = c3; image[3] = c4; image[4] = type;
  if (fread (image+5, imagelen-5, 1, fp) != 1)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      xfree (image);
      return tmperr;
    }
  
  rc = r_blob? _keybox_new_blob (r_blob, image, imagelen, off) : 0;
  if (rc || !r_blob)
        xfree (image);
  return rc;
}


/* Write the block to the current file position */
int
_keybox_write_blob (KEYBOXBLOB blob, FILE *fp)
{
  const char *image;
  size_t length;

  image = _keybox_get_blob_image (blob, &length);
  if (fwrite (image, length, 1, fp) != 1)
    return gpg_error (gpg_err_code_from_errno (errno));
  return 0;
}
