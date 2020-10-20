/* keybox-file.c - File operations
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "keybox-defs.h"


#define IMAGELEN_LIMIT (5*1024*1024)


#if !defined(HAVE_FTELLO) && !defined(ftello)
static off_t
ftello (FILE *stream)
{
  long int off;

  off = ftell (stream);
  if (off == -1)
    return (off_t)-1;
  return off;
}
#endif /* !defined(HAVE_FTELLO) && !defined(ftello) */



/* Read a block at the current position and return it in R_BLOB.
   R_BLOB may be NULL to simply skip the current block.  */
int
_keybox_read_blob (KEYBOXBLOB *r_blob, estream_t fp, int *skipped_deleted)
{
  unsigned char *image;
  size_t imagelen = 0;
  int c1, c2, c3, c4, type;
  int rc;
  off_t off;

  if (skipped_deleted)
    *skipped_deleted = 0;
 again:
  if (r_blob)
    *r_blob = NULL;
  off = es_ftello (fp);
  if (off == (off_t)-1)
    return gpg_error_from_syserror ();

  if ((c1 = es_getc (fp)) == EOF
      || (c2 = es_getc (fp)) == EOF
      || (c3 = es_getc (fp)) == EOF
      || (c4 = es_getc (fp)) == EOF
      || (type = es_getc (fp)) == EOF)
    {
      if ( c1 == EOF && !es_ferror (fp) )
        return -1; /* eof */
      if (!es_ferror (fp))
        return gpg_error (GPG_ERR_TOO_SHORT);
      return gpg_error_from_syserror ();
    }

  imagelen = ((unsigned int) c1 << 24) | (c2 << 16) | (c3 << 8 ) | c4;
  if (imagelen < 5)
    return gpg_error (GPG_ERR_TOO_SHORT);

  if (!type)
    {
      /* Special treatment for empty blobs. */
      if (es_fseek (fp, imagelen-5, SEEK_CUR))
        return gpg_error_from_syserror ();
      if (skipped_deleted)
        *skipped_deleted = 1;
      goto again;
    }

  if (imagelen > IMAGELEN_LIMIT) /* Sanity check. */
    {
      /* Seek forward so that the caller may choose to ignore this
         record.  */
      if (es_fseek (fp, imagelen-5, SEEK_CUR))
        return gpg_error_from_syserror ();
      return gpg_error (GPG_ERR_TOO_LARGE);
    }

  if (!r_blob)
    {
      /* This blob shall be skipped.  */
      if (es_fseek (fp, imagelen-5, SEEK_CUR))
        return gpg_error_from_syserror ();
      return 0;
    }

  image = xtrymalloc (imagelen);
  if (!image)
    return gpg_error_from_syserror ();

  image[0] = c1; image[1] = c2; image[2] = c3; image[3] = c4; image[4] = type;
  if (es_fread (image+5, imagelen-5, 1, fp) != 1)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      xfree (image);
      return tmperr;
    }

  rc = _keybox_new_blob (r_blob, image, imagelen, off);
  if (rc)
    xfree (image);
  return rc;
}


/* Write the block to the current file position */
int
_keybox_write_blob (KEYBOXBLOB blob, estream_t fp, FILE *outfp)
{
  const unsigned char *image;
  size_t length;

  image = _keybox_get_blob_image (blob, &length);

  if (length > IMAGELEN_LIMIT)
    return gpg_error (GPG_ERR_TOO_LARGE);

  if (fp)
    {
      if (es_fwrite (image, length, 1, fp) != 1)
        return gpg_error_from_syserror ();
    }
  else
    {
      if (fwrite (image, length, 1, outfp) != 1)
        return gpg_error_from_syserror ();
    }

  return 0;
}


/* Write a fresh header type blob. */
int
_keybox_write_header_blob (estream_t fp, int for_openpgp)
{
  unsigned char image[32];
  u32 val;

  memset (image, 0, sizeof image);
  /* Length of this blob. */
  image[3] = 32;

  image[4] = KEYBOX_BLOBTYPE_HEADER;
  image[5] = 1; /* Version */
  if (for_openpgp)
    image[7] = 0x02; /* OpenPGP data may be available.  */

  memcpy (image+8, "KBXf", 4);
  val = time (NULL);
  /* created_at and last maintenance run. */
  image[16]   = (val >> 24);
  image[16+1] = (val >> 16);
  image[16+2] = (val >>  8);
  image[16+3] = (val      );
  image[20]   = (val >> 24);
  image[20+1] = (val >> 16);
  image[20+2] = (val >>  8);
  image[20+3] = (val      );

  if (es_fwrite (image, 32, 1, fp) != 1)
    return gpg_error_from_syserror ();

  return 0;
}
