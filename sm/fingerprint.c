/* fingerprint.c - Get the fingerprint
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>
#include <ksba.h>

#include "gpgsm.h"

/* Return the fingerprint of the certificate (we can't put this into
   libksba because we need libgcrypt support).  The caller must
   provide an array of sufficient length or NULL so that the function
   allocates the array.  If r_len is not NULL, the length of the
   digest is return, well, this can also be done by using
   gcry_md_get_algo_dlen().  If algo is 0, a SHA-1 will be used.
   
   If there is a problem , the function does never return NULL but a
   digest of all 0xff.
 */
char *
gpgsm_get_fingerprint (KsbaCert cert, int algo, char *array, int *r_len)
{
  GCRY_MD_HD md;
  int rc, len;
  
  if (!algo)
    algo = GCRY_MD_SHA1;

  len = gcry_md_get_algo_dlen (algo);
  assert (len);
  if (!array)
    array = xmalloc (len);

  if (r_len)
    *r_len = len;

  md = gcry_md_open (algo, 0);
  if (!md)
    {
      log_error ("md_open failed: %s\n", gcry_strerror (-1));
      memset (array, 0xff, len); /* better return an invalid fpr than NULL */
      return array;
    }

  rc = ksba_cert_hash (cert, 0, HASH_FNC, md);
  if (rc)
    {
      log_error ("ksba_cert_hash failed: %s\n", ksba_strerror (rc));
      gcry_md_close (md);
      memset (array, 0xff, len); /* better return an invalid fpr than NULL */
      return array;
    }
  gcry_md_final (md);
  memcpy (array, gcry_md_read(md, algo), len );
  return array;
}


/* Return an allocated buffer with the formatted fungerprint */
char *
gpgsm_get_fingerprint_string (KsbaCert cert, int algo)
{
  unsigned char digest[MAX_DIGEST_LEN];
  char *buf;
  int len, i;

  if (!algo)
    algo = GCRY_MD_SHA1;

  len = gcry_md_get_algo_dlen (algo);
  assert (len <= MAX_DIGEST_LEN );
  gpgsm_get_fingerprint (cert, algo, digest, NULL);
  buf = xmalloc (len*3+1);
  *buf = 0;
  for (i=0; i < len; i++ )
    sprintf (buf+strlen(buf), i? ":%02X":"%02X", digest[i]);
  return buf;
}

/* Return an allocated buffer with the formatted fungerprint as one
   large hexnumber */
char *
gpgsm_get_fingerprint_hexstring (KsbaCert cert, int algo)
{
  unsigned char digest[MAX_DIGEST_LEN];
  char *buf;
  int len, i;

  if (!algo)
    algo = GCRY_MD_SHA1;

  len = gcry_md_get_algo_dlen (algo);
  assert (len <= MAX_DIGEST_LEN );
  gpgsm_get_fingerprint (cert, algo, digest, NULL);
  buf = xmalloc (len*3+1);
  *buf = 0;
  for (i=0; i < len; i++ )
    sprintf (buf+strlen(buf), "%02X", digest[i]);
  return buf;
}


