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
   digest is returned; well, this can also be done by using
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


/* Return an allocated buffer with the formatted fingerprint */
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

/* Return an allocated buffer with the formatted fingerprint as one
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

/* Return a certificate ID.  These are the last 4 bytes of the SHA-1
   fingerprint. */
unsigned long
gpgsm_get_short_fingerprint (KsbaCert cert)
{
  unsigned char digest[20];

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL);
  return ((digest[16]<<24)|(digest[17]<<16)|(digest[18]<< 8)|digest[19]);
}


/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed as an canoncial encoded S-Exp.  array must
   be 20 bytes long. returns the array or a newly allocated one if the
   passed one was NULL */
char *
gpgsm_get_keygrip (KsbaCert cert, char *array)
{
  GCRY_SEXP s_pkey;
  int rc;
  KsbaSexp p;
  size_t n;
  
  p = ksba_cert_get_public_key (cert);
  if (!p)
    return NULL; /* oops */

  if (DBG_X509)
    log_debug ("get_keygrip for public key: %s\n", p);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      return NULL;
    }
  rc = gcry_sexp_sscan ( &s_pkey, NULL, p, n);
  xfree (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gcry_strerror (rc));
      return NULL;
    }
  array = gcry_pk_get_keygrip (s_pkey, array);
  gcry_sexp_release (s_pkey);
  if (!array)
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      log_error ("can't calculate keygrip\n");
      return NULL;
    }
  if (DBG_X509)
    log_printhex ("keygrip=", array, 20);

  return array;
}

/* Return an allocated buffer with the keygrip of CERT in from of an
   hexstring.  NULL is returned in case of error */
char *
gpgsm_get_keygrip_hexstring (KsbaCert cert)
{
  unsigned char grip[20];
  char *buf, *p;
  int i;

  gpgsm_get_keygrip (cert, grip);
  buf = p = xmalloc (20*2+1);
  for (i=0; i < 20; i++, p += 2 )
    sprintf (p, "%02X", grip[i]);
  return buf;
}



/* For certain purposes we need a certificate id which has an upper
   limit of the size.  We use the hash of the issuer name and the
   serial number for this.  In most cases the serial number is not
   that large and the resulting string can be passed on an assuan
   command line.  Everything is hexencoded with the serialnumber
   delimted from the has by a dot. 

   The caller must free the string.
*/
char *
gpgsm_get_certid (KsbaCert cert)
{
  KsbaSexp serial;
  unsigned char *p;
  char *endp;
  unsigned char hash[20];
  unsigned long n;
  char *certid;
  int i;
  
  p = ksba_cert_get_issuer (cert, 0);
  if (!p)
    return NULL; /* Ooops: No issuer */
  gcry_md_hash_buffer (GCRY_MD_SHA1, hash, p, strlen (p));
  xfree (p);

  serial = ksba_cert_get_serial (cert);
  if (!serial)
    return NULL; /* oops: no serial number */
  p = serial;
  if (*p != '(')
    {
      log_error ("Ooops: invalid serial number\n");
      xfree (serial);
      return NULL;
    }
  p++;
  n = strtoul (p, &endp, 10);
  p = endp;
  if (*p != ':')
    {
      log_error ("Ooops: invalid serial number (no colon)\n");
      xfree (serial);
      return NULL;
    }
  p++;

  certid = xtrymalloc ( 40 + 1 + n*2 + 1);
  if (!certid)
    {
      xfree (serial);
      return NULL; /* out of core */
    }

  for (i=0, endp = certid; i < 20; i++, endp += 2 )
    sprintf (endp, "%02X", hash[i]);
  *endp++ = '.';
  for (i=0; i < n; i++, endp += 2)
    sprintf (endp, "%02X", p[i]);
  *endp = 0;

  xfree (serial);
  return certid;
}






