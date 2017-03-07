/* fingerprint.c - Get the fingerprint
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>


#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "../common/host2net.h"


/* Return the fingerprint of the certificate (we can't put this into
   libksba because we need libgcrypt support).  The caller must
   provide an array of sufficient length or NULL so that the function
   allocates the array.  If r_len is not NULL, the length of the
   digest is returned; well, this can also be done by using
   gcry_md_get_algo_dlen().  If algo is 0, a SHA-1 will be used.

   If there is a problem , the function does never return NULL but a
   digest of all 0xff.
 */
unsigned char *
gpgsm_get_fingerprint (ksba_cert_t cert, int algo,
                       unsigned char *array, int *r_len)
{
  gcry_md_hd_t md;
  int rc, len;

  if (!algo)
    algo = GCRY_MD_SHA1;

  len = gcry_md_get_algo_dlen (algo);
  assert (len);
  if (!array)
    array = xmalloc (len);

  if (r_len)
    *r_len = len;

  /* Fist check whether we have cached the fingerprint.  */
  if (algo == GCRY_MD_SHA1)
    {
      size_t buflen;

      assert (len >= 20);
      if (!ksba_cert_get_user_data (cert, "sha1-fingerprint",
                                    array, len, &buflen)
          && buflen == 20)
        return array;
    }

  /* No, need to compute it.  */
  rc = gcry_md_open (&md, algo, 0);
  if (rc)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (rc));
      memset (array, 0xff, len); /* better return an invalid fpr than NULL */
      return array;
    }

  rc = ksba_cert_hash (cert, 0, HASH_FNC, md);
  if (rc)
    {
      log_error ("ksba_cert_hash failed: %s\n", gpg_strerror (rc));
      gcry_md_close (md);
      memset (array, 0xff, len); /* better return an invalid fpr than NULL */
      return array;
    }
  gcry_md_final (md);
  memcpy (array, gcry_md_read(md, algo), len );
  gcry_md_close (md);

  /* Cache an SHA-1 fingerprint.  */
  if ( algo == GCRY_MD_SHA1 )
    ksba_cert_set_user_data (cert, "sha1-fingerprint", array, 20);

  return array;
}


/* Return an allocated buffer with the formatted fingerprint */
char *
gpgsm_get_fingerprint_string (ksba_cert_t cert, int algo)
{
  unsigned char digest[MAX_DIGEST_LEN];
  char *buf;
  int len;

  if (!algo)
    algo = GCRY_MD_SHA1;

  len = gcry_md_get_algo_dlen (algo);
  assert (len <= MAX_DIGEST_LEN );
  gpgsm_get_fingerprint (cert, algo, digest, NULL);
  buf = xmalloc (len*3+1);
  bin2hexcolon (digest, len, buf);
  return buf;
}

/* Return an allocated buffer with the formatted fingerprint as one
   large hexnumber */
char *
gpgsm_get_fingerprint_hexstring (ksba_cert_t cert, int algo)
{
  unsigned char digest[MAX_DIGEST_LEN];
  char *buf;
  int len;

  if (!algo)
    algo = GCRY_MD_SHA1;

  len = gcry_md_get_algo_dlen (algo);
  assert (len <= MAX_DIGEST_LEN );
  gpgsm_get_fingerprint (cert, algo, digest, NULL);
  buf = xmalloc (len*2+1);
  bin2hex (digest, len, buf);
  return buf;
}

/* Return a certificate ID.  These are the last 4 bytes of the SHA-1
   fingerprint.  If R_HIGH is not NULL the next 4 bytes are stored
   there. */
unsigned long
gpgsm_get_short_fingerprint (ksba_cert_t cert, unsigned long *r_high)
{
  unsigned char digest[20];

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL);
  if (r_high)
    *r_high = buf32_to_ulong (digest+12);
  return buf32_to_ulong (digest + 16);
}


/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed as an canoncial encoded S-Exp.  ARRAY must
   be 20 bytes long.  Returns ARRAY or a newly allocated buffer if ARRAY was
   given as NULL.  May return NULL on error.  */
unsigned char *
gpgsm_get_keygrip (ksba_cert_t cert, unsigned char *array)
{
  gcry_sexp_t s_pkey;
  int rc;
  ksba_sexp_t p;
  size_t n;

  p = ksba_cert_get_public_key (cert);
  if (!p)
    return NULL; /* oops */

  if (DBG_X509)
    log_debug ("get_keygrip for public key\n");
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      return NULL;
    }
  rc = gcry_sexp_sscan ( &s_pkey, NULL, (char*)p, n);
  xfree (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return NULL;
    }
  array = gcry_pk_get_keygrip (s_pkey, array);
  gcry_sexp_release (s_pkey);
  if (!array)
    {
      log_error ("can't calculate keygrip\n");
      return NULL;
    }
  if (DBG_X509)
    log_printhex ("keygrip=", array, 20);

  return array;
}

/* Return an allocated buffer with the keygrip of CERT encoded as a
   hexstring.  NULL is returned in case of error.  */
char *
gpgsm_get_keygrip_hexstring (ksba_cert_t cert)
{
  unsigned char grip[20];
  char *buf;

  if (!gpgsm_get_keygrip (cert, grip))
    return NULL;
  buf = xtrymalloc (20*2+1);
  if (buf)
    bin2hex (grip, 20, buf);
  return buf;
}


/* Return the PK algorithm used by CERT as well as the length in bits
   of the public key at NBITS. */
int
gpgsm_get_key_algo_info (ksba_cert_t cert, unsigned int *nbits)
{
  gcry_sexp_t s_pkey;
  int rc;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t l1, l2;
  const char *name;
  char namebuf[128];

  if (nbits)
    *nbits = 0;

  p = ksba_cert_get_public_key (cert);
  if (!p)
    return 0;
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      xfree (p);
      return 0;
    }
  rc = gcry_sexp_sscan (&s_pkey, NULL, (char *)p, n);
  xfree (p);
  if (rc)
    return 0;

  if (nbits)
    *nbits = gcry_pk_get_nbits (s_pkey);

  /* Breaking the algorithm out of the S-exp is a bit of a challenge ... */
  l1 = gcry_sexp_find_token (s_pkey, "public-key", 0);
  if (!l1)
    {
      gcry_sexp_release (s_pkey);
      return 0;
    }
  l2 = gcry_sexp_cadr (l1);
  gcry_sexp_release (l1);
  l1 = l2;
  name = gcry_sexp_nth_data (l1, 0, &n);
  if (name)
    {
      if (n > sizeof namebuf -1)
        n = sizeof namebuf -1;
      memcpy (namebuf, name, n);
      namebuf[n] = 0;
    }
  else
    *namebuf = 0;
  gcry_sexp_release (l1);
  gcry_sexp_release (s_pkey);
  return gcry_pk_map_name (namebuf);
}




/* For certain purposes we need a certificate id which has an upper
   limit of the size.  We use the hash of the issuer name and the
   serial number for this.  In most cases the serial number is not
   that large and the resulting string can be passed on an assuan
   command line.  Everything is hexencoded with the serialnumber
   delimited from the hash by a dot.

   The caller must free the string.
*/
char *
gpgsm_get_certid (ksba_cert_t cert)
{
  ksba_sexp_t serial;
  char *p;
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
  p = (char *)serial;
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
    sprintf (endp, "%02X", ((unsigned char*)p)[i]);
  *endp = 0;

  xfree (serial);
  return certid;
}
