/* openpgp-fpr.c - OpenPGP Fingerprint computation
 * Copyright (C) 2021 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "util.h"
#include "openpgpdefs.h"

/* Count the number of bits, assuming the A represents an unsigned big
 * integer of length LEN bytes. */
static unsigned int
count_bits (const unsigned char *a, size_t len)
{
  unsigned int n = len * 8;
  int i;

  for (; len && !*a; len--, a++, n -=8)
    ;
  if (len)
    {
      for (i=7; i && !(*a & (1<<i)); i--)
        n--;
    }
  return n;
}

/* Variant of count_bits for simple octet strings.  */
static unsigned int
count_sos_bits (const unsigned char *a, size_t len)
{
  unsigned int n = len * 8;
  int i;

  if (len == 0 || *a == 0)
    return n;

  for (i=7; i && !(*a & (1<<i)); i--)
    n--;

  return n;
}


gpg_error_t
compute_openpgp_fpr (int keyversion, int pgpalgo, unsigned long timestamp,
                     gcry_buffer_t *iov, int iovcnt,
                     unsigned char *result, unsigned int *r_resultlen)
{
  gpg_error_t err;
  int hashalgo;
  unsigned char prefix[15];
  size_t n;
  int i;

  if (r_resultlen)
    *r_resultlen = 0;

  if (iovcnt < 2)
    return gpg_error (GPG_ERR_INV_ARG);

  /* Note that iov[0] is reserved.  */
  for (n=0, i=1; i < iovcnt; i++)
    n += iov[i].len;

  i = 0;
  if (keyversion == 5)
    {
      hashalgo = GCRY_MD_SHA256;
      n += 10; /* Add the prefix length.  */
      prefix[i++] = 0x9a;
      prefix[i++] = (n >> 24);
      prefix[i++] = (n >> 16);
    }
  else if (keyversion == 4)
    {
      hashalgo = GCRY_MD_SHA1;
      n += 6;  /* Add the prefix length.  */
      prefix[i++] = 0x99;
    }
  else
    return gpg_error (GPG_ERR_UNKNOWN_VERSION);

  prefix[i++] = (n >> 8);
  prefix[i++] = n;
  prefix[i++] = keyversion;
  prefix[i++] = (timestamp >> 24);
  prefix[i++] = (timestamp >> 16);
  prefix[i++] = (timestamp >>  8);
  prefix[i++] = (timestamp);
  prefix[i++] = pgpalgo;
  if (keyversion == 5)
    {
      prefix[i++] = ((n-10) >> 24);
      prefix[i++] = ((n-10) >> 16);
      prefix[i++] = ((n-10) >>  8);
      prefix[i++] = (n-10);
    }
  log_assert (i <= sizeof prefix);
  /* The first element is reserved for our use; set it.  */
  iov[0].size = 0;
  iov[0].off = 0;
  iov[0].len = i;
  iov[0].data = prefix;

  /* for (i=0; i < iovcnt; i++) */
  /*   log_printhex (iov[i].data, iov[i].len, "cmpfpr i=%d: ", i); */

  err = gcry_md_hash_buffers (hashalgo, 0, result, iov, iovcnt);
  /* log_printhex (result, 20, "fingerpint: "); */

  /* Better clear the first element because it was set by us.  */
  iov[0].size = 0;
  iov[0].off = 0;
  iov[0].len = 0;
  iov[0].data = NULL;

  if (!err && r_resultlen)
    *r_resultlen = (hashalgo == GCRY_MD_SHA1)? 20 : 32;

  return err;
}


gpg_error_t
compute_openpgp_fpr_rsa (int keyversion, unsigned long timestamp,
                         const unsigned char *m, unsigned int mlen,
                         const unsigned char *e, unsigned int elen,
                         unsigned char *result, unsigned int *r_resultlen)
{
  gcry_buffer_t iov[5] = { {0} };
  unsigned char nbits_m[2], nbits_e[2];
  unsigned int n;

  /* Strip leading zeroes. */
  for (; mlen && !*m; mlen--, m++)
    ;
  for (; elen && !*e; elen--, e++)
    ;

  /* Count bits. */
  n = count_bits (m, mlen);
  nbits_m[0] = n >> 8;
  nbits_m[1] = n;

  n = count_bits (e, elen);
  nbits_e[0] = n >> 8;
  nbits_e[1] = n;

  /* Put parms into the array.  Note that iov[0] is reserved. */
  iov[1].len  = 2;
  iov[1].data = nbits_m;
  iov[2].len  = mlen;
  iov[2].data = (void*)m;
  iov[3].len  = 2;
  iov[3].data = nbits_e;
  iov[4].len  = elen;
  iov[4].data = (void*)e;

  return compute_openpgp_fpr (keyversion, PUBKEY_ALGO_RSA, timestamp,
                              iov, 5, result, r_resultlen);
}


/* Determine KDF hash algorithm and KEK encryption algorithm by CURVE.
 * The returned buffer has a length of 4.
 * Note: This needs to be kept in sync with the table in g10/ecdh.c */
static const unsigned char*
default_ecdh_params (unsigned int nbits)
{
  /* See RFC-6637 for those constants.
         0x03: Number of bytes
         0x01: Version for this parameter format
         KEK digest algorithm
         KEK cipher algorithm
  */
  if (nbits <= 256)
    return (const unsigned char*)"\x03\x01\x08\x07";
  else if (nbits <= 384)
    return (const unsigned char*)"\x03\x01\x09\x09";
  else
    return (const unsigned char*)"\x03\x01\x0a\x09";
}


gpg_error_t
compute_openpgp_fpr_ecc (int keyversion, unsigned long timestamp,
                         const char *curvename, int for_encryption,
                         const unsigned char *q, unsigned int qlen,
                         const unsigned char *kdf, unsigned int kdflen,
                         unsigned char *result, unsigned int *r_resultlen)
{
  gpg_error_t err;
  const char *curveoidstr;
  gcry_mpi_t curveoid = NULL;
  unsigned int curvebits;
  int pgpalgo;
  const unsigned char *oidraw;
  size_t oidrawlen;
  gcry_buffer_t iov[5] = { {0} };
  unsigned int iovlen;
  unsigned char nbits_q[2];
  unsigned int n;

  curveoidstr = openpgp_curve_to_oid (curvename, &curvebits, &pgpalgo);
  err = openpgp_oid_from_str (curveoidstr, &curveoid);
  if (err)
    goto leave;
  oidraw = gcry_mpi_get_opaque (curveoid, &n);
  if (!oidraw)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  oidrawlen = (n+7)/8;

  /* If the curve does not enforce a certain algorithm, we use the
   * for_encryption flag to decide which algo to use.  */
  if (!pgpalgo)
    pgpalgo = for_encryption? PUBKEY_ALGO_ECDH : PUBKEY_ALGO_ECDSA;

  /* Count bits. */
  n = count_sos_bits (q, qlen);
  nbits_q[0] = n >> 8;
  nbits_q[1] = n;

  /* Put parms into the array.  Note that iov[0] is reserved. */
  iov[1].len  = oidrawlen;
  iov[1].data = (void*)oidraw;
  iov[2].len  = 2;
  iov[2].data = nbits_q;
  iov[3].len  = qlen;
  iov[3].data = (void*)q;
  iovlen = 4;
  if (pgpalgo == PUBKEY_ALGO_ECDH)
    {
      if (!kdf || !kdflen || !kdf[0])
        {
          /* No KDF given - use the default.  */
          kdflen = 4;
          kdf = default_ecdh_params (curvebits);
        }
      iov[4].len  = kdflen;
      iov[4].data = (void*)kdf;
      iovlen++;
    }

  err = compute_openpgp_fpr (keyversion, pgpalgo, timestamp,
                             iov, iovlen, result, r_resultlen);

 leave:
  gcry_mpi_release (curveoid);
  return err;
}
