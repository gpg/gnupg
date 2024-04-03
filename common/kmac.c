/* kmac.c -  Keccak based MAC
 * Copyright (C) 2024  g10 Code GmbH.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <gpg-error.h>
#include <gcrypt.h>
#include "mischelp.h"

#define KECCAK512_BLOCKSIZE 136
gpg_error_t
compute_kmac256 (void *digest, size_t digestlen,
                 const void *key, size_t keylen,
                 const void *custom, size_t customlen,
                 gcry_buffer_t *data_iov, int data_iovlen)
{
#if GCRYPT_VERSION_NUMBER >= 0x010b00
  gpg_error_t err;
  gcry_buffer_t iov[20];
  const unsigned char headPAD[2] = { 1, KECCAK512_BLOCKSIZE };
  unsigned char headK[3];
  const unsigned char pad[KECCAK512_BLOCKSIZE] = { 0 };
  unsigned char right_encode_L[3];
  unsigned int len;
  int iovcnt;

  if (data_iovlen >= DIM(iov) - 6)
    return gpg_error (GPG_ERR_TOO_LARGE);

  /* Check the validity conditions of NIST SP 800-185 */
  if (keylen >= 255 || customlen >= 255 || digestlen >= 255)
    return gpg_error (GPG_ERR_TOO_LARGE);

  iovcnt = 0;
  iov[iovcnt].data = "KMAC";
  iov[iovcnt].off = 0;
  iov[iovcnt].len = 4;
  iovcnt++;

  iov[iovcnt].data = (void *)custom;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = customlen;
  iovcnt++;

  iov[iovcnt].data = (void *)headPAD;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = sizeof (headPAD);
  iovcnt++;

  if (keylen < 32)
    {
      headK[0] = 1;
      headK[1] = (keylen*8)&0xff;
      iov[iovcnt].data = headK;
      iov[iovcnt].off = 0;
      iov[iovcnt].len = 2;
    }
  else
    {
      headK[0] = 2;
      headK[1] = (keylen*8)>>8;
      headK[2] = (keylen*8)&0xff;
      iov[iovcnt].data = headK;
      iov[iovcnt].off = 0;
      iov[iovcnt].len = 3;
    }
  iovcnt++;

  iov[iovcnt].data = (void *)key;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = keylen;
  iovcnt++;

  len = iov[2].len + iov[3].len + iov[4].len;
  len %= KECCAK512_BLOCKSIZE;

  iov[iovcnt].data = (unsigned char *)pad;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = sizeof (pad) - len;
  iovcnt++;

  memcpy (&iov[iovcnt], data_iov, data_iovlen * sizeof (gcry_buffer_t));
  iovcnt += data_iovlen;

  if (digestlen < 32)
    {
      right_encode_L[0] = (digestlen * 8) & 0xff;
      right_encode_L[1] = 1;
    }
  else
    {
      right_encode_L[0] = (digestlen * 8) >> 8;
      right_encode_L[1] = (digestlen * 8) & 0xff;
      right_encode_L[2] = 2;
    }

  iov[iovcnt].data = right_encode_L;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = 3;
  iovcnt++;

  err = gcry_md_hash_buffers_ext (GCRY_MD_CSHAKE256, 0,
                                  digest, digestlen, iov, iovcnt);
  return err;
#else
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}
