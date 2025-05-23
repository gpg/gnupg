/* ecdh.c - ECDH public key operations used in public key glue code
 *	Copyright (C) 2010, 2011 Free Software Foundation, Inc.
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

#include "gpg.h"
#include "../common/util.h"
#include "pkglue.h"
#include "main.h"
#include "options.h"

/* A table with the default KEK parameters used by GnuPG.  */
static const struct
{
  unsigned int qbits;
  int openpgp_hash_id;   /* KEK digest algorithm. */
  int openpgp_cipher_id; /* KEK cipher algorithm. */
} kek_params_table[] =
  /* Note: Must be sorted by ascending values for QBITS.  */
  {
    { 256, DIGEST_ALGO_SHA256, CIPHER_ALGO_AES    },
    { 384, DIGEST_ALGO_SHA384, CIPHER_ALGO_AES256 },

    /* Note: 528 is 521 rounded to the 8 bit boundary */
    { 528, DIGEST_ALGO_SHA512, CIPHER_ALGO_AES256 }
  };



/* Return KEK parameters as an opaque MPI The caller must free the
   returned value.  Returns NULL and sets ERRNO on error.  */
gcry_mpi_t
pk_ecdh_default_params (unsigned int qbits)
{
  byte kek_params[4] = {
    3, /* Number of bytes to follow. */
    1  /* Version for KDF+AESWRAP.   */
  };
  int i;

  /* Search for matching KEK parameter.  Defaults to the strongest
     possible choices.  Performance is not an issue here, only
     interoperability.  */
  for (i=0; i < DIM (kek_params_table); i++)
    {
      if (kek_params_table[i].qbits >= qbits
          || i+1 == DIM (kek_params_table))
        {
          kek_params[2] = kek_params_table[i].openpgp_hash_id;
          kek_params[3] = kek_params_table[i].openpgp_cipher_id;
          break;
        }
    }
  log_assert (i < DIM (kek_params_table));
  if (DBG_CRYPTO)
    log_printhex (kek_params, sizeof(kek_params), "ECDH KEK params are");

  return gcry_mpi_set_opaque_copy (NULL, kek_params, 4 * 8);
}


/* Build KDF parameters */
/* RFC 6637 defines the KDF parameters and its encoding in Section
   8. EC DH Algorighm (ECDH).  Since it was written for v4 key, it
   said "20 octets representing a recipient encryption subkey or a
   master key fingerprint".  For v5 key, it is considered "adequate"
   (in terms of NIST SP 800 56A, see 5.8.2 FixedInfo) to use the first
   20 octets of its 32 octets fingerprint.  */
gpg_error_t
ecc_build_kdf_params (unsigned char **r_kdf_params, size_t *r_len,
                      const unsigned char **r_kdf_params_spec,
                      gcry_mpi_t *pkey, const byte fp[MAX_FINGERPRINT_LEN])
{
  const unsigned char *oid;
  const unsigned char *kdf_params_spec;
  unsigned int nbits;
  size_t oid_len;
  size_t len;
  unsigned char *kdf_params = NULL;
  int kdf_params_len = 0;

  if (!gcry_mpi_get_flag (pkey[0], GCRYMPI_FLAG_OPAQUE))
    return gpg_error (GPG_ERR_BAD_PUBKEY);

  oid = gcry_mpi_get_opaque (pkey[0], &nbits);
  oid_len = (nbits+7)/8;

  /* In the public key part, there is a specifier of KDF parameters
     (namely, hash algo for KDF and symmetric algo for wrapping key).
     Using this specifier (together with curve OID of the public key
     and the fingerprint), we build _the_ KDF parameters.  */
  if (!gcry_mpi_get_flag (pkey[2], GCRYMPI_FLAG_OPAQUE))
    return gpg_error (GPG_ERR_BAD_PUBKEY);

  kdf_params_spec = gcry_mpi_get_opaque (pkey[2], &nbits);
  len = (nbits+7)/8;

  /* Expect 4 bytes  03 01 hash_alg symm_alg.  */
  if (len != 4 || kdf_params_spec[0] != 3 || kdf_params_spec[1] != 1)
    return gpg_error (GPG_ERR_BAD_PUBKEY);

  kdf_params_len = oid_len + 1 + 4 + 20 + 20;
  kdf_params = xtrymalloc (kdf_params_len);
  if (!kdf_params)
    return gpg_error_from_syserror ();

  memcpy (kdf_params, oid, oid_len);
  kdf_params[oid_len] = PUBKEY_ALGO_ECDH;
  memcpy (kdf_params + oid_len + 1, kdf_params_spec, 4);
  memcpy (kdf_params + oid_len + 1 + 4, "Anonymous Sender    ", 20);
  memcpy (kdf_params + oid_len + 1 + 4 + 20, fp, 20);

  if (DBG_CRYPTO)
    log_printhex (kdf_params, kdf_params_len,
                  "ecdh KDF message params are:");

  *r_kdf_params = kdf_params;
  *r_len = kdf_params_len;
  if (r_kdf_params_spec)
    *r_kdf_params_spec = kdf_params_spec;
  return 0;
}
