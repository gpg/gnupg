/* openpgp-misc.c - miscellaneous functions for OpenPGP
 * Copyright (C) 2021 g10 Code GmbH
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

#include "util.h"
#include "openpgpdefs.h"

/*
 * Parse the key (pubkey or seckey), and return real version of the
 * key; That is, for Ed448/X448, return key with prefix removed.
 */
gcry_mpi_t
openpgp_ecc_parse_key (pubkey_algo_t pkalgo, const char *curve,
                       gcry_mpi_t key)
{
  unsigned int nbits = 0;
  unsigned char *buf = NULL;

  if ((pkalgo == PUBKEY_ALGO_EDDSA && !strcmp (curve, "Ed448"))
      || (pkalgo == PUBKEY_ALGO_ECDH && !strcmp (curve, "X448")))
    buf = gcry_mpi_get_opaque (key, &nbits);

  /* Either Ed448/X448 non-prefixed or not Ed448/X448.  */
  if (nbits == 0
      || (pkalgo == PUBKEY_ALGO_EDDSA && (nbits+7)/8 == (448 + 8)/8)
      || (pkalgo == PUBKEY_ALGO_ECDH && (nbits+7)/8 == 448/8))
    return gcry_mpi_copy (key);

  /* Ed448 or X448 prefixed.  */
  if (pkalgo == PUBKEY_ALGO_EDDSA)
    return gcry_mpi_set_opaque_copy (NULL, buf+1, 8 + 448);
  else
    return gcry_mpi_set_opaque_copy (NULL, buf+1, 448);
}


/*
 * Fix up public key for OpenPGP adding the prefix.
 */
gpg_error_t
openpgp_fixup_pubkey_448 (int algo, gcry_mpi_t *p_pubkey)
{
  gcry_mpi_t pubkey_mpi;
  gcry_mpi_t a;
  unsigned char *p;
  const unsigned char *p_key;
  unsigned int nbits;
  unsigned int len;

  pubkey_mpi = *p_pubkey;
  *p_pubkey = NULL;
  p_key = gcry_mpi_get_opaque (pubkey_mpi, &nbits);
  len = (nbits+7)/8;
  if ((algo == PUBKEY_ALGO_ECDH && len != 56)
      || (algo == PUBKEY_ALGO_EDDSA && len != 57)
      || (algo != PUBKEY_ALGO_ECDH && algo != PUBKEY_ALGO_EDDSA))
    {
      gcry_mpi_release (pubkey_mpi);
      return gpg_error (GPG_ERR_BAD_PUBKEY);
    }

  p = xtrymalloc (1 + len);
  if (!p)
    {
      gcry_mpi_release (pubkey_mpi);
      return gpg_error_from_syserror ();
    }

  p[0] = 0x40;
  memcpy (p+1, p_key, len);

  a = gcry_mpi_set_opaque (NULL, p, len*8+7);
  gcry_mpi_set_flag (a, GCRYMPI_FLAG_USER2);
  *p_pubkey = a;
  gcry_mpi_release (pubkey_mpi);

  return 0;
}
