/* gost-util.h - Some common code for GOST crypto.
 * Copyright (C) 2019 Paul Wolneykien <manowar@altlinux.org>
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

#ifndef GNUPG_COMMON_GOST_UTIL_H
#define GNUPG_COMMON_GOST_UTIL_H

#include <gcrypt.h> /* We need this for the memory function protos. */
#include <errno.h>  /* We need errno.  */
#include <gpg-error.h> /* We need gpg_error_t and estream. */
#include "openpgpdefs.h" /* We need gpg_error_t and estream. */

gpg_error_t
gost_generate_ukm (unsigned int ukm_blen, gcry_mpi_t *r_ukm);

gpg_error_t
gost_cpdiversify_key (gcry_mpi_t *result,
                      enum gcry_cipher_algos cipher_algo,
                      const char *cipher_sbox,
                      const unsigned char *key, size_t key_len,
                      gcry_mpi_t ukm);

gpg_error_t
gost_keywrap (gcry_mpi_t *result,
              enum gcry_cipher_algos cipher_algo,
              const char *cipher_sbox,
              enum gcry_mac_algos mac_algo,
              const char *mac_sbox,
              gcry_mpi_t key, gcry_mpi_t ukm, gcry_mpi_t kek);

gpg_error_t
gost_vko (gcry_mpi_t shared, enum gcry_md_algos digest_algo,
          const char *digest_params, unsigned char **keyout,
          size_t *keyout_len);

gpg_error_t
gost_keyunwrap (gcry_mpi_t *result,
                enum gcry_cipher_algos cipher_algo,
                const char *cipher_sbox,
                enum gcry_mac_algos mac_algo,
                const char *mac_sbox,
                const unsigned char *wrapped, size_t wrapped_len,
                gcry_mpi_t ukm, gcry_mpi_t kek);

#endif /*GNUPG_COMMON_GOST_UTIL_H*/
