/* pkglue.h - public key operations definitions
 *	Copyright (C) 2003, 2010 Free Software Foundation, Inc.
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

#ifndef GNUPG_G10_PKGLUE_H
#define GNUPG_G10_PKGLUE_H

#include "packet.h"  /* For PKT_public_key.  */

/*-- pkglue.c --*/
gcry_mpi_t get_mpi_from_sexp (gcry_sexp_t sexp, const char *item, int mpifmt);

int pk_verify (pubkey_algo_t algo, gcry_mpi_t hash, gcry_mpi_t *data,
               gcry_mpi_t *pkey);
int pk_encrypt (pubkey_algo_t algo, gcry_mpi_t *resarr, gcry_mpi_t data,
		PKT_public_key *pk, gcry_mpi_t *pkey);
int pk_check_secret_key (pubkey_algo_t algo, gcry_mpi_t *skey);


/*-- ecdh.c --*/
gcry_mpi_t  pk_ecdh_default_params (unsigned int qbits);
gpg_error_t pk_ecdh_generate_ephemeral_key (gcry_mpi_t *pkey, gcry_mpi_t *r_k);
gpg_error_t pk_ecdh_encrypt_with_shared_point
/*         */  (int is_encrypt, const char *shared, size_t nshared,
                const byte pk_fp[MAX_FINGERPRINT_LEN],
                gcry_mpi_t data, gcry_mpi_t *pkey,
                gcry_mpi_t *out);

int pk_ecdh_encrypt (gcry_mpi_t *resarr, const byte pk_fp[MAX_FINGERPRINT_LEN],
                     gcry_mpi_t data, gcry_mpi_t * pkey);
int pk_ecdh_decrypt (gcry_mpi_t *result, const byte sk_fp[MAX_FINGERPRINT_LEN],
                     gcry_mpi_t data, const char *shared, size_t nshared,
                     gcry_mpi_t *skey);


#endif /*GNUPG_G10_PKGLUE_H*/
