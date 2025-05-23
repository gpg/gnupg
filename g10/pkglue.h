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
gpg_error_t sexp_extract_param_sos (gcry_sexp_t sexp, const char *param,
                                    gcry_mpi_t *r_sos);
gpg_error_t sexp_extract_param_sos_nlz (gcry_sexp_t sexp, const char *param,
                                        gcry_mpi_t *r_sos);

int pk_verify (pubkey_algo_t algo, gcry_mpi_t hash, gcry_mpi_t *data,
               gcry_mpi_t *pkey);
gpg_error_t pk_encrypt (PKT_public_key *pk, gcry_mpi_t data, int seskey_algo,
                        gcry_mpi_t *resarr);
int pk_check_secret_key (pubkey_algo_t algo, gcry_mpi_t *skey);


/*-- ecdh.c --*/
gcry_mpi_t  pk_ecdh_default_params (unsigned int qbits);

gpg_error_t ecc_build_kdf_params (unsigned char **r_kdf_params, size_t *r_len,
                                  const unsigned char **r_kdf_params_spec,
                                  gcry_mpi_t *pkey,
                                  const byte fp[MAX_FINGERPRINT_LEN]);

#endif /*GNUPG_G10_PKGLUE_H*/
