/* pkglue.h - public key operations definitions
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_G10_PKGLUE_H
#define GNUPG_G10_PKGLUE_H

gcry_mpi_t mpi_from_sexp (gcry_sexp_t sexp, const char * item);

int pk_sign (int algo, gcry_mpi_t *data, gcry_mpi_t hash,
             gcry_mpi_t *skey);
int pk_verify (int algo, gcry_mpi_t hash, gcry_mpi_t *data,
               gcry_mpi_t *pkey);
int pk_encrypt (int algo, gcry_mpi_t *resarr, gcry_mpi_t data,
		const byte fp[MAX_FINGERPRINT_LEN],
                gcry_mpi_t *pkey);
int pk_decrypt (int algo, gcry_mpi_t *result, const byte fp[MAX_FINGERPRINT_LEN], gcry_mpi_t *data,
                gcry_mpi_t *skey);
int pk_check_secret_key (int algo, gcry_mpi_t *skey);

int pk_ecdh_encrypt (gcry_mpi_t * resarr, const byte pk_fp[MAX_FINGERPRINT_LEN], gcry_mpi_t  data, gcry_mpi_t * pkey);
int pk_ecdh_decrypt (gcry_mpi_t * result, const byte sk_fp[MAX_FINGERPRINT_LEN], gcry_mpi_t *data, gcry_mpi_t * skey);

gcry_mpi_t pk_ecdh_default_params_to_mpi( int qbits );
byte *pk_ecdh_default_params( int qbits, size_t *sizeout );

#endif /*GNUPG_G10_PKGLUE_H*/
