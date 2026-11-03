/* kemhelp.h - Definitions for KEM functions.
 * Copyright (C) 2026 g10 Code GmbH
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
 */
#ifndef GNUPG_COMMON_KEMHELP_H
#define GNUPG_COMMON_KEMHELP_H


/* Maximum buffer sizes required for ECC KEM.  */
#define ECC_SCALAR_LEN_MAX 66
#define ECC_POINT_LEN_MAX (1+2*ECC_SCALAR_LEN_MAX)
#define ECC_HASH_LEN_MAX 64


/* ECC parameters for KEM encryption/decryption.  */
struct gnupg_ecc_params
{
  const char *curve;      /* Canonical name of the curve.  */
  size_t pubkey_len;      /* Pubkey length in the SEXP representation.  */
  size_t scalar_len;
  size_t point_len;
  int hash_algo;          /* Hash algo when it's used for composite KEM.  */
  int kem_algo;
  int scalar_reverse;     /* Byte-oder is reverse.  */
  int may_have_prefix;    /* Point representation may have prefix.  */
  int is_weierstrauss;    /* True if it is Weierstrass curve.  */
};


/*-- kem.c --*/
gpg_error_t gpgsm_ecc_kem_kdf (void *kek, size_t kek_len,
                               int hashalgo, const void *ecdh, size_t ecdh_len,
                               const unsigned char *wrap, size_t wrap_len,
                               const unsigned char *ukm, size_t ukm_len);

gpg_error_t gnupg_ecc_kem_kdf (void *kek, size_t kek_len, int kdf_algo,
                               int hashalgo, const void *ecdh, size_t ecdh_len,
                               const unsigned char *kdf_params,
                               size_t kdf_params_len);

gpg_error_t gnupg_ecc_kem_simple_kdf (void *kek, size_t kek_len, int hashalgo,
                                      const void *ecdh, size_t ecdh_len,
                                      const void *ecc_ct, size_t ecc_ct_len,
                                      const void *ecc_pk, size_t ecc_pk_len);

gpg_error_t gnupg_kem_combiner  (void *kek, size_t kek_len,
                                 const void *ecc_ss, size_t ecc_ss_len,
                                 const void *ecc_ct, size_t ecc_ct_len,
                                 const void *mlkem_ss, size_t mlkem_ss_len,
                                 const void *mlkem_ct, size_t mlkem_ct_len,
                                 const void *fixedinfo, size_t fixedinfo_len);

gpg_error_t gnupg_kem_combiner_sha3_256 (void *kek, size_t kek_len,
                             const void *ecc_ss, size_t ecc_ss_len,
                             const void *ecc_ct, size_t ecc_ct_len,
                             const void *ecc_pk, size_t ecc_pk_len,
                             const void *mlkem_ss, size_t mlkem_ss_len,
                              const void *fixedinfo, size_t fixedinfo_len);

const struct gnupg_ecc_params *gnupg_get_ecc_params (const char *curve);



#endif /*GNUPG_COMMON_KEMHELP_H*/
