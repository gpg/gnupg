/* compliance.h - Definitions for compliance modi
 * Copyright (C) 2017 g10 Code GmbH
 * Copyright (C) 2017 Bundesamt für Sicherheit in der Informationstechnik
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

#ifndef GNUPG_COMMON_COMPLIANCE_H
#define GNUPG_COMMON_COMPLIANCE_H

#include <gcrypt.h>
#include "openpgpdefs.h"

void gnupg_initialize_compliance (int gnupg_module_name);

enum gnupg_compliance_mode
  {
    CO_GNUPG, CO_RFC4880, CO_RFC2440,
    CO_PGP6, CO_PGP7, CO_PGP8, CO_DE_VS
  };

enum pk_use_case
  {
    PK_USE_ENCRYPTION, PK_USE_DECRYPTION,
    PK_USE_SIGNING, PK_USE_VERIFICATION,
  };

/* Flags to distinguish public key algorithm variants.  */
#define PK_ALGO_FLAG_RSAPSS 1    /* Use rsaPSS padding. */


int gnupg_pk_is_compliant (enum gnupg_compliance_mode compliance, int algo,
                           unsigned int algo_flags,
                           gcry_mpi_t key[], unsigned int keylength,
                           const char *curvename);
int gnupg_pk_is_allowed (enum gnupg_compliance_mode compliance,
                         enum pk_use_case use, int algo,
                         unsigned int algo_flags, gcry_mpi_t key[],
                         unsigned int keylength, const char *curvename);
int gnupg_cipher_is_compliant (enum gnupg_compliance_mode compliance,
                               cipher_algo_t cipher,
                               enum gcry_cipher_modes mode);
int gnupg_cipher_is_allowed (enum gnupg_compliance_mode compliance,
                             int producer,
                             cipher_algo_t cipher,
                             enum gcry_cipher_modes mode);
int gnupg_digest_is_compliant (enum gnupg_compliance_mode compliance,
                               digest_algo_t digest);
int gnupg_digest_is_allowed (enum gnupg_compliance_mode compliance,
                             int producer,
                             digest_algo_t digest);
int gnupg_rng_is_compliant (enum gnupg_compliance_mode compliance);
int gnupg_gcrypt_is_compliant (enum gnupg_compliance_mode compliance);

const char *gnupg_status_compliance_flag (enum gnupg_compliance_mode
                                          compliance);

struct gnupg_compliance_option
{
  const char *keyword;
  int value;
};

int gnupg_parse_compliance_option (const char *string,
                                   struct gnupg_compliance_option options[],
                                   size_t length,
                                   int quiet);
const char *gnupg_compliance_option_string (enum gnupg_compliance_mode
                                            compliance);

void gnupg_set_compliance_extra_info (unsigned int min_rsa);


#endif /*GNUPG_COMMON_COMPLIANCE_H*/
