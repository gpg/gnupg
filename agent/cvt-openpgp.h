/* cvt-openpgp.h - Convert an OpenPGP key to our internal format.
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
#ifndef GNUPG_AGENT_CVT_OPENPGP_H
#define GNUPG_AGENT_CVT_OPENPGP_H

gpg_error_t convert_from_openpgp (ctrl_t ctrl, gcry_sexp_t s_pgp,
                                  int dontcare_exist,
                                  unsigned char *grip, const char *prompt,
                                  const char *cache_nonce,
                                  unsigned char **r_key, char **r_passphrase);
gpg_error_t convert_from_openpgp_native (ctrl_t ctrl,
                                         gcry_sexp_t s_pgp,
                                         const char *passphrase,
                                         unsigned char **r_key);

gpg_error_t convert_to_openpgp (ctrl_t ctrl, gcry_sexp_t s_key,
                                const char *passphrase,
                                unsigned char **r_transferkey,
                                size_t *r_transferkeylen);

#endif /*GNUPG_AGENT_CVT_OPENPGP_H*/
