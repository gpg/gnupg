/* ssh-utils.c - Secure Shell helper function definitions
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_SSH_UTILS_H
#define GNUPG_COMMON_SSH_UTILS_H


gpg_error_t _ssh_get_fingerprint (gcry_sexp_t key, void **r_fpr, size_t *r_len,
                                  gpg_err_source_t errsource);
#define ssh_get_fingerprint(a,b,c)                              \
  _ssh_get_fingerprint ((a), (b), (c), GPG_ERR_SOURCE_DEFAULT)

gpg_error_t _ssh_get_fingerprint_string (gcry_sexp_t key, char **r_fprstr,
                                         gpg_err_source_t errsource);
#define ssh_get_fingerprint_string(a,b)                         \
  _ssh_get_fingerprint_string ((a), (b), GPG_ERR_SOURCE_DEFAULT)



#endif /*GNUPG_COMMON_SSH_UTILS_H*/
