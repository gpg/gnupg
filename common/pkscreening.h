/* pkscreening.c - Screen public keys for vulnerabilities
 * Copyright (C) 2017 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_PKSCREENING_H
#define GNUPG_COMMON_PKSCREENING_H

gpg_error_t screen_key_for_roca (gcry_mpi_t modulus);


#endif /*GNUPG_COMMON_PKSCREENING_H*/
