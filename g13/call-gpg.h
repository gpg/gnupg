/* call-gpg.h - Defs for the communication with GPG
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#ifndef G13_CALL_GPG_H
#define G13_CALL_GPG_H

gpg_error_t gpg_encrypt_blob (ctrl_t ctrl,
                              const void *plain, size_t plainlen,
                              strlist_t keys,
                              void **r_ciph, size_t *r_ciphlen);
gpg_error_t gpg_decrypt_blob (ctrl_t ctrl, const void *ciph, size_t ciphlen,
                              void **r_plain, size_t *r_plainlen);



#endif /*G13_CALL_GPG_H*/
