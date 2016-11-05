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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_CALL_GPG_H
#define GNUPG_COMMON_CALL_GPG_H

#include <gpg-error.h>

#include "fwddecl.h"
#include "strlist.h"

gpg_error_t gpg_encrypt_blob (ctrl_t ctrl,
			      const char *gpg_program,
			      strlist_t gpg_arguments,
                              const void *plain, size_t plainlen,
                              strlist_t keys,
                              void **r_ciph, size_t *r_ciphlen);

gpg_error_t gpg_encrypt_stream (ctrl_t ctrl,
				const char *gpg_program,
				strlist_t gpg_arguments,
				estream_t plain_stream,
				strlist_t keys,
				estream_t cipher_stream);

gpg_error_t gpg_decrypt_blob (ctrl_t ctrl,
			      const char *gpg_program,
			      strlist_t gpg_arguments,
			      const void *ciph, size_t ciphlen,
                              void **r_plain, size_t *r_plainlen);

gpg_error_t gpg_decrypt_stream (ctrl_t ctrl,
				const char *gpg_program,
				strlist_t gpg_arguments,
				estream_t cipher_stream,
				estream_t plain_stream);

#endif /*GNUPG_COMMON_CALL_GPG_H*/
