/* To satisfy the linker for the gpgv target 
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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

#include <config.h>

#include <stdio.h>
#include "gpg.h"
#include "main.h"

int
pk_ecc_keypair_gen( PKT_public_key **pk_out, int algo, int keygen_flags, char **cache_nonce_addr, unsigned nbits)  {
	return GPG_ERR_NOT_IMPLEMENTED;
}
