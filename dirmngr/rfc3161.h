/* rfc3161.h - X.509 Time-Stamp protocol interface
 * Copyright (C) 2022 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef GNUPG_RFC3161_H
#define GNUPG_RFC3161_H

#include <gpg-error.h>
#include "dirmngr.h"

gpg_error_t dirmngr_get_timestamp (ctrl_t ctrl, char *hashalgoid,
                                    const void *tbshash,
                                    unsigned int tbshashlen, ksba_cms_t *r_cms);


#endif /*GNUPG_RFC3161_H*/
