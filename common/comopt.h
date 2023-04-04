/* comopt.h - Common options for GnuPG (common.conf)
 * Copyright (C) 2021 g10 Code GmbH
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
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#ifndef GNUPG_COMOPT_H
#define GNUPG_COMOPT_H

#include "../common/util.h"


/* Common options for all GnuPG components.  */
struct gnupg_comopt_s
{
  char *logfile;     /* Socket used by daemons for logging.  */
  int use_keyboxd;   /* Use the keyboxd as storage backend.  */
  int no_autostart;  /* Do not start gpg-agent.              */
  char *keyboxd_program;  /* Use this as keyboxd program.    */
};


extern struct gnupg_comopt_s comopt;


gpg_error_t parse_comopt (int module_id, int verbose);


#endif /*GNUPG_COMOPT_H*/
