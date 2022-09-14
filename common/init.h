/* init.h - Definitions for init functions.
 * Copyright (C) 2007, 2012 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_INIT_H
#define GNUPG_COMMON_INIT_H

#ifndef GPG_ERR_SOURCE_DEFAULT
# error GPG_ERR_SOURCE_DEFAULT is not defined
#endif

void register_mem_cleanup_func (void (*func)(void));

void early_system_init (void);
void _init_common_subsystems (gpg_err_source_t errsource,
                              int *argcp, char ***argvp);
#define init_common_subsystems(a,b)                             \
  _init_common_subsystems (GPG_ERR_SOURCE_DEFAULT, (a), (b))

#endif /*GNUPG_COMMON_INIT_H*/
