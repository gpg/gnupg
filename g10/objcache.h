/* objcache.h - Caching functions for keys and user ids.
 * Copyright (C) 2019 g10 Code GmbH
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

#ifndef GNUPG_G10_OBJCACHE_H
#define GNUPG_G10_OBJCACHE_H

void objcache_dump_stats (void);
void cache_put_keyblock (kbnode_t keyblock);
char *cache_get_uid_bykid (u32 *keyid, unsigned int *r_length);
char *cache_get_uid_byfpr (const byte *fpr, size_t fprlen, size_t *r_length);

#endif /*GNUPG_G10_OBJCACHE_H*/
