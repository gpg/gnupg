/* key-clean.h - Functions to clean a keyblock
 * Copyright (C) 2018 Werner Koch
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

#ifndef GNUPG_G10_KEY_CLEAN_H
#define GNUPG_G10_KEY_CLEAN_H

#include "gpg.h"

void mark_usable_uid_certs (ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode,
                            u32 *main_kid, struct key_item *klist,
                            u32 curtime, u32 *next_expire);

void clean_one_uid (ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode,
                    int noisy, int self_only,
                    int *uids_cleaned, int *sigs_cleaned);
void clean_key (ctrl_t ctrl, kbnode_t keyblock, int noisy, int self_only,
                int *uids_cleaned,int *sigs_cleaned);


#endif /*GNUPG_G10_KEY_CLEAN_H*/
