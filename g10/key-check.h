/* key-check.h - Detect and fix various problems with keys
 * Copyright (C) 2017 g10 Code GmbH
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

#ifndef GNUPG_G10_PACKET_TOOLS_H
#define GNUPG_G10_PACKET_TOOLS_H

#include "gpg.h"

int key_check_all_keysigs (ctrl_t ctrl, int mode, kbnode_t kb,
			   int only_selected, int only_selfsigs);

#endif	/* GNUPG_G10_PACKET_TOOLS_H */
