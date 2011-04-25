/* userids.h - Utility functions for user ids.
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

#ifndef GNUPG_COMMON_USERIDS_H
#define GNUPG_COMMON_USERIDS_H

#include "../kbx/keybox-search-desc.h"

gpg_error_t classify_user_id (const char *name, KEYDB_SEARCH_DESC *desc,
                              int openpgp_hack);


#endif /*GNUPG_COMMON_USERIDS_H*/
