/* frontend.h - Definitions for the keyboxd frontend
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
 */

#ifndef KBX_FRONTEND_H
#define KBX_FRONTEND_H

#include "keybox-search-desc.h"


gpg_error_t kbxd_set_database (ctrl_t ctrl,
                               const char *filename_arg, int readonly);

void kbxd_release_session_info (ctrl_t ctrl);

gpg_error_t kbxd_rollback (void);
gpg_error_t kbxd_commit (void);
gpg_error_t kbxd_search (ctrl_t ctrl,
                         KEYDB_SEARCH_DESC *desc, unsigned int ndesc,
                         int reset);
gpg_error_t kbxd_store (ctrl_t ctrl, const void *blob, size_t bloblen,
                        enum kbxd_store_modes mode);
gpg_error_t kbxd_delete (ctrl_t ctrl, const unsigned char *ubid);


#endif /*KBX_FRONTEND_H*/
