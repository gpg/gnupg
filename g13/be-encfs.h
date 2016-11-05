/* be-encfs.h - Public defs for the EncFS based backend
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

#ifndef G13_BE_ENCFS_H
#define G13_BE_ENCFS_H

#include "backend.h"

gpg_error_t be_encfs_get_detached_name (const char *fname,
                                        char **r_name, int *r_isdir);
gpg_error_t be_encfs_create_new_keys (membuf_t *mb);

gpg_error_t be_encfs_create_container (ctrl_t ctrl,
                                       const char *fname,
                                       tupledesc_t tuples,
                                       unsigned int *r_id);

gpg_error_t be_encfs_mount_container (ctrl_t ctrl,
                                      const char *fname,
                                      const char *mountpoint,
                                      tupledesc_t tuples,
                                      unsigned int *r_id);


#endif /*G13_BE_ENCFS_H*/
