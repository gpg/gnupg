/* backend.h - Defs for the dispatcher to the various backends.
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

#ifndef G13_BACKEND_H
#define G13_BACKEND_H

#include "../common/membuf.h"
#include "g13tuple.h"

int be_parse_conttype_name (const char *name);
int be_is_supported_conttype (int conttype);
gpg_error_t be_take_lock_for_create (ctrl_t ctrl, const char *fname,
                                     dotlock_t *r_lock);
gpg_error_t be_get_detached_name (int conttype, const char *fname,
                                  char **r_name, int *r_isdir);
gpg_error_t be_create_new_keys (int conttype, membuf_t *mb);

gpg_error_t be_create_container (ctrl_t ctrl, int conttype,
                                 const char *fname, int fd,
                                 tupledesc_t tuples,
                                 unsigned int *r_id);
gpg_error_t be_mount_container (ctrl_t ctrl, int conttype,
                                const char *fname, const char *mountpoint,
                                tupledesc_t tuples,
                                unsigned int *r_id);
gpg_error_t be_umount_container (ctrl_t ctrl, int conttype, const char *fname);
gpg_error_t be_suspend_container (ctrl_t ctrl, int conttype,
                                  const char *fname);
gpg_error_t be_resume_container (ctrl_t ctrl, int conttype,
                                 const char *fname, tupledesc_t tuples);


#endif /*G13_BACKEND_H*/
